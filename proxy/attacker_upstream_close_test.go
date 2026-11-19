package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// An HTTP/2 client sends all its requests on one connection to the proxy, and
// that connection has one upstream connection behind it. Once the upstream
// connection has closed, requests on the client's connection can only fail, so
// the client has to be told to move to a new one.

// connRecorder records the proxy's connection events.
type connRecorder struct {
	BaseAddon

	mu          sync.Mutex
	clientsSeen int
	clientsOpen int

	upstreamClosedOnce sync.Once
	upstreamClosed     chan struct{}
	upstreamClosedAt   time.Time

	uploadSeenOnce sync.Once
	uploadSeen     chan struct{}
}

func newConnRecorder() *connRecorder {
	return &connRecorder{
		upstreamClosed: make(chan struct{}),
		uploadSeen:     make(chan struct{}),
	}
}

func (r *connRecorder) ClientConnected(*ClientConn) {
	r.mu.Lock()
	r.clientsSeen++
	r.clientsOpen++
	r.mu.Unlock()
}

func (r *connRecorder) ClientDisconnected(*ClientConn) {
	r.mu.Lock()
	r.clientsOpen--
	r.mu.Unlock()
}

func (r *connRecorder) ServerDisconnected(*ConnContext) {
	r.upstreamClosedOnce.Do(func() {
		r.upstreamClosedAt = time.Now()
		close(r.upstreamClosed)
	})
}

func (r *connRecorder) Requestheaders(f *Flow) {
	if f.Request.Method == http.MethodPost {
		r.uploadSeenOnce.Do(func() { close(r.uploadSeen) })
	}
}

// requireClientsClosed fails unless the proxy closes every client connection
// it has accepted within the given time.
func (r *connRecorder) requireClientsClosed(t *testing.T, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		r.mu.Lock()
		seen, open := r.clientsSeen, r.clientsOpen
		r.mu.Unlock()
		if seen > 0 && open == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d client connections still open after %v", open, seen, within)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// goAwayUpstream is an HTTP/2 server. It answers GET /goaway with "Connection:
// close", which makes it send GOAWAY and close the connection.
func goAwayUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	mux.HandleFunc("/goaway", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		_, _ = io.WriteString(w, "bye")
	})
	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, "ok")
	})
	upstream := httptest.NewUnstartedServer(mux)
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	t.Cleanup(upstream.Close)
	return upstream
}

func TestAttackerMovesHTTP2ClientOffClosedUpstream(t *testing.T) {
	t.Run("plain", func(t *testing.T) { testHTTP2ClientMovesOffClosedUpstream(t, false) })
	// The upload's handler runs until the upload ends, so the client's
	// connection is never idle while the workers are requesting.
	t.Run("slow upload open", func(t *testing.T) { testHTTP2ClientMovesOffClosedUpstream(t, true) })
}

func testHTTP2ClientMovesOffClosedUpstream(t *testing.T, slowUpload bool) {
	const (
		workers = 8
		// settle is how long the client gets to learn that its connection is
		// going away. Requests started later than this after the upstream
		// closed must not fail on the old connection.
		settle   = 250 * time.Millisecond
		runAfter = time.Second
	)

	rec := newConnRecorder()
	upstream := goAwayUpstream(t)
	client := earlyAnswerClient(t, startEarlyAnswerProxy(t, 0, rec), true)
	client.Timeout = 20 * time.Second

	resp, err := client.Get(upstream.URL + "/ok")
	handleError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ProtoMajor != 2 {
		t.Fatalf("warm-up got %d over %s; want 200 over HTTP/2", resp.StatusCode, resp.Proto)
	}

	if slowUpload {
		body, feed := io.Pipe()
		stopUpload := make(chan struct{})
		uploadDone := make(chan struct{})
		go func() {
			defer feed.Close()
			tick := time.NewTicker(20 * time.Millisecond)
			defer tick.Stop()
			for {
				select {
				case <-stopUpload:
					return
				case <-tick.C:
					if _, err := feed.Write(make([]byte, 1024)); err != nil {
						return
					}
				}
			}
		}()
		go func() {
			defer close(uploadDone)
			resp, err := client.Post(upstream.URL+"/upload", "application/octet-stream", body)
			if err != nil {
				t.Logf("slow upload: %v", err)
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			t.Logf("slow upload: %d", resp.StatusCode)
		}()
		defer func() {
			close(stopUpload)
			<-uploadDone
		}()
		select {
		case <-rec.uploadSeen:
		case <-time.After(5 * time.Second):
			t.Fatal("the upload did not reach the proxy")
		}
	}

	type result struct {
		started time.Time
		status  int
		err     error
	}
	var (
		mu      sync.Mutex
		results []result
		wg      sync.WaitGroup
	)
	stop := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				r := result{started: time.Now()}
				resp, err := client.Get(upstream.URL + "/ok")
				if err != nil {
					r.err = err
				} else {
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					r.status = resp.StatusCode
				}
				mu.Lock()
				results = append(results, r)
				mu.Unlock()
			}
		}()
	}

	time.Sleep(100 * time.Millisecond)
	if resp, err := client.Get(upstream.URL + "/goaway"); err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	select {
	case <-rec.upstreamClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("the upstream connection did not close")
	}
	time.Sleep(time.Until(rec.upstreamClosedAt.Add(runAfter)))
	close(stop)
	wg.Wait()

	var badGateway, lateBadGateway, lateOK, failed int
	var lastBadGateway time.Duration
	for _, r := range results {
		after := r.started.Sub(rec.upstreamClosedAt)
		switch {
		case r.err != nil:
			failed++
		case r.status == http.StatusBadGateway:
			if badGateway == 0 || after > lastBadGateway {
				lastBadGateway = after
			}
			badGateway++
			if after > settle {
				lateBadGateway++
			}
		case r.status == http.StatusOK && after > settle:
			lateOK++
		}
	}
	t.Logf("%d requests: %d got 502, %d failed without a response", len(results), badGateway, failed)
	if badGateway > 0 {
		t.Logf("the last 502 was for a request started %v after the upstream closed", lastBadGateway.Round(time.Millisecond))
	}
	if lateBadGateway > 0 {
		t.Errorf("%d requests started more than %v after the upstream closed got 502; want the client moved to a new connection by then",
			lateBadGateway, settle)
	}
	if lateOK == 0 {
		t.Errorf("no request started more than %v after the upstream closed got 200", settle)
	}
}

// closeUpstreamBeforeReply closes the upstream's connections once the proxy
// has read a response, and waits for the proxy to see the close, so the
// response headers are written with the server connection already gone.
type closeUpstreamBeforeReply struct {
	BaseAddon
	closeUpstream func()
	closed        <-chan struct{}
}

func (a *closeUpstreamBeforeReply) Response(*Flow) {
	a.closeUpstream()
	select {
	case <-a.closed:
	case <-time.After(5 * time.Second):
	}
}

// A client that is slow to open its flow-control window must still get the end
// of a response written after the upstream closed: the HTTP/2 server waits for
// the stream, and the deferred close must not cut it off after h2FlushGrace.
func TestAttackerLetsSlowHTTP2ClientFinishAfterUpstreamCloses(t *testing.T) {
	const bodySize, window = 3000, 1000

	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("b"), bodySize))
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	t.Cleanup(upstream.Close)
	target, err := url.Parse(upstream.URL)
	handleError(t, err)

	rec := newConnRecorder()
	proxyURL := startEarlyAnswerProxy(t, 0, rec, &closeUpstreamBeforeReply{
		closeUpstream: upstream.CloseClientConnections,
		closed:        rec.upstreamClosed,
	})

	raw, err := net.DialTimeout("tcp", proxyURL.Host, 2*time.Second)
	handleError(t, err)
	defer raw.Close()
	_, err = fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target.Host, target.Host)
	handleError(t, err)
	br := bufio.NewReader(raw)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	handleError(t, err)
	if resp.StatusCode != http.StatusOK || br.Buffered() != 0 {
		t.Fatalf("CONNECT got %d with %d bytes buffered", resp.StatusCode, br.Buffered())
	}
	conn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	handleError(t, conn.Handshake())
	if proto := conn.ConnectionState().NegotiatedProtocol; proto != "h2" {
		t.Fatalf("negotiated %q; want h2", proto)
	}

	_, err = conn.Write([]byte(http2.ClientPreface))
	handleError(t, err)
	fr := http2.NewFramer(conn, conn)
	handleError(t, fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: window}))
	var headerBlock bytes.Buffer
	enc := hpack.NewEncoder(&headerBlock)
	for _, hf := range []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: target.Host},
		{Name: ":path", Value: "/"},
	} {
		handleError(t, enc.WriteField(hf))
	}
	handleError(t, fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		EndStream:     true,
		EndHeaders:    true,
		BlockFragment: headerBlock.Bytes(),
	}))

	var got int
	var goAway, ended bool
	readUntil := func(done func() bool) error {
		for !done() {
			if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				return err
			}
			f, err := fr.ReadFrame()
			if err != nil {
				return err
			}
			switch f := f.(type) {
			case *http2.SettingsFrame:
				if !f.IsAck() {
					if err := fr.WriteSettingsAck(); err != nil {
						return err
					}
				}
			case *http2.GoAwayFrame:
				goAway = true
			case *http2.DataFrame:
				if f.StreamID == 1 {
					got += len(f.Data())
					ended = ended || f.StreamEnded()
				}
			}
		}
		return nil
	}

	if err := readUntil(func() bool { return got >= window && goAway }); err != nil {
		t.Fatalf("got %d bytes, GOAWAY %v, then %v; want the window filled and a GOAWAY", got, goAway, err)
	}
	time.Sleep(2 * h2FlushGrace)
	handleError(t, fr.WriteWindowUpdate(1, bodySize))
	if err := readUntil(func() bool { return ended }); err != nil || got != bodySize {
		t.Fatalf("after the window reopened: %d of %d bytes, then %v; want the whole response", got, bodySize, err)
	}
}
