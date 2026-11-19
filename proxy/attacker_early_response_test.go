package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lqqyt2423/go-mitmproxy/cert"
)

// An upstream may answer a request before it has read the whole body, for
// example rejecting a bad credential after the headers and the first part of
// a large body. The proxy must hand that answer to the client rather than
// close the client connection when the upstream connection goes away.

const earlyAnswerBody = `{"error":"invalid credentials"}`

// earlyAnswerUpstream reads the first 100 KiB of each request body, then
// answers 401 and stops reading.
//   - keepAlive: the answer says "Connection: keep-alive" and the connection
//     stays open with the rest of the body unread, as some API servers answer
//     a rejected credential. HTTP/1.1 only.
//   - otherwise the answer says "Connection: close"; over HTTP/2 the upstream
//     then sends GOAWAY and closes the connection right after answering.
func earlyAnswerUpstream(t *testing.T, enableHTTP2, keepAlive bool) *httptest.Server {
	t.Helper()
	done := make(chan struct{})
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.CopyN(io.Discard, r.Body, 100<<10)
		if keepAlive {
			// net/http would add "Connection: close" itself for a body left
			// unread, so write the answer on the raw connection instead.
			conn, buf, err := http.NewResponseController(w).Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			defer conn.Close()
			_, _ = fmt.Fprintf(buf, "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n%s", len(earlyAnswerBody), earlyAnswerBody)
			_ = buf.Flush()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(earlyAnswerBody))
	}))
	upstream.EnableHTTP2 = enableHTTP2
	upstream.StartTLS()
	t.Cleanup(func() { close(done); upstream.Close() })
	return upstream
}

// bufferWholeBodies is a StreamLargeBodies that no body reaches, so the proxy
// reads the client's whole request before it sends anything upstream.
const bufferWholeBodies = 0x7FFFFFFFFFFFFFFE

// startEarlyAnswerProxy starts a proxy and returns its URL. A streamLargeBodies
// of 0 leaves the default, which streams bodies of 5 MiB and more.
func startEarlyAnswerProxy(t *testing.T, streamLargeBodies int64, addons ...Addon) *url.URL {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	handleError(t, err)
	addr := ln.Addr().String()
	_ = ln.Close()

	p, err := NewProxy(&Options{
		Addr:              addr,
		StreamLargeBodies: streamLargeBodies,
		SslInsecure:       true,
		NewCaFunc:         cert.NewSelfSignCAMemory,
	})
	handleError(t, err)
	for _, addon := range addons {
		p.AddAddon(addon)
	}
	go func() { _ = p.Start() }()
	t.Cleanup(func() { _ = p.Close() })

	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("proxy did not start listening on %s: %v", addr, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return &url.URL{Scheme: "http", Host: addr}
}

func earlyAnswerClient(t *testing.T, proxyURL *url.URL, http2 bool) *http.Client {
	t.Helper()
	tr := &http.Transport{
		Proxy:             http.ProxyURL(proxyURL),
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2: http2,
	}
	if !http2 {
		tr.TLSClientConfig.NextProtos = []string{"http/1.1"}
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr}
}

// postLargeAndRequireAnswer posts 32 MiB, large enough that the proxy's upload
// upstream is still running when the answer arrives (loopback socket buffers
// absorb a few MiB), and requires the upstream's 401 to reach the client.
func postLargeAndRequireAnswer(t *testing.T, client *http.Client, target string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	payload := bytes.Repeat([]byte("a"), 32<<20)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(payload))
	handleError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client got %v; want the upstream's 401", err)
	}
	defer resp.Body.Close()
	// Read the whole body first: a response that starts and then resets is not
	// a complete response, whatever its status.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("response %d ended with %v; want a complete response", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(string(body), "invalid credentials") {
		t.Fatalf("got %d %q; want the upstream's 401", resp.StatusCode, body)
	}
}

// clientCloseBound is how long the proxy gets to close the client connection
// after the answer. It is far below deferredClientCloseLimit, so a connection
// that only the limit would close fails the test.
const clientCloseBound = 5 * time.Second

// testEarlyAnswer requires the upstream's early 401 to reach the client, and
// the proxy to close the client connection afterwards, since its upstream
// connection is gone. It runs once with the proxy buffering the request body,
// so the client has finished sending when the answer arrives, and once with
// the default StreamLargeBodies, where the body is streamed and the client is
// still sending.
func testEarlyAnswer(t *testing.T, http2, keepAlive bool) {
	for _, tc := range []struct {
		name              string
		streamLargeBodies int64
	}{
		{"body buffered", bufferWholeBodies},
		{"body streamed", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := newConnRecorder()
			upstream := earlyAnswerUpstream(t, http2, keepAlive)
			client := earlyAnswerClient(t, startEarlyAnswerProxy(t, tc.streamLargeBodies, rec), http2)
			postLargeAndRequireAnswer(t, client, upstream.URL+"/upload")
			rec.requireClientsClosed(t, clientCloseBound)
		})
	}
}

func TestAttackerDeliversEarlyKeepAliveAnswerToHTTP1Client(t *testing.T) {
	testEarlyAnswer(t, false, true)
}

// The upstream sends GOAWAY and closes right after its early answer. The
// answer and the closed connection can both be ready when x/net/http2's
// RoundTrip looks, and it then returns the answer (golang/go#49645), so the
// client must get the upstream's 401 and never the proxy's 502.
func TestAttackerAnswersHTTP2ClientWhenUpstreamClosesAfterAnswering(t *testing.T) {
	testEarlyAnswer(t, true, false)
}
