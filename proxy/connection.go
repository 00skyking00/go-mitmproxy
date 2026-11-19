package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	uuid "github.com/google/uuid"
)

// client connection
type ClientConn struct {
	Id                 uuid.UUID
	Conn               net.Conn
	Tls                bool
	NegotiatedProtocol string
	UpstreamCert       bool // Connect to upstream server to look up certificate details. Default: True
	clientHello        *tls.ClientHelloInfo
}

func newClientConn(c net.Conn) *ClientConn {
	return &ClientConn{
		Id:           uuid.New(),
		Conn:         c,
		Tls:          false,
		UpstreamCert: true,
	}
}

func (c *ClientConn) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})
	m["id"] = c.Id
	m["tls"] = c.Tls
	m["address"] = c.Conn.RemoteAddr().String()
	return json.Marshal(m)
}

// server connection
type ServerConn struct {
	Id      uuid.UUID
	Address string
	Conn    net.Conn

	client   *http.Client
	tlsConn  *tls.Conn
	tlsState *tls.ConnectionState
}

func newServerConn() *ServerConn {
	return &ServerConn{
		Id: uuid.New(),
	}
}

func (c *ServerConn) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})
	m["id"] = c.Id
	m["address"] = c.Address
	peername := ""
	if c.Conn != nil {
		peername = c.Conn.RemoteAddr().String()
	}
	m["peername"] = peername
	return json.Marshal(m)
}

func (c *ServerConn) TlsState() *tls.ConnectionState {
	return c.tlsState
}

// connection context ctx key
var connContextKey = new(struct{})

// connection context
type ConnContext struct {
	ClientConn *ClientConn   `json:"clientConn"`
	ServerConn *ServerConn   `json:"serverConn"`
	Intercept  bool          `json:"intercept"` // Indicates whether to parse HTTPS
	FlowCount  atomic.Uint32 `json:"-"`         // Number of HTTP requests made on the same connection

	proxy              *Proxy
	closeAfterResponse bool                        // after http response, http server will close the connection
	dialFn             func(context.Context) error // when begin request, if there no ServerConn, use this func to dial

	// clientMu guards clientActive, h2Handlers, closeClientWhenIdle and
	// h2GoAway. An HTTP/1 client connection is active from when the attacker
	// server starts reading a request on it until that request's response has
	// been written; an HTTP/2 one while a handler is running for any stream
	// that arrived before the server connection closed.
	clientMu            sync.Mutex
	clientActive        bool
	h2Handlers          int
	closeClientWhenIdle bool
	h2GoAway            bool
}

// deferredClientCloseLimit bounds how long a deferred client close waits for
// the response in progress, so a client that stalls mid-request cannot hold
// the connection open indefinitely.
const deferredClientCloseLimit = time.Minute

// h2FlushGrace is how long a deferred close of an HTTP/2 client connection
// waits after its last handler returns: the HTTP/2 server writes a stream's
// final frames after the handler returns, and has no hook for when it has.
// It applies only when the server connection closed after the response
// headers had been sent and no later response could carry "Connection:
// close" (see closeH2ClientIfUpstreamGone).
const h2FlushGrace = 500 * time.Millisecond

// upstreamGone reports whether the server connection has closed.
func (connCtx *ConnContext) upstreamGone() bool {
	if connCtx.ServerConn == nil {
		return false
	}
	c, ok := connCtx.ServerConn.Conn.(*wrapServerConn)
	if !ok {
		return false
	}
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	return c.closed
}

// closeClientOrDefer closes the client connection, or, if a response is still
// being written to it, closes it once that response is done. The server
// connection can close first: when an upstream answers before it has read the
// whole request body, the transport closes it as soon as the answer is read.
// An HTTP/2 connection that has been told to close (see h2GoAwayRequested) is
// left to the HTTP/2 server, within deferredClientCloseLimit.
func (connCtx *ConnContext) closeClientOrDefer() {
	connCtx.clientMu.Lock()
	if connCtx.clientActive || connCtx.h2Handlers > 0 || connCtx.h2GoAway {
		connCtx.closeClientWhenIdle = true
		connCtx.clientMu.Unlock()
		time.AfterFunc(deferredClientCloseLimit, func() {
			connCtx.clientMu.Lock()
			pending := connCtx.closeClientWhenIdle
			connCtx.closeClientWhenIdle = false
			connCtx.clientMu.Unlock()
			if pending {
				connCtx.ClientConn.Conn.Close()
			}
		})
		return
	}
	connCtx.clientMu.Unlock()
	connCtx.ClientConn.Conn.Close()
}

// h2HandlerStarted and h2HandlerDone bracket a handler serving one stream of
// an HTTP/2 client connection. When the last handler returns and a close was
// deferred, the connection is closed h2FlushGrace later, unless the HTTP/2
// server has been told to close it.
func (connCtx *ConnContext) h2HandlerStarted() {
	connCtx.clientMu.Lock()
	connCtx.h2Handlers++
	connCtx.clientMu.Unlock()
}

func (connCtx *ConnContext) h2HandlerDone() {
	connCtx.clientMu.Lock()
	connCtx.h2Handlers--
	startGrace := connCtx.h2Handlers == 0 && connCtx.closeClientWhenIdle && !connCtx.h2GoAway
	connCtx.clientMu.Unlock()
	if startGrace {
		time.AfterFunc(h2FlushGrace, connCtx.closeH2ClientAfterGrace)
	}
}

// closeH2ClientAfterGrace makes the deferred close, unless a response has
// carried "Connection: close" since the grace started.
func (connCtx *ConnContext) closeH2ClientAfterGrace() {
	connCtx.clientMu.Lock()
	closeNow := connCtx.closeClientWhenIdle && !connCtx.h2GoAway
	if closeNow {
		connCtx.closeClientWhenIdle = false
	}
	connCtx.clientMu.Unlock()
	if closeNow {
		connCtx.ClientConn.Conn.Close()
	}
}

// h2GoAwayRequested records that a response on the HTTP/2 client connection
// carried "Connection: close". The HTTP/2 server then sends GOAWAY, waits for
// the open streams to finish, including ones held up by the client's flow
// control, and closes the connection itself. The deferred close leaves the
// connection to it, and only deferredClientCloseLimit still applies.
func (connCtx *ConnContext) h2GoAwayRequested() {
	connCtx.clientMu.Lock()
	connCtx.h2GoAway = true
	connCtx.clientMu.Unlock()
}

// clientStateChanged tracks the HTTP/1 attacker server's state for the client
// connection, and makes a close that closeClientOrDefer deferred once the
// response has been written.
func (connCtx *ConnContext) clientStateChanged(state http.ConnState) {
	connCtx.clientMu.Lock()
	closeNow := false
	switch state {
	case http.StateActive:
		connCtx.clientActive = true
	case http.StateIdle:
		connCtx.clientActive = false
		closeNow = connCtx.closeClientWhenIdle
		connCtx.closeClientWhenIdle = false
	case http.StateHijacked, http.StateClosed:
		connCtx.clientActive = false
		connCtx.closeClientWhenIdle = false
	}
	connCtx.clientMu.Unlock()
	if closeNow {
		connCtx.ClientConn.Conn.Close()
	}
}

func newConnContext(c net.Conn, proxy *Proxy) *ConnContext {
	clientConn := newClientConn(c)
	return &ConnContext{
		ClientConn: clientConn,
		proxy:      proxy,
	}
}

func (connCtx *ConnContext) Id() uuid.UUID {
	return connCtx.ClientConn.Id
}
