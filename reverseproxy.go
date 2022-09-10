// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/* // mod by prog4food
Основные изменения:
 + режим StrictRequests - проксирование только по WhiteList заголовкам
 + режим DenyConnUpgrade, который блокирует Upgrade соединения
 + буфер fb (first bytes) который позволяет читать начало запроса для валидации данных
 + режим Deep3XX, проходящий по 3XX запросам до указанной глубины
 + лимит размера проксируемого запроса и соотв ошибка err_ResponseOversize
 + возможность останавливать проксирование на этапе Director
 + отключение Forwarded заголовка через NoForwardedHeader
*/
// HTTP reverse proxy handler

package reverse_proxy_plus

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"reverse_proxy_plus/internal/ascii"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http/httpguts"
)

// ReverseProxy is an HTTP Handler that takes an incoming request and
// sends it to another server, proxying the response back to the
// client.
//
// ReverseProxy by default sets the client IP as the value of the
// X-Forwarded-For header.
//
// If an X-Forwarded-For header already exists, the client IP is
// appended to the existing values. As a special case, if the header
// exists in the Request.Header map but has a nil value (such as when
// set by the Director func), the X-Forwarded-For header is
// not modified.
//
// To prevent IP spoofing, be sure to delete any pre-existing
// X-Forwarded-For header coming from the client or
// an untrusted proxy.
type ReverseProxy struct {
	// Director must be a function which modifies
	// the request into a new request to be sent
	// using Transport. Its response is then copied
	// back to the original client unmodified.
	// Director must not access the provided Request
	// after returning.
	Director func(*http.Request) bool

	// The transport used to perform proxy requests.
	// If nil, http.DefaultTransport is used.
	Transport http.RoundTripper

	// FlushInterval specifies the flush interval
	// to flush to the client while copying the
	// response body.
	// If zero, no periodic flushing is done.
	// A negative value means to flush immediately
	// after each write to the client.
	// The FlushInterval is ignored when ReverseProxy
	// recognizes a response as a streaming response, or
	// if its ContentLength is -1; for such responses, writes
	// are flushed to the client immediately.
	FlushInterval time.Duration

	// ErrorLog specifies an optional logger for errors
	// that occur when attempting to proxy the request.
	// If nil, logging is done via the log package's standard logger.
	ErrorLog *log.Logger

	// BufferPool optionally specifies a buffer pool to
	// get byte slices for use by io.CopyBuffer when
	// copying HTTP response bodies.
	BufferPool BufferPool

	// ModifyResponse is an optional function that modifies the
	// Response from the backend. It is called if the backend
	// returns a response at all, with any HTTP status code.
	// If the backend is unreachable, the optional ErrorHandler is
	// called without any call to ModifyResponse.
	//
	// If ModifyResponse returns an error, ErrorHandler is called
	// with its error value. If ErrorHandler is nil, its default
	// implementation is used.
	ModifyResponse func(*http.Response) ([]byte, error)

	// ErrorHandler is an optional function that handles errors
	// reaching the backend or errors from ModifyResponse.
	//
	// If nil, the default is to log the provided error and return
	// a 502 Status Bad Gateway response.
	ErrorHandler func(http.ResponseWriter, *http.Request, error)

	Deep3XX uint8
	DenyConnUpgrade bool
	NoForwardedHeader bool

	StrictRequests bool
	StrictReqHeaderList []string
	ResponseLimit int64
}

var (
	err_ResponseOversize = errors.New("Response oversize!")
)

// A BufferPool is an interface for getting and returning temporary
// byte slices for use by io.CopyBuffer.
type BufferPool interface {
	Get() []byte
	Put([]byte)
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

func joinURLPath(a, b *url.URL) (path, rawpath string) {
	if a.RawPath == "" && b.RawPath == "" {
		return singleJoiningSlash(a.Path, b.Path), ""
	}
	// Same as singleJoiningSlash, but uses EscapedPath to determine
	// whether a slash should be added
	apath := a.EscapedPath()
	bpath := b.EscapedPath()

	aslash := strings.HasSuffix(apath, "/")
	bslash := strings.HasPrefix(bpath, "/")

	switch {
	case aslash && bslash:
		return a.Path + b.Path[1:], apath + bpath[1:]
	case !aslash && !bslash:
		return a.Path + "/" + b.Path, apath + "/" + bpath
	}
	return a.Path + b.Path, apath + bpath
}

// NewSingleHostReverseProxy returns a new ReverseProxy that routes
// URLs to the scheme, host, and base path provided in target. If the
// target's path is "/base" and the incoming request was for "/dir",
// the target request will be for /base/dir.
// NewSingleHostReverseProxy does not rewrite the Host header.
// To rewrite Host headers, use ReverseProxy directly with a custom
// Director policy.
func NewSingleHostReverseProxy(target *url.URL) *ReverseProxy {
	targetQuery := target.RawQuery
	director := func(req *http.Request) bool {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path, req.URL.RawPath = joinURLPath(target, req.URL)
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
		if _, ok := req.Header["User-Agent"]; !ok {
			// explicitly disable User-Agent so it's not set to default value
			req.Header.Set("User-Agent", "")
		}
		return true
	}
	return &ReverseProxy{Director: director}
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// Hop-by-hop headers. These are removed when sent to the backend.
// As of RFC 7230, hop-by-hop headers are required to appear in the
// Connection header field. These are the headers defined by the
// obsoleted RFC 2616 (section 13.5.1) and are used for backward
// compatibility.
var hopHeaders = []string{
	"Connection",
	"Proxy-Connection", // non-standard but still sent by libcurl and rejected by e.g. google
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",      // canonicalized version of "TE"
	"Trailer", // not Trailers per URL above; https://www.rfc-editor.org/errata_search.php?eid=4522
	"Transfer-Encoding",
	"Upgrade",
}

func (p *ReverseProxy) defaultErrorHandler(rw http.ResponseWriter, req *http.Request, err error) {
	p.logf("http: proxy error: %v", err)
	rw.WriteHeader(http.StatusBadGateway)
}

func (p *ReverseProxy) getErrorHandler() func(http.ResponseWriter, *http.Request, error) {
	if p.ErrorHandler != nil {
		return p.ErrorHandler
	}
	return p.defaultErrorHandler
}

// modifyResponse conditionally runs the optional ModifyResponse hook
// and reports whether the request should proceed.
func (p *ReverseProxy) modifyResponse(rw http.ResponseWriter, res *http.Response, req *http.Request) ([]byte, error) {
	if p.ModifyResponse == nil {
		return nil, nil
	}
	fb, err := p.ModifyResponse(res); if err != nil {
		res.Body.Close()
		p.getErrorHandler()(rw, req, err)
		return nil, err
	}
	return fb, nil
}

func (p *ReverseProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	transport := p.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}

	ctx := req.Context()
	if ctx.Done() != nil {
		// CloseNotifier predates context.Context, and has been
		// entirely superseded by it. If the request contains
		// a Context that carries a cancellation signal, don't
		// bother spinning up a goroutine to watch the CloseNotify
		// channel (if any).
		//
		// If the request Context has a nil Done channel (which
		// means it is either context.Background, or a custom
		// Context implementation with no cancellation signal),
		// then consult the CloseNotifier if available.
	} else if cn, ok := rw.(http.CloseNotifier); ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		defer cancel()
		notifyChan := cn.CloseNotify()
		go func() {
			select {
			case <-notifyChan:
				cancel()
			case <-ctx.Done():
			}
		}()
	}

	outreq := req.Clone(ctx)
	if req.ContentLength == 0 {
		outreq.Body = nil // Issue 16036: nil Body for http.Transport retries
	}
	if outreq.Body != nil {
		// Reading from the request body after returning from a handler is not
		// allowed, and the RoundTrip goroutine that reads the Body can outlive
		// this handler. This can lead to a crash if the handler panics (see
		// Issue 46866). Although calling Close doesn't guarantee there isn't
		// any Read in flight after the handle returns, in practice it's safe to
		// read after closing it.
		defer outreq.Body.Close()
	}
	if outreq.Header == nil {
		outreq.Header = make(http.Header) // Issue 33142: historical behavior was to always allocate
	}

	if !p.Director(outreq) {
		return
	}
	outreq.Close = false

	if !p.DenyConnUpgrade {
		// Request: Normal mode
		reqUpType := upgradeType(outreq.Header)
		if !ascii.IsPrint(reqUpType) {
			p.getErrorHandler()(rw, req, fmt.Errorf("client tried to switch to invalid protocol %q", reqUpType))
			return
		}
		removeConnectionHeaders(outreq.Header)

		// Remove hop-by-hop headers to the backend. Especially
		// important is "Connection" because we want a persistent
		// connection, regardless of what the client sent to us.
		for _, h := range hopHeaders {
			outreq.Header.Del(h)
		}

		// After stripping all the hop-by-hop connection headers above, add back any
		// necessary for protocol upgrades, such as for websockets.
		if reqUpType != "" {
			outreq.Header.Set("Connection", "Upgrade")
			outreq.Header.Set("Upgrade", reqUpType)
		}
	} else {
		// Request: Deny Upgrade
		removeConnectionHeaders(outreq.Header)

		for _, h := range hopHeaders {
			outreq.Header.Del(h)
		}
	}

	if p.StrictRequests {
		// Request: Strict mode
		var whitelist_headers = make(http.Header)
		var _head_val string
		for _, h := range p.StrictReqHeaderList {
			_head_val = outreq.Header.Get(h)
			if _head_val != "" {
				whitelist_headers.Add(h, _head_val)
			}
		}
		outreq.Header = whitelist_headers
	}

	// Issue 21096: tell backend applications that care about trailer support
	// that we support trailers. (We do, but we don't go out of our way to
	// advertise that unless the incoming client request thought it was worth
	// mentioning.) Note that we look at req.Header, not outreq.Header, since
	// the latter has passed through removeConnectionHeaders.
	if httpguts.HeaderValuesContainsToken(req.Header["Te"], "trailers") {
		outreq.Header.Set("Te", "trailers")
	}

	if !p.NoForwardedHeader {
		if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
			// If we aren't the first proxy retain prior
			// X-Forwarded-For information as a comma+space
			// separated list and fold multiple headers into one.
			prior, ok := outreq.Header["X-Forwarded-For"]
			omit := ok && prior == nil // Issue 38079: nil now means don't populate the header
			if len(prior) > 0 {
				clientIP = strings.Join(prior, ", ") + ", " + clientIP
			}
			if !omit {
				outreq.Header.Set("X-Forwarded-For", clientIP)
			}
		}
	}

	var (
		res *http.Response
		err error
	)

	// Follow redirects if Deep3XX > 0
	R:
	for i := uint8(0); i <= p.Deep3XX; i++ {
		res, err = transport.RoundTrip(outreq)
		if err != nil {
			p.getErrorHandler()(rw, outreq, err)
			return
		}
		if p.Deep3XX == 0 {
			break R
		} else {
			switch res.StatusCode {
				// https://stackoverflow.com/questions/16194988/for-which-3xx-http-codes-is-the-location-header-mandatory
				case 300, 301, 302, 303, 307, 308:
					loc := res.Header.Get("Location")
					if loc == "" {
						// While most 3xx responses include a Location, it is not
						// required and 3xx responses without a Location have been
						// observed in the wild. See issues #17773 and #49281.
						p.logf("code 3xx, but Location header is empty")
						break R
					}
					outreq.URL, err = req.URL.Parse(loc)
					if err != nil {
						p.logf("failed to parse Location header %q: %v", loc, err)
						break R
					}
					outreq.Host = outreq.URL.Host
					continue
				default:
					break R
			}
		}
	}

	var fb []byte // First bytes buffer
	if !p.DenyConnUpgrade {
		// Deal with 101 Switching Protocols responses: (WebSocket, h2c, etc)
		if res.StatusCode == http.StatusSwitchingProtocols {
			fb, err = p.modifyResponse(rw, res, outreq); if err != nil {
				return
			}
			p.handleUpgradeResponse(rw, outreq, res)
			return
		}
	}

	removeConnectionHeaders(res.Header)

	for _, h := range hopHeaders {
		res.Header.Del(h)
	}

	fb, err = p.modifyResponse(rw, res, outreq); if err != nil {
		return
	}

	copyHeader(rw.Header(), res.Header)

	// The "Trailer" header isn't included in the Transport's response,
	// at least for *http.Transport. Build it up from Trailer.
	announcedTrailers := len(res.Trailer)
	if announcedTrailers > 0 {
		trailerKeys := make([]string, 0, len(res.Trailer))
		for k := range res.Trailer {
			trailerKeys = append(trailerKeys, k)
		}
		rw.Header().Add("Trailer", strings.Join(trailerKeys, ", "))
	}

	rw.WriteHeader(res.StatusCode)

	// Write header first bytes first
	if fb != nil {
		_, err = rw.Write(fb)
		if err != nil {
			p.logf("first bytes write error: %v", err)
		}
	}

	err = p.copyResponse(rw, res.Body, p.flushInterval(res))
	if err != nil {
		defer res.Body.Close()
		if err == err_ResponseOversize {
			p.logf("response error: %v", err)
			return
		}
		// Since we're streaming the response, if we run into an error all we can do
		// is abort the request. Issue 23643: ReverseProxy should use ErrAbortHandler
		// on read error while copying body.
		if !shouldPanicOnCopyError(req) {
			p.logf("suppressing panic for copyResponse error in test; copy error: %v", err)
			return
		}
		panic(http.ErrAbortHandler)
	}
	res.Body.Close() // close now, instead of defer, to populate res.Trailer

	if len(res.Trailer) > 0 {
		// Force chunking if we saw a response trailer.
		// This prevents net/http from calculating the length for short
		// bodies and adding a Content-Length.
		if fl, ok := rw.(http.Flusher); ok {
			fl.Flush()
		}
	}

	if len(res.Trailer) == announcedTrailers {
		copyHeader(rw.Header(), res.Trailer)
		return
	}

	for k, vv := range res.Trailer {
		k = http.TrailerPrefix + k
		for _, v := range vv {
			rw.Header().Add(k, v)
		}
	}
}

var inOurTests bool // whether we're in our own tests

// shouldPanicOnCopyError reports whether the reverse proxy should
// panic with http.ErrAbortHandler. This is the right thing to do by
// default, but Go 1.10 and earlier did not, so existing unit tests
// weren't expecting panics. Only panic in our own tests, or when
// running under the HTTP server.
func shouldPanicOnCopyError(req *http.Request) bool {
	if inOurTests {
		// Our tests know to handle this panic.
		return true
	}
	if req.Context().Value(http.ServerContextKey) != nil {
		// We seem to be running under an HTTP server, so
		// it'll recover the panic.
		return true
	}
	// Otherwise act like Go 1.10 and earlier to not break
	// existing tests.
	return false
}

// removeConnectionHeaders removes hop-by-hop headers listed in the "Connection" header of h.
// See RFC 7230, section 6.1
func removeConnectionHeaders(h http.Header) {
	for _, f := range h["Connection"] {
		for _, sf := range strings.Split(f, ",") {
			if sf = textproto.TrimString(sf); sf != "" {
				h.Del(sf)
			}
		}
	}
}

// flushInterval returns the p.FlushInterval value, conditionally
// overriding its value for a specific request/response.
func (p *ReverseProxy) flushInterval(res *http.Response) time.Duration {
	resCT := res.Header.Get("Content-Type")

	// For Server-Sent Events responses, flush immediately.
	// The MIME type is defined in https://www.w3.org/TR/eventsource/#text-event-stream
	if baseCT, _, _ := mime.ParseMediaType(resCT); baseCT == "text/event-stream" {
		return -1 // negative means immediately
	}

	// We might have the case of streaming for which Content-Length might be unset.
	if res.ContentLength == -1 {
		return -1
	}

	return p.FlushInterval
}

func (p *ReverseProxy) copyResponse(dst io.Writer, src io.Reader, flushInterval time.Duration) error {
	if flushInterval != 0 {
		if wf, ok := dst.(writeFlusher); ok {
			mlw := &maxLatencyWriter{
				dst:     wf,
				latency: flushInterval,
			}
			defer mlw.stop()

			// set up initial timer so headers get flushed even if body writes are delayed
			mlw.flushPending = true
			mlw.t = time.AfterFunc(flushInterval, mlw.delayedFlush)

			dst = mlw
		}
	}

	var buf []byte
	if p.BufferPool != nil {
		buf = p.BufferPool.Get()
		defer p.BufferPool.Put(buf)
	}
	_, err := p.copyBuffer(dst, src, buf)
	return err
}

// copyBuffer returns any write errors or non-EOF read errors, and the amount
// of bytes written.
func (p *ReverseProxy) copyBuffer(dst io.Writer, src io.Reader, buf []byte) (int64, error) {
	if len(buf) == 0 {
		buf = make([]byte, 32*1024)
	}
	var written int64
	for {
		nr, rerr := src.Read(buf)
		if rerr != nil && rerr != io.EOF && rerr != context.Canceled {
			p.logf("httputil: ReverseProxy read error during body copy: %v", rerr)
		}
		if nr > 0 {
			nw, werr := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
				if p.ResponseLimit != 0 && p.ResponseLimit < written {
					return written, err_ResponseOversize
				}
			}
			if werr != nil {
				return written, werr
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				rerr = nil
			}
			return written, rerr
		}
	}
}

func (p *ReverseProxy) logf(format string, args ...any) {
	if p.ErrorLog != nil {
		p.ErrorLog.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

type writeFlusher interface {
	io.Writer
	http.Flusher
}

type maxLatencyWriter struct {
	dst     writeFlusher
	latency time.Duration // non-zero; negative means to flush immediately

	mu           sync.Mutex // protects t, flushPending, and dst.Flush
	t            *time.Timer
	flushPending bool
}

func (m *maxLatencyWriter) Write(p []byte) (n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, err = m.dst.Write(p)
	if m.latency < 0 {
		m.dst.Flush()
		return
	}
	if m.flushPending {
		return
	}
	if m.t == nil {
		m.t = time.AfterFunc(m.latency, m.delayedFlush)
	} else {
		m.t.Reset(m.latency)
	}
	m.flushPending = true
	return
}

func (m *maxLatencyWriter) delayedFlush() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.flushPending { // if stop was called but AfterFunc already started this goroutine
		return
	}
	m.dst.Flush()
	m.flushPending = false
}

func (m *maxLatencyWriter) stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flushPending = false
	if m.t != nil {
		m.t.Stop()
	}
}

func upgradeType(h http.Header) string {
	if !httpguts.HeaderValuesContainsToken(h["Connection"], "Upgrade") {
		return ""
	}
	return h.Get("Upgrade")
}

func (p *ReverseProxy) handleUpgradeResponse(rw http.ResponseWriter, req *http.Request, res *http.Response) {
	reqUpType := upgradeType(req.Header)
	resUpType := upgradeType(res.Header)
	if !ascii.IsPrint(resUpType) { // We know reqUpType is ASCII, it's checked by the caller.
		p.getErrorHandler()(rw, req, fmt.Errorf("backend tried to switch to invalid protocol %q", resUpType))
	}
	if !ascii.EqualFold(reqUpType, resUpType) {
		p.getErrorHandler()(rw, req, fmt.Errorf("backend tried to switch protocol %q when %q was requested", resUpType, reqUpType))
		return
	}

	hj, ok := rw.(http.Hijacker)
	if !ok {
		p.getErrorHandler()(rw, req, fmt.Errorf("can't switch protocols using non-Hijacker ResponseWriter type %T", rw))
		return
	}
	backConn, ok := res.Body.(io.ReadWriteCloser)
	if !ok {
		p.getErrorHandler()(rw, req, fmt.Errorf("internal error: 101 switching protocols response with non-writable body"))
		return
	}

	backConnCloseCh := make(chan bool)
	go func() {
		// Ensure that the cancellation of a request closes the backend.
		// See issue https://golang.org/issue/35559.
		select {
		case <-req.Context().Done():
		case <-backConnCloseCh:
		}
		backConn.Close()
	}()

	defer close(backConnCloseCh)

	conn, brw, err := hj.Hijack()
	if err != nil {
		p.getErrorHandler()(rw, req, fmt.Errorf("Hijack failed on protocol switch: %v", err))
		return
	}
	defer conn.Close()

	copyHeader(rw.Header(), res.Header)

	res.Header = rw.Header()
	res.Body = nil // so res.Write only writes the headers; we have res.Body in backConn above
	if err := res.Write(brw); err != nil {
		p.getErrorHandler()(rw, req, fmt.Errorf("response write: %v", err))
		return
	}
	if err := brw.Flush(); err != nil {
		p.getErrorHandler()(rw, req, fmt.Errorf("response flush: %v", err))
		return
	}
	errc := make(chan error, 1)
	spc := switchProtocolCopier{user: conn, backend: backConn}
	go spc.copyToBackend(errc)
	go spc.copyFromBackend(errc)
	<-errc
}

// switchProtocolCopier exists so goroutines proxying data back and
// forth have nice names in stacks.
type switchProtocolCopier struct {
	user, backend io.ReadWriter
}

func (c switchProtocolCopier) copyFromBackend(errc chan<- error) {
	_, err := io.Copy(c.user, c.backend)
	errc <- err
}

func (c switchProtocolCopier) copyToBackend(errc chan<- error) {
	_, err := io.Copy(c.backend, c.user)
	errc <- err
}
