package gateway

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/sync/semaphore"
)

// The gate holds every model-route body in memory: it reads the whole body
// to find the model, and hands the same bytes to the handler. bodyBudget
// caps, process wide, the bytes those bodies hold, so parallel large bodies
// cannot exhaust memory. A body is charged the capacity of the buffer
// holding it, which grows with the bytes received — a declared length only
// bounds it — and decoding an encoded body is charged a whole maxJSONBody
// more while it runs, then the decoded body instead of the encoded one. A
// charge is held until the handler returns. A request that cannot get a step
// of its charge within bodyWait is answered 503. The body must arrive within
// bodyReadTimeout (408 otherwise), so a stalled sender releases its charge.
//
// What is charged is the live buffer: the one a growing buffer is copied
// out of, and buffers already given back, stay on the heap uncharged until
// the garbage collector frees them. So the budget holds two multipart image
// edits at their limit, or eight JSON bodies at theirs, and the heap may
// briefly exceed it by the buffers being replaced.
const (
	maxBodiesInFlight  int64 = 2 * maxMultipartBody
	initialBodyBuffer  int64 = 16 << 10
	defaultBodyWait          = 2 * time.Second
	defaultBodyTimeout       = 60 * time.Second
)

var (
	bodyBudget      = semaphore.NewWeighted(maxBodiesInFlight)
	bodyWait        = defaultBodyWait
	bodyReadTimeout = defaultBodyTimeout
)

// errBodyBusy is a body's charge not being granted within bodyWait.
var errBodyBusy = errors.New("gateway: too many request bodies in flight")

// bodyCharge is the share of bodyBudget one request holds. The gate's
// goroutine alone uses it; the zero or nil charge holds nothing.
type bodyCharge struct {
	n int64
}

// grow adds n bytes to the charge, waiting at most bodyWait for them.
func (b *bodyCharge) grow(ctx context.Context, n int64) error {
	waitCtx, cancel := context.WithTimeout(ctx, bodyWait)
	defer cancel()
	if err := bodyBudget.Acquire(waitCtx, n); err != nil {
		return errBodyBusy
	}
	b.n += n
	return nil
}

// shrinkTo gives back all but n bytes of the charge; a charge already at
// most n is left as it is.
func (b *bodyCharge) shrinkTo(n int64) {
	if b == nil || b.n <= n {
		return
	}
	bodyBudget.Release(b.n - n)
	b.n = n
}

// release gives back the whole charge.
func (b *bodyCharge) release() { b.shrinkTo(0) }

// bodyLength is the length r's body declares: 0 for none, -1 when it is sent
// without one (chunked).
func bodyLength(r *http.Request) int64 {
	switch {
	case r.Body == nil || r.Body == http.NoBody:
		return 0
	case r.ContentLength > 0:
		return r.ContentLength
	default:
		return -1
	}
}

// bufferBody reads a body of length (bodyLength; at most limit) whole from
// body, a reader bounded at limit, charging bodyBudget for the buffer as it
// grows: it doubles from initialBodyBuffer as bytes arrive, straight to the
// declared length once doubling would reach it, so a body is charged at most
// its own length and a sender that declares a large body and sends nothing
// holds only the initial buffer. It returns the body and its charge, which
// the caller releases once the request is done with the body, also when
// reading failed (errBodyBusy when a step of the charge was not granted in
// time).
func bufferBody(ctx context.Context, body io.ReadCloser, length, limit int64) ([]byte, *bodyCharge, error) {
	defer body.Close()
	held := &bodyCharge{}
	// A known length is read exactly, an unknown one up to limit.
	size := length
	if length < 0 {
		size = limit
	}
	initial := min(initialBodyBuffer, size)
	if err := held.grow(ctx, initial); err != nil {
		return nil, held, err
	}
	buf := make([]byte, 0, initial)
	for {
		if len(buf) == cap(buf) {
			if int64(len(buf)) == size {
				if length >= 0 {
					return buf, held, nil
				}
				return buf, held, probeEnd(body)
			}
			grown := min(2*int64(cap(buf)), size)
			if err := held.grow(ctx, grown-held.n); err != nil {
				return buf, held, err
			}
			next := make([]byte, len(buf), grown)
			copy(next, buf)
			buf = next
		}
		n, err := body.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		switch {
		case errors.Is(err, io.EOF) && length >= 0 && int64(len(buf)) < length:
			return buf, held, io.ErrUnexpectedEOF
		case errors.Is(err, io.EOF):
			return buf, held, nil
		case err != nil:
			return buf, held, err
		}
	}
}

// probeEnd reports whether body, read up to its limit, ends there: nil at
// its end; the bounded reader's error, or errBodyOverRead, when there is
// more.
func probeEnd(body io.Reader) error {
	var probe [1]byte
	for {
		n, err := body.Read(probe[:])
		switch {
		case n > 0:
			return errBodyOverRead
		case errors.Is(err, io.EOF):
			return nil
		case err != nil:
			return err
		}
	}
}

// errBodyOverRead is a body going on past its limit.
var errBodyOverRead = errors.New("gateway: request body over its limit")

// readDeadlineKey is where readDeadlineControl keeps the request's
// *http.ResponseController in the gin context.
const readDeadlineKey = "gateway.readDeadline"

// readDeadlineControl is the embedded engine's first middleware. It keeps a
// controller over the connection's writer for the gate while c.Writer is
// still gin's own: upstream's middleware wraps the writer (logging
// cpaTraceResponseWriter) in a type a ResponseController cannot see through.
func readDeadlineControl() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(readDeadlineKey, http.NewResponseController(c.Writer))
	}
}

// errNoReadDeadline is a request whose connection cannot bound the time
// its body takes: readDeadlineControl did not run, or the writer it saw
// offers no deadline.
var errNoReadDeadline = errors.New("gateway: the request body's read deadline cannot be set")

// setBodyReadDeadline bounds, on c's connection, the time left to receive
// the request body: a sender that stalls cannot keep its request, and what
// its body is charged, past bodyReadTimeout. The server lifts the deadline
// itself once the whole body has been read (net/http
// connReader.startBackgroundRead), so a long response is not cut, and every
// request on the connection starts without one.
func setBodyReadDeadline(c *gin.Context) error {
	rc, ok := c.Value(readDeadlineKey).(*http.ResponseController)
	if !ok {
		return errNoReadDeadline
	}
	if err := rc.SetReadDeadline(time.Now().Add(bodyReadTimeout)); err != nil {
		return errors.Join(errNoReadDeadline, err)
	}
	return nil
}

// bodyTimedOut reports whether err is the body's read deadline passing.
func bodyTimedOut(err error) bool {
	return errors.Is(err, os.ErrDeadlineExceeded)
}
