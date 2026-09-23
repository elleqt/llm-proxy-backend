package gateway

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
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
// of its charge within bodyWait is answered 503. Each user's charges together
// may hold a quarter of the budget, or one request's own maximum if that is
// more (newBodyCharge); a charge past it is answered 429 at once. The body
// must arrive within bodyReadTimeout (408 otherwise), so a stalled sender
// releases its charge.
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
	bodyBudgetSize  = maxBodiesInFlight
	bodyWait        = defaultBodyWait
	bodyReadTimeout = defaultBodyTimeout
)

// errBodyBusy is a body's charge not being granted within bodyWait.
var errBodyBusy = errors.New("gateway: too many request bodies in flight")

// errBodyShare is a charge that would take its owner past their share.
var errBodyShare = errors.New("gateway: the account holds its share of the body budget")

// bodyShares is what each owner's charges hold of bodyBudget together, so
// that one user — with any number of tokens — holding bodies in long
// responses cannot take the whole budget from everyone else. An owner
// holding nothing has no entry.
var bodyShares = struct {
	mu   sync.Mutex
	held map[uuid.UUID]int64
}{held: map[uuid.UUID]int64{}}

// bodyCharge is the share of bodyBudget one request holds, counted to its
// owner. The gate's goroutine alone uses it.
type bodyCharge struct {
	n     int64
	owner uuid.UUID
	// share is the most the owner's charges may hold together while this
	// one grows.
	share int64
}

// newBodyCharge is an empty charge for a request of owner that may itself
// be charged at most most bytes. The owner's share is a quarter of the
// budget, but never less than most: a request within its route's limits is
// not refused for its own size, only for what else its owner holds.
func newBodyCharge(owner uuid.UUID, most int64) *bodyCharge {
	return &bodyCharge{owner: owner, share: max(bodyBudgetSize/4, most)}
}

// grow adds n bytes to the charge: refused at once (errBodyShare) when the
// owner's charges would pass the share, else waiting at most bodyWait for
// the budget.
func (b *bodyCharge) grow(ctx context.Context, n int64) error {
	bodyShares.mu.Lock()
	if bodyShares.held[b.owner]+n > b.share {
		bodyShares.mu.Unlock()
		return errBodyShare
	}
	bodyShares.held[b.owner] += n
	bodyShares.mu.Unlock()
	waitCtx, cancel := context.WithTimeout(ctx, bodyWait)
	defer cancel()
	if err := bodyBudget.Acquire(waitCtx, n); err != nil {
		b.unshare(n)
		return errBodyBusy
	}
	b.n += n
	return nil
}

// unshare takes n bytes off the owner's charges.
func (b *bodyCharge) unshare(n int64) {
	bodyShares.mu.Lock()
	defer bodyShares.mu.Unlock()
	if left := bodyShares.held[b.owner] - n; left > 0 {
		bodyShares.held[b.owner] = left
	} else {
		delete(bodyShares.held, b.owner)
	}
}

// shrinkTo gives back all but n bytes of the charge, to the budget and the
// owner's share alike; a charge already at most n is left as it is.
func (b *bodyCharge) shrinkTo(n int64) {
	if b.n <= n {
		return
	}
	bodyBudget.Release(b.n - n)
	b.unshare(b.n - n)
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
// body, a reader bounded at limit, charging held for the buffer as it
// grows: it doubles from initialBodyBuffer as bytes arrive, straight to the
// declared length once doubling would reach it, so a body is charged at most
// its own length and a sender that declares a large body and sends nothing
// holds only the initial buffer. The caller releases held once the request
// is done with the body, also when reading failed (errBodyShare or
// errBodyBusy when a step of the charge was not granted).
func bufferBody(ctx context.Context, held *bodyCharge, body io.ReadCloser, length, limit int64) ([]byte, error) {
	defer body.Close()
	// A known length is read exactly, an unknown one up to limit.
	size := length
	if length < 0 {
		size = limit
	}
	initial := min(initialBodyBuffer, size)
	if err := held.grow(ctx, initial); err != nil {
		return nil, err
	}
	buf := make([]byte, 0, initial)
	for {
		if len(buf) == cap(buf) {
			if int64(len(buf)) == size {
				if length >= 0 {
					return buf, nil
				}
				return buf, probeEnd(body)
			}
			grown := min(2*int64(cap(buf)), size)
			if err := held.grow(ctx, grown-held.n); err != nil {
				return buf, err
			}
			next := make([]byte, len(buf), grown)
			copy(next, buf)
			buf = next
		}
		n, err := body.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		switch {
		case errors.Is(err, io.EOF) && length >= 0 && int64(len(buf)) < length:
			return buf, io.ErrUnexpectedEOF
		case errors.Is(err, io.EOF):
			return buf, nil
		case err != nil:
			return buf, err
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

// bodyDeadline bounds the time left to receive a request body: a sender that
// stalls cannot keep its request, and what its body is charged, past
// bodyReadTimeout.
//
// The deadline is set on the connection at once, and set again by a timer when
// it passes. The second setting is what enforces it: upstream's connection
// multiplexer hands a connection to the HTTP server and only then clears its
// own sniffing deadline (internal/api/protocol_multiplexer.go,
// routeMuxConnection), so on a busy process that clear can land after the
// first setting, while the gate is already blocked reading. A deadline already
// past makes that read return at once.
//
// The server lifts the deadline itself once the whole body has been read
// (net/http connReader.startBackgroundRead), so a long response is not cut,
// and every request on the connection starts without one. stop must be called
// as soon as the body has been read, before anything slow.
type bodyDeadline struct {
	timer *time.Timer
	fired chan struct{}
}

// setBodyReadDeadline starts c's body deadline.
func setBodyReadDeadline(c *gin.Context) (*bodyDeadline, error) {
	rc, ok := c.Value(readDeadlineKey).(*http.ResponseController)
	if !ok {
		return nil, errNoReadDeadline
	}
	deadline := time.Now().Add(bodyReadTimeout)
	if err := rc.SetReadDeadline(deadline); err != nil {
		return nil, errors.Join(errNoReadDeadline, err)
	}
	d := &bodyDeadline{fired: make(chan struct{})}
	d.timer = time.AfterFunc(time.Until(deadline), func() {
		defer close(d.fired)
		_ = rc.SetReadDeadline(deadline)
	})
	return d, nil
}

// stop ends the deadline's watch and reports whether the timer had already
// fired. A body read by then counts as late whatever the read returned: once
// the deadline was set again, the server's background read on a finished body
// may have failed on it and cancelled the request. stop waits for a running
// timer, so the connection is not touched after the gate moves on. A nil
// deadline (a request without a body) never fires.
func (d *bodyDeadline) stop() (late bool) {
	if d == nil || d.timer.Stop() {
		return false
	}
	<-d.fired
	return true
}

// bodyTimedOut reports whether err is the body's read deadline passing.
func bodyTimedOut(err error) bool {
	return errors.Is(err, os.ErrDeadlineExceeded)
}
