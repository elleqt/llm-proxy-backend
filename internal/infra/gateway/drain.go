package gateway

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// drainSettle is how long a drain waits, once the last request in flight has
// returned from the handler chain, before the service is stopped. net/http
// writes a response's last buffered bytes, and a chunked response's
// terminator, only after the chain has returned, and upstream's stop closes
// every connection at once, so stopping straight away could cut them. It
// covers that final write into the socket, not a client too slow to take it.
const drainSettle = 250 * time.Millisecond

// requestDrain lets Shutdown finish the proxied requests in flight, which
// upstream's own stop does not: from v7.3.17 it closes the listener and every
// connection at once (internal/api/server.go Stop). It counts the requests
// in flight; once the drain starts, it refuses every new request 503 with
// Connection: close, so the client does not reuse the connection and steady
// traffic cannot hold the drain open until its deadline. The zero value
// serves.
type requestDrain struct {
	mu       sync.Mutex
	inFlight int
	// idle is nil until the drain starts, and then closed once no request is
	// in flight.
	idle chan struct{}
}

// track is the drain's middleware. It goes ahead of every other one
// (configureEngine), so it counts a request from before upstream's first
// middleware until after its last.
func (d *requestDrain) track() gin.HandlerFunc {
	return func(ginCtx *gin.Context) {
		if !d.enter() {
			ginCtx.Header("Connection", "close")
			abortWithError(ginCtx, http.StatusServiceUnavailable, "server_error", "the gateway is shutting down; retry")

			return
		}
		defer d.leave()

		ginCtx.Next()
	}
}

// enter counts a request in, and reports false, counting nothing, once the
// drain has started.
func (d *requestDrain) enter() bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.idle != nil {
		return false
	}

	d.inFlight++

	return true
}

// leave counts a request out, and ends a started drain with the last one.
func (d *requestDrain) leave() {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.inFlight--
	if d.inFlight == 0 && d.idle != nil {
		close(d.idle)
	}
}

// stop starts the drain, unless it has started, and returns a channel closed
// once no request is in flight.
func (d *requestDrain) stop() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.idle == nil {
		d.idle = make(chan struct{})
		if d.inFlight == 0 {
			close(d.idle)
		}
	}

	return d.idle
}

// wait starts the drain, unless it has started, and returns nil drainSettle
// after no request is in flight, or an error wrapping ctx's if ctx ends first.
func (d *requestDrain) wait(ctx context.Context) error {
	select {
	case <-d.stop():
	case <-ctx.Done():
		return fmt.Errorf("gateway: drain the requests in flight: %w", ctx.Err())
	}

	settle := time.NewTimer(drainSettle)
	defer settle.Stop()

	select {
	case <-settle.C:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("gateway: let the last response settle: %w", ctx.Err())
	}
}
