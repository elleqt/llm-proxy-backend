package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// drainedEngine serves POST /v1/chat/completions behind drain. Its handler
// tells entered it was reached and, for a target carrying ?hold, then waits
// for proceed to be closed.
func drainedEngine(drain *requestDrain, entered chan<- struct{}, proceed <-chan struct{}) *gin.Engine {
	engine := gin.New()
	engine.Use(drain.track())
	engine.POST("/v1/chat/completions", func(ginCtx *gin.Context) {
		entered <- struct{}{}

		if _, hold := ginCtx.GetQuery("hold"); hold {
			<-proceed
		}

		ginCtx.Status(http.StatusOK)
	})

	return engine
}

func chatTo(engine *gin.Engine, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodPost, target, strings.NewReader(`{}`)))

	return rec
}

// TestTheDrainFinishesRequestsInFlightAndRefusesNewOnes: once the drain has
// started, a new request is answered 503 with Connection: close without
// reaching its handler, while the request already in flight runs to its end.
// The drain ends only after that request, and drainSettle after it, so the
// last response's final bytes are written before the service stops.
func TestTheDrainFinishesRequestsInFlightAndRefusesNewOnes(t *testing.T) {
	var drain requestDrain

	entered, proceed := make(chan struct{}, 2), make(chan struct{})
	engine := drainedEngine(&drain, entered, proceed)

	var wg sync.WaitGroup
	wg.Go(func() {
		rec := chatTo(engine, "/v1/chat/completions?hold")
		assert.Equal(t, http.StatusOK, rec.Code, "the request in flight when the drain started")
	})
	<-entered

	idle := drain.stop()

	rec := chatTo(engine, "/v1/chat/completions")
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, "a request after the drain started")
	require.JSONEq(t, `{"error":{"message":"the gateway is shutting down; retry","type":"server_error"}}`, rec.Body.String())
	require.Equal(t, "close", rec.Header().Get("Connection"), "a request after the drain started")
	require.Empty(t, entered, "a request after the drain started reached its handler")

	select {
	case <-idle:
		require.Fail(t, "the drain ended with a request in flight")
	default:
	}

	close(proceed)
	wg.Wait()

	started := time.Now()

	require.NoError(t, drain.wait(t.Context()))
	require.GreaterOrEqual(t, time.Since(started), drainSettle, "the drain ended without letting the last response settle")
}

// TestTheDrainGivesUpWhenItsContextEnds: a request still in flight when the
// drain's context ends leaves the drain with the context's error, which
// Shutdown reports as requests cut.
func TestTheDrainGivesUpWhenItsContextEnds(t *testing.T) {
	var drain requestDrain

	entered, proceed := make(chan struct{}, 1), make(chan struct{})
	engine := drainedEngine(&drain, entered, proceed)

	var wg sync.WaitGroup
	wg.Go(func() { chatTo(engine, "/v1/chat/completions?hold") })
	<-entered

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	require.ErrorIs(t, drain.wait(ctx), context.DeadlineExceeded)

	close(proceed)
	wg.Wait()
}
