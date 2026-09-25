package gateway

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/api/handlers"
	cliproxyconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seenRequest is what a handler behind the gate was given.
type seenRequest struct {
	encoding      string
	contentLength int64
	lengthHeader  string
	body          string
	readBody      string
}

// TestEncodedBodyIsDecodedOnceForTheHandler: on a route whose handler decodes
// a zstd body, the gate decodes it and passes it on identity-encoded, so
// neither the handler nor upstream's request logger decodes it again —
// and plain JSON labelled zstd is passed on as sent, as upstream reads it.
func TestEncodedBodyIsDecodedOnceForTheHandler(t *testing.T) {
	const payload = `{"model":"gpt-5.6","messages":[{"role":"user","content":"hi"}]}`

	engine := gateEngine(staticResolver(gateSecret, gatePrincipal, "chatgpt:*"), fixedCatalog(map[string][]string{"gpt-5.6": {"chatgpt"}}))

	var seen seenRequest

	engine.POST("/v1/chat/completions", func(ginCtx *gin.Context) {
		raw, _ := io.ReadAll(ginCtx.Request.Body)
		ginCtx.Request.Body = io.NopCloser(bytes.NewReader(raw))

		read, err := handlers.ReadRequestBody(ginCtx)
		seen = seenRequest{ginCtx.GetHeader("Content-Encoding"), ginCtx.Request.ContentLength, ginCtx.GetHeader("Content-Length"), string(raw), string(read)}

		assert.NoError(t, err, "upstream's ReadRequestBody on what the gate passed on")
	})

	for _, tc := range []struct{ what, body string }{
		{"a zstd body", zstdCompress(t, payload)},
		{"plain JSON labelled zstd", payload},
	} {
		seen = seenRequest{}
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/chat/completions", strings.NewReader(tc.body))
		req.Header.Set("Content-Encoding", "zstd")
		req.Header.Set("Authorization", "Bearer "+gateSecret)

		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)

		want := seenRequest{"", int64(len(payload)), strconv.Itoa(len(payload)), payload, payload}

		assert.Equal(t, http.StatusOK, rec.Code, tc.what)
		assert.Equal(t, want, seen, "what the handler saw of %s", tc.what)
	}
}

// TestEncodedBodiesAreRefusedWhereNotDecoded: every route whose handler reads
// the body as sent, and the routes that read none, refuse an encoded body
// with 415 before anything else — even a body far beyond any limit once
// decoded costs nothing.
func TestEncodedBodiesAreRefusedWhereNotDecoded(t *testing.T) {
	catalog := fixedCatalog(map[string][]string{"gpt-5.6": {"chatgpt"}, "claude-sonnet-5": {"claude"}, "gemini-3-pro": {"gemini"}, "gpt-image-2": {"chatgpt"}})
	engine, reached := gated(staticResolver(gateSecret, gatePrincipal, "*:*"), catalog)
	bomb := chatDecodingTo("gpt-5.6", 1<<30)

	const refused = `{"error":{"message":"unsupported content encoding","type":"invalid_request_error"}}`

	for _, tc := range []struct{ method, path, contentType string }{
		{http.MethodPost, "/v1/messages", "application/json"},
		{http.MethodPost, "/v1/messages/count_tokens", "application/json"},
		{http.MethodPost, "/v1beta/models/gemini-3-pro:generateContent", "application/json"},
		{http.MethodPost, "/v1beta/interactions", "application/json"},
		{http.MethodPost, "/v1/images/edits", "multipart/form-data; boundary=x"},
		{http.MethodPost, "/v1/images/edits", ""},
		{http.MethodGet, "/v1/models", ""},
		{http.MethodHead, "/healthz", ""},
	} {
		*reached = false
		req := httptest.NewRequestWithContext(t.Context(), tc.method, tc.path, bytes.NewReader(bomb))
		req.Header.Set("Content-Encoding", "zstd")

		if tc.contentType != "" {
			req.Header.Set("Content-Type", tc.contentType)
		}

		req.Header.Set("Authorization", "Bearer "+gateSecret)

		rec := httptest.NewRecorder()

		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		engine.ServeHTTP(rec, req)
		runtime.ReadMemStats(&after)

		assert.Equal(t, http.StatusUnsupportedMediaType, rec.Code, "%s %s (%s) with a zstd body", tc.method, tc.path, tc.contentType)
		assert.JSONEq(t, refused, rec.Body.String(), "%s %s (%s) with a zstd body", tc.method, tc.path, tc.contentType)
		assert.False(t, *reached, "%s %s (%s) with a zstd body reached the handler", tc.method, tc.path, tc.contentType)
		assert.LessOrEqual(t, after.TotalAlloc-before.TotalAlloc, uint64(16<<20), "%s %s with a zstd body allocated too much", tc.method, tc.path)
	}
}

// TestPublicAndListingRoutesGetNoBody: the routes that read no body pass
// none on, so nothing upstream reads what a client sent with them.
func TestPublicAndListingRoutesGetNoBody(t *testing.T) {
	engine := gateEngine(staticResolver(gateSecret, gatePrincipal, "*:*"), fixedCatalog(nil))

	var got []string

	record := func(c *gin.Context) {
		b, _ := io.ReadAll(c.Request.Body)
		got = append(got, c.Request.Method+" "+string(b))
		c.JSON(http.StatusOK, gin.H{"object": "list", "data": []any{}})
	}
	engine.HEAD("/healthz", record)
	engine.GET("/v1/models", record)

	for _, method := range []string{http.MethodHead, http.MethodGet} {
		path := map[string]string{http.MethodHead: "/healthz", http.MethodGet: "/v1/models"}[method]
		req := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader("a body nobody asked for"))
		req.Header.Set("Authorization", "Bearer "+gateSecret)
		engine.ServeHTTP(httptest.NewRecorder(), req)
	}

	require.Equal(t, "HEAD |GET ", strings.Join(got, "|"), "handlers read %q, want no body on either route", got)
}

// allocatedBy sends req and returns the status and the bytes the
// process allocated meanwhile.
func allocatedBy(t *testing.T, req *http.Request) (int, uint64) {
	t.Helper()

	var before, after runtime.MemStats

	runtime.GC()
	runtime.ReadMemStats(&before)

	resp, err := noRedirects.Do(req)
	require.NoError(t, err, "%s %s", req.Method, req.URL.Path)

	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	runtime.ReadMemStats(&after)

	return resp.StatusCode, after.TotalAlloc - before.TotalAlloc
}

// TestEncodedBodiesNeverReachUpstreamsDecoders drives the real server — so
// upstream's request logger, which decodes every non-GET body it captures
// without a bound, is on the path. A 16 KiB frame decoding to 512 MiB is
// refused without a token on HEAD /healthz, and with one on the Gemini
// action route, whose handler reads the body as sent; neither allocates
// anything near its decoded size.
func TestEncodedBodiesNeverReachUpstreamsDecoders(t *testing.T) {
	srv := start(t, &cliproxyconfig.Config{})
	registerClient(t, "decoders-client-gemini", "gemini", "decoders-gemini")

	bomb := chatDecodingTo("decoders-gemini", 512<<20)

	for _, tc := range []struct{ method, path, key string }{
		{http.MethodHead, "/healthz", ""},
		{http.MethodPost, "/v1beta/models/decoders-gemini:generateContent", wireSecret},
	} {
		req, err := http.NewRequestWithContext(t.Context(), tc.method, srv.baseURL+tc.path, bytes.NewReader(bomb))
		require.NoError(t, err, "build request")

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Encoding", "zstd")

		if tc.key != "" {
			req.Header.Set("Authorization", "Bearer "+tc.key)
		}

		code, allocated := allocatedBy(t, req)
		assert.Equal(t, http.StatusUnsupportedMediaType, code, "%s %s with a %d-byte zstd body", tc.method, tc.path, len(bomb))
		assert.LessOrEqual(t, allocated, uint64(64<<20),
			"%s %s with a %d-byte zstd body allocated too much, want far below its 512 MiB decoded size", tc.method, tc.path, len(bomb))
	}
}

// zstdChat sends a zstd-encoded chat request through engine.
func zstdChat(engine *gin.Engine, frame []byte) *httptest.ResponseRecorder {
	return zstdChatAs(engine, gateSecret, frame)
}

// zstdChatAs is zstdChat with key.
func zstdChatAs(engine *gin.Engine, key string, frame []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", bytes.NewReader(frame))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "zstd")
	req.Header.Set("Authorization", "Bearer "+key)

	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

	return rec
}

// TestDecodingWaitsForItsShareOfTheBudget: a request that cannot get the
// share of the process-wide body budget decoding needs in time is answered
// 503 without being decoded or handled; once the budget is free it is served.
func TestDecodingWaitsForItsShareOfTheBudget(t *testing.T) {
	budget := withBodyBudget(t, 2*maxJSONBody, 50*time.Millisecond)
	engine, reached := gated(staticResolver(gateSecret, gatePrincipal, "chatgpt:*"), fixedCatalog(map[string][]string{"gpt-5.6": {"chatgpt"}}))
	frame := []byte(zstdCompress(t, `{"model":"gpt-5.6","messages":[]}`))

	// Room for the frame as sent, not for decoding it.
	const taken = maxJSONBody + 1
	require.NoError(t, budget.Acquire(context.Background(), taken))

	const busy = `{"error":{"message":"too many request bodies in flight; retry","type":"server_error"}}`

	rec := zstdChat(engine, frame)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, "without room to decode")
	require.JSONEq(t, busy, rec.Body.String(), "without room to decode")
	require.False(t, *reached, "without room to decode, reached the handler")

	budget.Release(taken)

	rec = zstdChat(engine, frame)
	require.Equal(t, http.StatusOK, rec.Code, "with the decode budget free: %s", rec.Body)
	require.True(t, *reached, "with the decode budget free, did not reach the handler")
}

// TestParallelBombsStayWithinTheDecodeBudget: sixteen requests of sixteen
// users decoding past the limit at once are decoded a budget's worth at a
// time, so the heap peaks near what that budget allows, not sixteen times one
// decode; each is answered 413.
func TestParallelBombsStayWithinTheDecodeBudget(t *testing.T) {
	const parallel = 16

	withBodyBudget(t, 2*maxJSONBody, time.Minute)

	defer debug.SetGCPercent(debug.SetGCPercent(10))

	engine, _ := gated(usersResolver, fixedCatalog(map[string][]string{"gpt-5.6": {"chatgpt"}}))
	bomb := chatDecodingTo("gpt-5.6", 1<<30)

	runtime.GC()

	var base runtime.MemStats
	runtime.ReadMemStats(&base)

	var peak atomic.Uint64

	stop := make(chan struct{})

	sampled := make(chan struct{})
	go func() {
		defer close(sampled)

		var mem runtime.MemStats

		for {
			select {
			case <-stop:
				return
			case <-time.After(2 * time.Millisecond):
			}

			runtime.ReadMemStats(&mem)

			if mem.HeapInuse > peak.Load() {
				peak.Store(mem.HeapInuse)
			}
		}
	}()

	var wg sync.WaitGroup

	codes := make([]int, parallel)
	for i := range parallel {
		wg.Go(func() {
			codes[i] = zstdChatAs(engine, userKey(strconv.Itoa(i), 1), bomb).Code
		})
	}

	wg.Wait()
	close(stop)
	<-sampled

	for i, code := range codes {
		assert.Equal(t, http.StatusRequestEntityTooLarge, code, "bomb %d", i)
	}

	const bound = 1 << 30

	grew := peak.Load() - min(peak.Load(), base.HeapInuse)
	t.Logf("%d parallel bombs grew the heap by %d MiB at peak", parallel, grew>>20)

	require.LessOrEqual(t, grew, uint64(bound), "%d parallel bombs grew the heap by %d MiB at peak, want at most %d MiB", parallel, grew>>20, bound>>20)
}

// TestDecodedBodiesHoldTheBudgetUntilServed: a decoded body keeps its length
// of the body budget until its handler returns, so bodies of different users
// waiting in slow handlers cannot pile up past the budget: once they hold it,
// the next encoded request is answered 503, and when they finish the whole
// budget is free again.
func TestDecodedBodiesHoldTheBudgetUntilServed(t *testing.T) {
	const budget, bodySize = 2 * maxJSONBody, 32 << 20
	withBodyBudget(t, budget, 50*time.Millisecond)

	engine := gateEngine(usersResolver, fixedCatalog(map[string][]string{"gpt-5.6": {"chatgpt"}}))
	proceed, entered := make(chan struct{}), make(chan struct{}, 8)

	engine.POST("/v1/chat/completions", func(_ *gin.Context) {
		entered <- struct{}{}

		<-proceed
	})

	frame := chatDecodingTo("gpt-5.6", bodySize)

	runtime.GC()

	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	// Decoding needs a whole maxJSONBody on top of the frame, so each held
	// body leaves room for one more decode until two are held.
	const held = 2

	var wg sync.WaitGroup
	for i := range held {
		wg.Go(func() {
			rec := zstdChatAs(engine, userKey(strconv.Itoa(i), 1), frame)
			assert.Equal(t, http.StatusOK, rec.Code, "held request: %s", rec.Body)
		})

		<-entered
	}

	runtime.GC()

	var holding runtime.MemStats
	runtime.ReadMemStats(&holding)

	grew := holding.HeapInuse - min(holding.HeapInuse, base.HeapInuse)
	assert.LessOrEqual(t, grew, uint64(budget), "%d held bodies grew the heap by %d MiB, want at most the %d MiB budget", held, grew>>20, budget>>20)

	const busy = `{"error":{"message":"too many request bodies in flight; retry","type":"server_error"}}`

	next := make(chan *httptest.ResponseRecorder, 1)
	go func() { next <- zstdChatAs(engine, userKey("next", 1), frame) }()

	select {
	case <-entered:
		close(proceed)
		wg.Wait()
		<-next
		require.Failf(t, "another encoded request reached its handler", "with %d bodies held, want 503", held)
	case rec := <-next:
		require.Equal(t, http.StatusServiceUnavailable, rec.Code, "with %d bodies held", held)
		require.JSONEq(t, busy, rec.Body.String(), "with %d bodies held", held)
	}

	close(proceed)
	wg.Wait()

	require.True(t, bodyBudget.TryAcquire(budget), "after the held requests finished the budget is not whole again")

	bodyBudget.Release(budget)
}
