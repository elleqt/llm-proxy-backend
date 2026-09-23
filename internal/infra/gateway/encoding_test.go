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
	engine.POST("/v1/chat/completions", func(c *gin.Context) {
		raw, _ := io.ReadAll(c.Request.Body)
		c.Request.Body = io.NopCloser(bytes.NewReader(raw))
		read, err := handlers.ReadRequestBody(c)
		if err != nil {
			t.Errorf("upstream's ReadRequestBody on what the gate passed on: %v", err)
		}
		seen = seenRequest{c.GetHeader("Content-Encoding"), c.Request.ContentLength, c.GetHeader("Content-Length"), string(raw), string(read)}
	})

	for _, tc := range []struct{ what, body string }{
		{"a zstd body", zstdCompress(t, payload)},
		{"plain JSON labelled zstd", payload},
	} {
		seen = seenRequest{}
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(tc.body))
		req.Header.Set("Content-Encoding", "zstd")
		req.Header.Set("Authorization", "Bearer "+gateSecret)
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)
		want := seenRequest{"", int64(len(payload)), strconv.Itoa(len(payload)), payload, payload}
		if rec.Code != http.StatusOK || seen != want {
			t.Errorf("%s = %d, the handler saw %+v; want 200 and %+v", tc.what, rec.Code, seen, want)
		}
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
		req := httptest.NewRequest(tc.method, tc.path, bytes.NewReader(bomb))
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
		if rec.Code != http.StatusUnsupportedMediaType || rec.Body.String() != refused || *reached {
			t.Errorf("%s %s (%s) with a zstd body = %d %s (reached %t), want 415 %s", tc.method, tc.path, tc.contentType, rec.Code, rec.Body, *reached, refused)
		}
		if n := after.TotalAlloc - before.TotalAlloc; n > 16<<20 {
			t.Errorf("%s %s with a zstd body allocated %d MiB", tc.method, tc.path, n>>20)
		}
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
		req := httptest.NewRequest(method, path, strings.NewReader("a body nobody asked for"))
		req.Header.Set("Authorization", "Bearer "+gateSecret)
		engine.ServeHTTP(httptest.NewRecorder(), req)
	}
	if strings.Join(got, "|") != "HEAD |GET " {
		t.Fatalf("handlers read %q, want no body on either route", got)
	}
}

// allocatedBy sends req and returns the status and the bytes the
// process allocated meanwhile.
func allocatedBy(t *testing.T, req *http.Request) (int, uint64) {
	t.Helper()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	resp, err := noRedirects.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
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
	r := start(t, &cliproxyconfig.Config{})
	registerClient(t, "decoders-client-gemini", "gemini", "decoders-gemini")
	bomb := chatDecodingTo("decoders-gemini", 512<<20)

	for _, tc := range []struct{ method, path, key string }{
		{http.MethodHead, "/healthz", ""},
		{http.MethodPost, "/v1beta/models/decoders-gemini:generateContent", wireSecret},
	} {
		req, err := http.NewRequest(tc.method, r.baseURL+tc.path, bytes.NewReader(bomb))
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Encoding", "zstd")
		if tc.key != "" {
			req.Header.Set("Authorization", "Bearer "+tc.key)
		}
		code, allocated := allocatedBy(t, req)
		if code != http.StatusUnsupportedMediaType {
			t.Errorf("%s %s with a %d-byte zstd body = %d, want 415", tc.method, tc.path, len(bomb), code)
		}
		if allocated > 64<<20 {
			t.Errorf("%s %s with a %d-byte zstd body allocated %d MiB, want far below its 512 MiB decoded size", tc.method, tc.path, len(bomb), allocated>>20)
		}
	}
}

// zstdChat sends a zstd-encoded chat request through engine.
func zstdChat(engine *gin.Engine, frame []byte) *httptest.ResponseRecorder {
	return zstdChatAs(engine, gateSecret, frame)
}

// zstdChatAs is zstdChat with key.
func zstdChatAs(engine *gin.Engine, key string, frame []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(frame))
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
	if err := budget.Acquire(context.Background(), taken); err != nil {
		t.Fatal(err)
	}
	const busy = `{"error":{"message":"too many request bodies in flight; retry","type":"server_error"}}`
	if rec := zstdChat(engine, frame); rec.Code != http.StatusServiceUnavailable || rec.Body.String() != busy || *reached {
		t.Fatalf("without room to decode = %d %s (reached %t), want 503 %s", rec.Code, rec.Body, *reached, busy)
	}
	budget.Release(taken)
	if rec := zstdChat(engine, frame); rec.Code != http.StatusOK || !*reached {
		t.Fatalf("with the decode budget free = %d %s, want 200", rec.Code, rec.Body)
	}
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
		var m runtime.MemStats
		for {
			select {
			case <-stop:
				return
			case <-time.After(2 * time.Millisecond):
			}
			runtime.ReadMemStats(&m)
			if m.HeapInuse > peak.Load() {
				peak.Store(m.HeapInuse)
			}
		}
	}()

	var wg sync.WaitGroup
	codes := make([]int, parallel)
	for i := range parallel {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i] = zstdChatAs(engine, userKey(strconv.Itoa(i), 1), bomb).Code
		}()
	}
	wg.Wait()
	close(stop)
	<-sampled

	for i, code := range codes {
		if code != http.StatusRequestEntityTooLarge {
			t.Errorf("bomb %d = %d, want 413", i, code)
		}
	}
	const bound = 1 << 30
	grew := peak.Load() - min(peak.Load(), base.HeapInuse)
	t.Logf("%d parallel bombs grew the heap by %d MiB at peak", parallel, grew>>20)
	if grew > bound {
		t.Fatalf("%d parallel bombs grew the heap by %d MiB at peak, want at most %d MiB", parallel, grew>>20, bound>>20)
	}
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
	engine.POST("/v1/chat/completions", func(c *gin.Context) {
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
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rec := zstdChatAs(engine, userKey(strconv.Itoa(i), 1), frame); rec.Code != http.StatusOK {
				t.Errorf("held request = %d %s, want 200", rec.Code, rec.Body)
			}
		}()
		<-entered
	}
	runtime.GC()
	var holding runtime.MemStats
	runtime.ReadMemStats(&holding)
	if grew := holding.HeapInuse - min(holding.HeapInuse, base.HeapInuse); grew > uint64(budget) {
		t.Errorf("%d held bodies grew the heap by %d MiB, want at most the %d MiB budget", held, grew>>20, budget>>20)
	}

	const busy = `{"error":{"message":"too many request bodies in flight; retry","type":"server_error"}}`
	next := make(chan *httptest.ResponseRecorder, 1)
	go func() { next <- zstdChatAs(engine, userKey("next", 1), frame) }()
	select {
	case <-entered:
		close(proceed)
		wg.Wait()
		<-next
		t.Fatalf("with %d bodies held another encoded request reached its handler, want 503", held)
	case rec := <-next:
		if rec.Code != http.StatusServiceUnavailable || rec.Body.String() != busy {
			t.Fatalf("with %d bodies held = %d %s, want 503 %s", held, rec.Code, rec.Body, busy)
		}
	}

	close(proceed)
	wg.Wait()
	if !bodyBudget.TryAcquire(budget) {
		t.Fatal("after the held requests finished the budget is not whole again")
	}
	bodyBudget.Release(budget)
}
