package gateway

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/sync/semaphore"

	"github.com/elleqt/llm-proxy-backend/internal/infra/gateway/faketest"
)

// withBodyBudget runs the test with the process-wide body budget and wait
// replaced.
func withBodyBudget(t *testing.T, budget int64, wait time.Duration) *semaphore.Weighted {
	t.Helper()
	oldBudget, oldWait := bodyBudget, bodyWait
	bodyBudget, bodyWait = semaphore.NewWeighted(budget), wait
	t.Cleanup(func() { bodyBudget, bodyWait = oldBudget, oldWait })
	return bodyBudget
}

const bodiesBusy = `{"error":{"message":"too many request bodies in flight; retry","type":"server_error"}}`

// heldEngine is a gated engine whose handlers signal entered with what they
// were given — the chat body, or the image edit's model once its form holds
// an image — then wait for proceed to be closed.
func heldEngine(entered chan<- []byte, proceed <-chan struct{}) *gin.Engine {
	catalog := fixedCatalog(map[string][]string{"gpt-5.6": {"chatgpt"}, "gpt-image-2": {"chatgpt"}})
	engine := gateEngine(staticResolver(gateSecret, gatePrincipal, "chatgpt:*"), catalog)
	engine.POST("/v1/chat/completions", func(c *gin.Context) {
		raw, _ := io.ReadAll(c.Request.Body)
		entered <- raw
		<-proceed
	})
	engine.POST("/v1/images/edits", func(c *gin.Context) {
		var got []byte
		if form, err := c.MultipartForm(); err == nil && len(form.File["image"]) == 1 && form.File["image"][0].Size > 0 {
			got = []byte(c.PostForm("model"))
		}
		entered <- got
		<-proceed
	})
	return engine
}

func sendBody(engine *gin.Engine, path, contentType string, body io.Reader) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, body)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+gateSecret)
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	return rec
}

// TestUnencodedBodiesHoldTheBudgetUntilServed: identity-encoded bodies, JSON
// and multipart, are charged their own length until their handler returns,
// so large bodies waiting in slow handlers cannot pile up past the budget:
// three of them fill a budget of exactly their size, the next request is
// answered 503 without reaching its handler, and when they finish the whole
// budget is free again.
func TestUnencodedBodiesHoldTheBudgetUntilServed(t *testing.T) {
	const size = 8 << 20
	const budget = 3 * size
	withBodyBudget(t, budget, 50*time.Millisecond)
	chat, err := io.ReadAll(jsonBodyOf("gpt-5.6", size))
	if err != nil {
		t.Fatal(err)
	}
	form, formType := imageEditOf(t, "gpt-image-2", size)
	edit, err := io.ReadAll(form)
	if err != nil {
		t.Fatal(err)
	}
	entered, proceed := make(chan []byte, 4), make(chan struct{})
	engine := heldEngine(entered, proceed)

	var wg sync.WaitGroup
	for _, sent := range []struct {
		path, contentType string
		body, want        []byte
	}{
		{"/v1/chat/completions", "application/json", chat, chat},
		{"/v1/chat/completions", "application/json", chat, chat},
		{"/v1/images/edits", formType, edit, []byte("gpt-image-2")},
	} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rec := sendBody(engine, sent.path, sent.contentType, bytes.NewReader(sent.body)); rec.Code != http.StatusOK {
				t.Errorf("held request to %s = %d %s, want 200", sent.path, rec.Code, rec.Body)
			}
		}()
		if got := <-entered; !bytes.Equal(got, sent.want) {
			t.Fatalf("the handler of %s was given %d bytes, not what was sent", sent.path, len(got))
		}
	}

	if rec := sendBody(engine, "/v1/chat/completions", "application/json", bytes.NewReader(chat)); rec.Code != http.StatusServiceUnavailable || rec.Body.String() != bodiesBusy {
		t.Errorf("with the budget held = %d %s, want 503 %s", rec.Code, rec.Body, bodiesBusy)
	}
	close(proceed)
	wg.Wait()
	select {
	case <-entered:
		t.Fatal("a request reached its handler with the budget held")
	default:
	}
	if !bodyBudget.TryAcquire(budget) {
		t.Fatal("after the held requests finished the budget is not whole again")
	}
	bodyBudget.Release(budget)
}

// TestTwoEditsAtTheLimitFitTwiceTheLimit: bodies of a declared length are
// never charged more than it, even while their buffers grow at once, so two
// multipart edits sent together fill a budget of twice their size and are
// both served — as two edits at the 256 MiB limit fit the real one.
func TestTwoEditsAtTheLimitFitTwiceTheLimit(t *testing.T) {
	const size = 8 << 20
	withBodyBudget(t, 2*size, 50*time.Millisecond)
	form, formType := imageEditOf(t, "gpt-image-2", size)
	edit, err := io.ReadAll(form)
	if err != nil {
		t.Fatal(err)
	}
	entered, proceed := make(chan []byte, 2), make(chan struct{})
	engine := heldEngine(entered, proceed)

	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rec := sendBody(engine, "/v1/images/edits", formType, bytes.NewReader(edit)); rec.Code != http.StatusOK {
				t.Errorf("edit = %d %s, want 200", rec.Code, rec.Body)
			}
		}()
	}
	for range 2 {
		if got := string(<-entered); got != "gpt-image-2" {
			t.Fatalf("the edit's handler was given model %q, want gpt-image-2", got)
		}
	}
	close(proceed)
	wg.Wait()
}

// idleBody is a request body that sends nothing: its first Read signals
// reading, then every Read blocks until stop is closed and fails.
type idleBody struct {
	once    sync.Once
	reading chan<- struct{}
	stop    <-chan struct{}
}

func (b *idleBody) Read([]byte) (int, error) {
	b.once.Do(func() { b.reading <- struct{}{} })
	<-b.stop
	return 0, io.ErrUnexpectedEOF
}

// TestDeclaredLengthsReserveNoBudget: bodies are charged as they arrive, not
// as declared, so eight requests declaring (or streaming towards) the JSON
// limit that send nothing hold next to nothing, and a normal request is
// still served beside them; once they give up the budget is whole again.
func TestDeclaredLengthsReserveNoBudget(t *testing.T) {
	const idle = 8
	const budget = idle * maxJSONBody
	withBodyBudget(t, budget, 50*time.Millisecond)
	engine, _ := gated(staticResolver(gateSecret, gatePrincipal, "chatgpt:*"), fixedCatalog(map[string][]string{"gpt-5.6": {"chatgpt"}}))

	reading, stop := make(chan struct{}), make(chan struct{})
	var wg sync.WaitGroup
	for i := range idle {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", &idleBody{reading: reading, stop: stop})
			if i%2 == 0 {
				req.ContentLength = maxJSONBody
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+gateSecret)
			engine.ServeHTTP(httptest.NewRecorder(), req)
		}()
	}
	for range idle {
		<-reading
	}

	const room = budget - idle*initialBodyBuffer
	if !bodyBudget.TryAcquire(room) {
		t.Errorf("%d requests that sent nothing hold more than their initial buffers", idle)
	} else {
		bodyBudget.Release(room)
	}
	if rec := sendBody(engine, "/v1/chat/completions", "application/json", jsonBodyOf("gpt-5.6", 32<<20)); rec.Code != http.StatusOK {
		t.Errorf("beside %d idle senders a 32 MiB request = %d %s, want 200", idle, rec.Code, rec.Body)
	}
	close(stop)
	wg.Wait()
	if !bodyBudget.TryAcquire(budget) {
		t.Fatal("after the idle requests gave up the budget is not whole again")
	}
	bodyBudget.Release(budget)
}

// withBodyReadTimeout runs the test with bodyReadTimeout replaced.
func withBodyReadTimeout(t *testing.T, timeout time.Duration) {
	t.Helper()
	old := bodyReadTimeout
	bodyReadTimeout = timeout
	t.Cleanup(func() { bodyReadTimeout = old })
}

// rawConn dials addr for a hand-written HTTP/1.1 exchange.
func rawConn(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	// A deadline that never fires must fail the test, not hang it.
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	return conn, bufio.NewReader(conn)
}

// requestHead is the head of a POST to path with key, declaring length.
func requestHead(path, key string, length int) string {
	return "POST " + path + " HTTP/1.1\r\nHost: gate\r\nContent-Type: application/json\r\n" +
		"Authorization: Bearer " + key + "\r\nContent-Length: " + strconv.Itoa(length) + "\r\n\r\n"
}

// TestStalledSenderIsCutByTheReadDeadline drives the real engine, with
// upstream's middleware (which wraps the response writer) on the path: a
// sender that stops mid-body is answered 408 once bodyReadTimeout passes and
// its charge is released. A vendor answering after the deadline, once the
// body has arrived, is still served: the request context stays live.
func TestStalledSenderIsCutByTheReadDeadline(t *testing.T) {
	const timeout = 300 * time.Millisecond
	withBodyBudget(t, maxBodiesInFlight, 50*time.Millisecond)
	withBodyReadTimeout(t, timeout)
	w := startOnTheWire(t, &faketest.Vendor{
		Payload: []byte(`{"id":"chatcmpl-1","object":"chat.completion","created":1,"model":"m",` +
			`"choices":[{"index":0,"message":{"role":"assistant","content":"late"},"finish_reason":"stop"}],` +
			`"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`),
		Latency: 3 * timeout,
	})
	addr := strings.TrimPrefix(w.baseURL, "http://")
	chat := `{"model":"` + w.alias + `","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}`

	conn, r := rawConn(t, addr)
	if _, err := io.WriteString(conn, requestHead("/v1/messages", wireSecret, 1<<20)+chat[:10]); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		t.Fatalf("stalled sender: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	const timedOut = `{"error":{"message":"request body not received in time","type":"invalid_request_error"}}`
	if resp.StatusCode != http.StatusRequestTimeout || string(body) != timedOut {
		t.Fatalf("stalled sender = %d %s, want 408 %s", resp.StatusCode, body, timedOut)
	}
	if !bodyBudget.TryAcquire(maxBodiesInFlight) {
		t.Fatal("after the stalled sender was cut its charge is still held")
	}
	bodyBudget.Release(maxBodiesInFlight)

	conn, r = rawConn(t, addr)
	if _, err := io.WriteString(conn, requestHead("/v1/messages", wireSecret, len(chat))+chat); err != nil {
		t.Fatal(err)
	}
	resp, err = http.ReadResponse(r, nil)
	if err != nil {
		t.Fatalf("slow vendor: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "late") {
		t.Fatalf("a vendor answering after the body's read deadline = %d %s, want 200 with its answer", resp.StatusCode, body)
	}
}

// TestBodilessRequestGetsNoReadDeadline: a model request without a body sets
// no deadline — the server is already reading its connection in the
// background, and a deadline there would cancel the request — so a handler
// outlasting bodyReadTimeout keeps a live request context.
func TestBodilessRequestGetsNoReadDeadline(t *testing.T) {
	const timeout = 200 * time.Millisecond
	withBodyReadTimeout(t, timeout)
	engine := gin.New()
	engine.Use(readDeadlineControl(), policyGate(staticResolver(gateSecret, gatePrincipal, "chatgpt:*"),
		fixedCatalog(map[string][]string{"gemini-3-pro": {"chatgpt"}}), nil))
	engine.POST("/v1beta/models/*action", func(c *gin.Context) {
		select {
		case <-c.Request.Context().Done():
			c.Status(http.StatusGone)
		case <-time.After(3 * timeout):
			c.Status(http.StatusOK)
		}
	})
	srv := httptest.NewServer(engine)
	t.Cleanup(srv.Close)

	conn, r := rawConn(t, srv.Listener.Addr().String())
	if _, err := io.WriteString(conn, requestHead("/v1beta/models/gemini-3-pro:generateContent", gateSecret, 0)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("a bodiless request outlasting the read deadline = %d, want 200 with its request context live", resp.StatusCode)
	}
}

// TestBodyIsRefusedWithoutAReadDeadline: a body the gate cannot bound in
// time — the controller missing, or a writer offering no deadline — is
// refused with 500 before any of it is read, never read unbounded.
func TestBodyIsRefusedWithoutAReadDeadline(t *testing.T) {
	const failed = `{"error":{"message":"request body cannot be received","type":"server_error"}}`
	resolver := staticResolver(gateSecret, gatePrincipal, "chatgpt:*")
	catalog := fixedCatalog(map[string][]string{"gpt-5.6": {"chatgpt"}})
	withoutControl := gin.New()
	withoutControl.Use(policyGate(resolver, catalog, nil))
	overRecorder := gin.New()
	overRecorder.Use(readDeadlineControl(), policyGate(resolver, catalog, nil))
	for what, engine := range map[string]*gin.Engine{"no controller": withoutControl, "no deadline on the writer": overRecorder} {
		reached := false
		engine.POST("/v1/chat/completions", func(*gin.Context) { reached = true })
		rec := sendBody(engine, "/v1/chat/completions", "application/json", iotest.ErrReader(io.ErrUnexpectedEOF))
		if rec.Code != http.StatusInternalServerError || rec.Body.String() != failed || reached {
			t.Errorf("%s = %d %s (reached %t), want 500 %s", what, rec.Code, rec.Body, reached, failed)
		}
	}
}
