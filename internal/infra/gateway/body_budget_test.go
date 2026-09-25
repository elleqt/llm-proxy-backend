package gateway

import (
	"bufio"
	"bytes"
	"context"
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

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/infra/gateway/faketest"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/semaphore"
)

// withBodyBudget runs the test with the process-wide body budget and wait
// replaced.
func withBodyBudget(t *testing.T, budget int64, wait time.Duration) *semaphore.Weighted {
	t.Helper()

	oldBudget, oldSize, oldWait := bodyBudget, bodyBudgetSize, bodyWait
	bodyBudget, bodyBudgetSize, bodyWait = semaphore.NewWeighted(budget), budget, wait

	t.Cleanup(func() { bodyBudget, bodyBudgetSize, bodyWait = oldBudget, oldSize, oldWait })

	return bodyBudget
}

const bodiesBusy = `{"error":{"message":"too many request bodies in flight; retry","type":"server_error"}}`

// userKey is a token of user: tokens of one user share its principal's
// user id, whatever follows the user.
func userKey(user string, token int) string {
	return "sk-user-" + user + "-" + strconv.Itoa(token)
}

// usersResolver admits gateSecret as gatePrincipal and every userKey as its
// user, all allowed chatgpt's models.
var usersResolver resolverFunc = func(ctx context.Context, secret string) (app.Principal, access.Policy, error) {
	rest, ok := strings.CutPrefix(secret, "sk-user-")
	if !ok {
		return staticResolver(gateSecret, gatePrincipal, "chatgpt:*")(ctx, secret)
	}

	user := rest[:strings.LastIndex(rest, "-")]

	return app.Principal{
		UserID:  uuid.NewSHA1(uuid.NameSpaceOID, []byte(user)),
		TokenID: uuid.NewSHA1(uuid.NameSpaceOID, []byte(secret)),
	}, mustPolicy("chatgpt:*"), nil
}

// heldEngine is a gated engine whose handlers signal entered with what they
// were given — the chat body, or the image edit's model once its form holds
// an image — then wait for proceed to be closed.
func heldEngine(entered chan<- []byte, proceed <-chan struct{}) *gin.Engine {
	catalog := fixedCatalog(map[string][]string{"gpt-5.6": {"chatgpt"}, "gpt-image-2": {"chatgpt"}})
	engine := gateEngine(usersResolver, catalog)
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
	return sendBodyAs(engine, gateSecret, path, contentType, body)
}

func sendBodyAs(engine *gin.Engine, key, path, contentType string, body io.Reader) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, body)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+key)

	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

	return rec
}

// TestOneUserHoldsAtMostItsShare: bodies held in long responses count
// against their user's quarter of the budget across all of the user's
// tokens, so a user holding it is answered 429 for the next body while
// another user is still served; once the user's requests finish they are
// admitted again, and no user is left on the books.
func TestOneUserHoldsAtMostItsShare(t *testing.T) {
	const size = 40 << 20
	// A quarter of it is maxJSONBody, so one body at the JSON limit fits.
	const budget = 4 * maxJSONBody
	withBodyBudget(t, budget, 50*time.Millisecond)

	chat, err := io.ReadAll(jsonBodyOf(size))
	require.NoError(t, err)

	entered, proceed := make(chan []byte, 4), make(chan struct{})
	engine := heldEngine(entered, proceed)

	var wg sync.WaitGroup

	hold := func(key string) {
		wg.Go(func() {
			rec := sendBodyAs(engine, key, "/v1/chat/completions", "application/json", bytes.NewReader(chat))
			assert.Equal(t, http.StatusOK, rec.Code, "held request of %s: %s", key, rec.Body)
		})

		<-entered
	}
	hold(userKey("a", 1))

	const (
		share  = `{"error":{"message":"too many large requests in flight for this account; retry","type":"rate_limit_error"}}`
		second = "a second body of a user holding its share, on another token"
	)

	rec := sendBodyAs(engine, userKey("a", 2), "/v1/chat/completions", "application/json", bytes.NewReader(chat))
	assert.Equal(t, http.StatusTooManyRequests, rec.Code, second)
	assert.JSONEq(t, share, rec.Body.String(), second)
	assert.Equal(t, "1", rec.Header().Get("Retry-After"), second)

	hold(userKey("b", 1))

	close(proceed)
	wg.Wait()

	rec = sendBodyAs(engine, userKey("a", 2), "/v1/chat/completions", "application/json", bytes.NewReader(chat))
	assert.Equal(t, http.StatusOK, rec.Code, "once its requests finished, the user's next body: %s", rec.Body)

	bodyShares.mu.Lock()
	left := len(bodyShares.held)
	bodyShares.mu.Unlock()

	assert.Zero(t, left, "users still on the books with nothing held")
	require.True(t, bodyBudget.TryAcquire(budget), "after every request finished the budget is not whole again")

	bodyBudget.Release(budget)
}

// TestUnencodedBodiesHoldTheBudgetUntilServed: identity-encoded bodies, JSON
// and multipart, are charged their own length until their handler returns,
// so large bodies waiting in slow handlers cannot pile up past the budget:
// three of them fill a budget of exactly their size, the next request is
// answered 503 without reaching its handler, and when they finish the whole
// budget is free again.
func TestUnencodedBodiesHoldTheBudgetUntilServed(t *testing.T) {
	const (
		size   = 8 << 20
		budget = 3 * size
	)
	withBodyBudget(t, budget, 50*time.Millisecond)

	chat, err := io.ReadAll(jsonBodyOf(size))
	require.NoError(t, err)

	form, formType := imageEditOf(t, "gpt-image-2", size)

	edit, err := io.ReadAll(form)
	require.NoError(t, err)

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
		wg.Go(func() {
			rec := sendBody(engine, sent.path, sent.contentType, bytes.NewReader(sent.body))
			assert.Equal(t, http.StatusOK, rec.Code, "held request to %s: %s", sent.path, rec.Body)
		})

		got := <-entered
		require.True(t, bytes.Equal(got, sent.want), "the handler of %s was given %d bytes, not what was sent", sent.path, len(got))
	}

	rec := sendBody(engine, "/v1/chat/completions", "application/json", bytes.NewReader(chat))
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code, "with the budget held")
	assert.JSONEq(t, bodiesBusy, rec.Body.String(), "with the budget held")

	close(proceed)
	wg.Wait()

	select {
	case <-entered:
		require.Fail(t, "a request reached its handler with the budget held")
	default:
	}

	require.True(t, bodyBudget.TryAcquire(budget), "after the held requests finished the budget is not whole again")

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
	require.NoError(t, err)

	entered, proceed := make(chan []byte, 2), make(chan struct{})
	engine := heldEngine(entered, proceed)

	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			rec := sendBody(engine, "/v1/images/edits", formType, bytes.NewReader(edit))
			assert.Equal(t, http.StatusOK, rec.Code, "edit: %s", rec.Body)
		})
	}

	for range 2 {
		require.Equal(t, "gpt-image-2", string(<-entered), "the model the edit's handler was given")
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
	const (
		idle   = 8
		budget = idle * maxJSONBody
	)
	withBodyBudget(t, budget, 50*time.Millisecond)

	engine, _ := gated(staticResolver(gateSecret, gatePrincipal, "chatgpt:*"), fixedCatalog(map[string][]string{"gpt-5.6": {"chatgpt"}}))

	reading, stop := make(chan struct{}), make(chan struct{})

	var wg sync.WaitGroup
	for i := range idle {
		wg.Go(func() {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/chat/completions", &idleBody{reading: reading, stop: stop})
			if i%2 == 0 {
				req.ContentLength = maxJSONBody
			}

			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+gateSecret)
			engine.ServeHTTP(httptest.NewRecorder(), req)
		})
	}

	for range idle {
		<-reading
	}

	const room = budget - idle*initialBodyBuffer
	if assert.True(t, bodyBudget.TryAcquire(room), "%d requests that sent nothing hold more than their initial buffers", idle) {
		bodyBudget.Release(room)
	}

	rec := sendBody(engine, "/v1/chat/completions", "application/json", jsonBodyOf(32<<20))
	assert.Equal(t, http.StatusOK, rec.Code, "beside %d idle senders a 32 MiB request: %s", idle, rec.Body)

	close(stop)
	wg.Wait()

	require.True(t, bodyBudget.TryAcquire(budget), "after the idle requests gave up the budget is not whole again")

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

	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", addr)
	require.NoError(t, err)

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
	wire := startOnTheWire(t, &faketest.Vendor{
		Payload: []byte(`{"id":"chatcmpl-1","object":"chat.completion","created":1,"model":"m",` +
			`"choices":[{"index":0,"message":{"role":"assistant","content":"late"},"finish_reason":"stop"}],` +
			`"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`),
		Latency: 3 * timeout,
	})
	addr := strings.TrimPrefix(wire.baseURL, "http://")
	chat := `{"model":"` + wire.alias + `","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}`

	conn, reader := rawConn(t, addr)
	_, err := io.WriteString(conn, requestHead("/v1/messages", wireSecret, 1<<20)+chat[:10])
	require.NoError(t, err)

	resp, err := http.ReadResponse(reader, nil)
	require.NoError(t, err, "stalled sender")

	body, _ := io.ReadAll(resp.Body)
	// Closed here, not deferred: resp is reused for the second exchange.
	_ = resp.Body.Close()

	const timedOut = `{"error":{"message":"request body not received in time","type":"invalid_request_error"}}`

	require.Equal(t, http.StatusRequestTimeout, resp.StatusCode, "stalled sender: %s", body)
	require.JSONEq(t, timedOut, string(body), "stalled sender")
	require.True(t, bodyBudget.TryAcquire(maxBodiesInFlight), "after the stalled sender was cut its charge is still held")

	bodyBudget.Release(maxBodiesInFlight)

	conn, reader = rawConn(t, addr)
	_, err = io.WriteString(conn, requestHead("/v1/messages", wireSecret, len(chat))+chat)
	require.NoError(t, err)

	resp, err = http.ReadResponse(reader, nil)
	require.NoError(t, err, "slow vendor")

	defer func() { _ = resp.Body.Close() }()

	body, _ = io.ReadAll(resp.Body)

	const late = "a vendor answering after the body's read deadline"
	require.Equal(t, http.StatusOK, resp.StatusCode, "%s: %s", late, body)
	require.Contains(t, string(body), "late", late)
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
		fixedCatalog(map[string][]string{"gemini-3-pro": {"chatgpt"}}), nil, nil))
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
	_, err := io.WriteString(conn, requestHead("/v1beta/models/gemini-3-pro:generateContent", gateSecret, 0))
	require.NoError(t, err)

	resp, err := http.ReadResponse(r, nil)
	require.NoError(t, err)

	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode, "a bodiless request outlasting the read deadline, want its request context live")
}

// TestBodyIsRefusedWithoutAReadDeadline: a body the gate cannot bound in
// time — the controller missing, or a writer offering no deadline — is
// refused with 500 before any of it is read, never read unbounded.
func TestBodyIsRefusedWithoutAReadDeadline(t *testing.T) {
	const failed = `{"error":{"message":"request body cannot be received","type":"server_error"}}`

	resolver := staticResolver(gateSecret, gatePrincipal, "chatgpt:*")
	catalog := fixedCatalog(map[string][]string{"gpt-5.6": {"chatgpt"}})
	withoutControl := gin.New()
	withoutControl.Use(policyGate(resolver, catalog, nil, nil))

	overRecorder := gin.New()
	overRecorder.Use(readDeadlineControl(), policyGate(resolver, catalog, nil, nil))

	for what, engine := range map[string]*gin.Engine{"no controller": withoutControl, "no deadline on the writer": overRecorder} {
		reached := false

		engine.POST("/v1/chat/completions", func(*gin.Context) { reached = true })

		rec := sendBody(engine, "/v1/chat/completions", "application/json", iotest.ErrReader(io.ErrUnexpectedEOF))
		assert.Equal(t, http.StatusInternalServerError, rec.Code, what)
		assert.JSONEq(t, failed, rec.Body.String(), what)
		assert.False(t, reached, what)
	}
}

// clearingListener hands out connections that report, on set, each non-zero
// read deadline put on them, so a test can clear it afterwards from outside the
// server, the way upstream's connection multiplexer does.
type clearingListener struct {
	net.Listener

	conns chan *clearingConn
}

func (l clearingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	c := &clearingConn{Conn: conn, set: make(chan struct{}, 1)}
	l.conns <- c

	return c, nil
}

type clearingConn struct {
	net.Conn

	set chan struct{}
}

func (c *clearingConn) SetReadDeadline(t time.Time) error {
	err := c.Conn.SetReadDeadline(t)
	if !t.IsZero() {
		select {
		case c.set <- struct{}{}:
		default:
		}
	}

	return err
}

// TestStalledSenderIsCutWhenTheTransportClearsTheDeadline: upstream's
// connection multiplexer hands a connection to the HTTP server and only then
// clears its own sniffing deadline (internal/api/protocol_multiplexer.go,
// routeMuxConnection). When that goroutine runs late, the clear lands after
// the gate has set the body's read deadline, while the gate is already
// blocked reading. The stalled sender must still be answered 408 in time,
// not kept until it gives up.
func TestStalledSenderIsCutWhenTheTransportClearsTheDeadline(t *testing.T) {
	const timeout = 200 * time.Millisecond
	withBodyReadTimeout(t, timeout)

	engine := gin.New()
	engine.Use(readDeadlineControl(), policyGate(staticResolver(gateSecret, gatePrincipal, "chatgpt:*"),
		fixedCatalog(map[string][]string{"gpt-5.6": {"chatgpt"}}), nil, nil))
	engine.POST("/v1/chat/completions", func(c *gin.Context) { c.Status(http.StatusOK) })

	inner, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)

	listener := clearingListener{Listener: inner, conns: make(chan *clearingConn, 1)}
	srv := &httptest.Server{Listener: listener, Config: &http.Server{Handler: engine}}
	srv.Start()
	t.Cleanup(srv.Close)

	conn, reader := rawConn(t, inner.Addr().String())
	_ = conn.SetDeadline(time.Now().Add(20 * timeout))

	chat := `{"model":"gpt-5.6","messages":[{"role":"user","content":"hi"}]}`
	_, err = io.WriteString(conn, requestHead("/v1/chat/completions", gateSecret, len(chat))+chat[:10])
	require.NoError(t, err)

	served := <-listener.conns
	select {
	case <-served.set:
	case <-time.After(10 * timeout):
		require.Fail(t, "the gate set no read deadline")
	}

	_ = served.Conn.SetReadDeadline(time.Time{})

	started := time.Now()

	resp, err := http.ReadResponse(reader, nil)
	require.NoError(t, err, "stalled sender after the transport cleared the deadline")

	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)

	const timedOut = `{"error":{"message":"request body not received in time","type":"invalid_request_error"}}`

	require.Equal(t, http.StatusRequestTimeout, resp.StatusCode, "stalled sender: %s", body)
	require.JSONEq(t, timedOut, string(body), "stalled sender")
	require.LessOrEqual(t, time.Since(started), 5*timeout, "408 came too long after the clear, want about %v", timeout)
}
