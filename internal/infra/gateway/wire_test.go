package gateway

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cliproxyconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"

	"github.com/elleqt/llm-proxy-backend/internal/infra/gateway/faketest"
)

const vendorKey = "vendor-upstream-key"

// wireSeq keeps the names of several gateways in one test apart.
var wireSeq atomic.Int64

// onTheWire is a running gateway whose only vendor is v, reachable under alias.
type onTheWire struct {
	*running
	vendor *faketest.Vendor
	alias  string
	model  string
}

// startOnTheWire boots a gateway whose configuration declares v as an
// openai-compatibility provider. Access is by user token: the gateway admits
// wireSecret unless the caller's Params carry another Resolver.
//
// The entry is in the boot configuration, not a pushed one, for two reasons
// verified against upstream v7.3.15:
//   - upstream synthesises credentials from configuration on Run and on its own
//     file watcher's reload, never on the reload callback PushConfig drives
//     (sdk/cliproxy/service_config.go: applyWatcherConfigUpdate passes
//     synthesizeConfigAuths=false). A pushed-only entry answers 400 "unknown
//     provider for model".
//   - once config-derived credentials exist, Run keeps registering their models
//     after the watcher is created (service_lifecycle.go syncPluginModelRuntime),
//     reading s.cfg without cfgMu (service_models.go registerModelsForAuthWithCache),
//     so a push straight after WaitReload is a data race inside upstream.
func startOnTheWire(t *testing.T, v *faketest.Vendor) *onTheWire {
	t.Helper()
	return startOnTheWireWith(t, v, Params{Config: &cliproxyconfig.Config{}})
}

// startOnTheWireWith is startOnTheWire over caller-built Params, whose Config
// gains the vendor entry.
func startOnTheWireWith(t *testing.T, v *faketest.Vendor, p Params) *onTheWire {
	t.Helper()
	srv := faketest.Start(t, v)
	// Per-gateway names keep the process-global model registry from routing a
	// test to a vendor an earlier gateway declared.
	name := strings.ToLower(t.Name()) + "-" + strconv.FormatInt(wireSeq.Add(1), 10)
	alias := "alias-" + name
	model := "upstream-" + name

	p.Config.OpenAICompatibility = []cliproxyconfig.OpenAICompatibility{
		faketest.Compatibility("fakevendor", srv.URL, vendorKey, model, alias),
	}
	w := &onTheWire{running: startWith(t, p), vendor: v, alias: alias, model: model}
	// Upstream registers configured models after it starts serving
	// (service_lifecycle.go syncPluginModelRuntime); until then the gate
	// rightly refuses the model as served by no provider.
	awaitProviders(t, w.gateway.catalog, alias, []string{"fakevendor"})
	return w
}

// productionParams builds Params the way the production entry point does: the
// core auth manager, its token store and cooldown store come from
// NewCoreAuthManager over the same auth directory the configuration names.
func productionParams(t *testing.T) Params {
	t.Helper()
	return productionParamsIn(t.TempDir())
}

// productionParamsIn is productionParams over an existing auth directory, for
// a gateway that restarts on what an earlier one persisted.
func productionParamsIn(authDir string) Params {
	cfg := &cliproxyconfig.Config{AuthDir: authDir}
	manager, store, cooldown := NewCoreAuthManager(cfg)
	return Params{
		Config:   cfg,
		CoreAuth: manager,
		Store:    store,
		Cooldown: cooldown,
	}
}

// postMessages sends an Anthropic Messages request, so that reaching an
// OpenAI-compatible vendor requires upstream to translate both ways.
func (w *onTheWire) postMessages(t *testing.T, key string, stream bool) (*http.Response, []byte) {
	t.Helper()
	resp := w.sendMessages(t, key, stream)
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp, out
}

// sendMessages is postMessages leaving the body unread; the caller closes it.
func (w *onTheWire) sendMessages(t *testing.T, key string, stream bool) *http.Response {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"model":      w.alias,
		"max_tokens": 64,
		"stream":     stream,
		"messages":   []map[string]any{{"role": "user", "content": "say hello"}},
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, w.baseURL+"/v1/messages", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /v1/messages: %v", err)
	}
	return resp
}

// assertTranslatedUpstreamRequest checks the one request the vendor saw is an
// OpenAI chat completion for the upstream model name, carrying the vendor key
// rather than the client's.
func (w *onTheWire) assertTranslatedUpstreamRequest(t *testing.T, stream bool) {
	t.Helper()
	reqs := w.vendor.Requests()
	if len(reqs) != 1 {
		t.Fatalf("vendor received %d requests, want 1", len(reqs))
	}
	got := reqs[0]
	if got.Method != http.MethodPost || got.Path != "/chat/completions" {
		t.Fatalf("vendor received %s %s, want POST /chat/completions", got.Method, got.Path)
	}
	if auth := got.Header.Get("Authorization"); auth != "Bearer "+vendorKey {
		t.Fatalf("vendor Authorization = %q, want the configured vendor key", auth)
	}
	var body struct {
		Model    string `json:"model"`
		Stream   bool   `json:"stream"`
		Messages []struct {
			Role    string `json:"role"`
			Content any    `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(got.Body, &body); err != nil {
		t.Fatalf("vendor body %s is not JSON: %v", got.Body, err)
	}
	if body.Model != w.model {
		t.Fatalf("vendor model = %q, want the upstream name %q for alias %q", body.Model, w.model, w.alias)
	}
	if body.Stream != stream {
		t.Fatalf("vendor stream = %t, want %t", body.Stream, stream)
	}
	if len(body.Messages) != 1 || body.Messages[0].Role != "user" || !strings.Contains(string(got.Body), "say hello") {
		t.Fatalf("vendor messages = %s, want the one user message", got.Body)
	}
}

func TestRequestReachesVendorAndReturnsTranslated(t *testing.T) {
	const latency = 50 * time.Millisecond
	w := startOnTheWire(t, &faketest.Vendor{
		Payload: []byte(`{"id":"chatcmpl-1","object":"chat.completion","created":1,"model":"m",` +
			`"choices":[{"index":0,"message":{"role":"assistant","content":"hello from the vendor"},"finish_reason":"stop"}],` +
			`"usage":{"prompt_tokens":3,"completion_tokens":4,"total_tokens":7}}`),
		Latency: latency,
	})

	// Access control is on the path: without a token nothing reaches the vendor.
	if resp, body := w.postMessages(t, "", false); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated POST /v1/messages = %d (%s), want %d", resp.StatusCode, body, http.StatusUnauthorized)
	}
	if n := len(w.vendor.Requests()); n != 0 {
		t.Fatalf("vendor received %d requests from an unauthenticated client", n)
	}

	began := time.Now()
	resp, body := w.postMessages(t, wireSecret, false)
	elapsed := time.Since(began)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /v1/messages = %d (%s), want 200", resp.StatusCode, body)
	}
	if elapsed < latency {
		t.Fatalf("response took %s, want at least the vendor latency %s", elapsed, latency)
	}
	w.assertTranslatedUpstreamRequest(t, false)

	var msg struct {
		Type    string `json:"type"`
		Role    string `json:"role"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		StopReason string `json:"stop_reason"`
		Usage      struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &msg); err != nil {
		t.Fatalf("response %s is not JSON: %v", body, err)
	}
	if msg.Type != "message" || msg.Role != "assistant" || len(msg.Content) != 1 ||
		msg.Content[0].Type != "text" || msg.Content[0].Text != "hello from the vendor" {
		t.Fatalf("response = %s, want an Anthropic message carrying the vendor's text", body)
	}
	if msg.StopReason != "end_turn" || msg.Usage.InputTokens != 3 || msg.Usage.OutputTokens != 4 {
		t.Fatalf("response = %s, want stop_reason end_turn and the vendor's usage translated", body)
	}
}

// streamChunk is an OpenAI chat.completion.chunk carrying delta, and finish
// as its finish_reason when non-empty.
func streamChunk(delta, finish string) []byte {
	finishJSON := "null"
	if finish != "" {
		finishJSON = `"` + finish + `"`
	}
	return []byte(`{"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"m",` +
		`"choices":[{"index":0,"delta":{"content":"` + delta + `"},"finish_reason":` + finishJSON + `}]}`)
}

func TestStreamingRequestReachesVendorAndReturnsTranslated(t *testing.T) {
	w := startOnTheWire(t, &faketest.Vendor{
		Chunks:  [][]byte{streamChunk("first ", ""), streamChunk("second ", ""), streamChunk("third", ""), streamChunk("", "stop")},
		Latency: time.Millisecond,
	})

	resp, body := w.postMessages(t, wireSecret, true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /v1/messages stream = %d (%s), want 200", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}
	w.assertTranslatedUpstreamRequest(t, true)

	events, texts := anthropicEvents(t, body)
	if want := []string{"first ", "second ", "third"}; strings.Join(texts, "|") != strings.Join(want, "|") {
		t.Fatalf("text deltas = %q, want %q in order; events %q", texts, want, events)
	}
	if len(events) == 0 || events[0] != "message_start" || events[len(events)-1] != "message_stop" {
		t.Fatalf("events = %q, want an Anthropic stream from message_start to message_stop", events)
	}
}

func TestVendorFailureReachesTheClient(t *testing.T) {
	w := startOnTheWire(t, &faketest.Vendor{
		FailStatus: http.StatusBadRequest,
		FailBody:   []byte(`{"error":{"message":"vendor refused the prompt","type":"invalid_request_error"}}`),
	})

	resp, body := w.postMessages(t, wireSecret, false)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /v1/messages = %d (%s), want the vendor's %d", resp.StatusCode, body, http.StatusBadRequest)
	}
	if !strings.Contains(string(body), "vendor refused the prompt") {
		t.Fatalf("response %s does not carry the vendor's error", body)
	}
}

func TestVendorDyingMidStreamTruncatesTheClientStream(t *testing.T) {
	w := startOnTheWire(t, &faketest.Vendor{
		Chunks: [][]byte{[]byte(`{"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"m",` +
			`"choices":[{"index":0,"delta":{"content":"partial"},"finish_reason":null}]}`)},
		DieMidStream: true,
	})

	_, body := w.postMessages(t, wireSecret, true)
	events, texts := anthropicEvents(t, body)
	if len(texts) != 1 || texts[0] != "partial" {
		t.Fatalf("text deltas = %q, want the one chunk sent before the vendor died; events %q", texts, events)
	}
	for _, e := range events {
		if e == "message_stop" {
			t.Fatalf("events = %q: the stream completed normally although the vendor died", events)
		}
	}
}

// TestRequestThroughProductionWiringReachesVendor sends a request through a
// gateway built exactly as production builds it — NewCoreAuthManager over the
// configured auth directory, passed with its cooldown store — so the manager on
// the request path is the one production hands in, not upstream's default.
func TestRequestThroughProductionWiringReachesVendor(t *testing.T) {
	p := productionParams(t)
	w := startOnTheWireWith(t, &faketest.Vendor{
		Payload: []byte(`{"id":"chatcmpl-1","object":"chat.completion","created":1,"model":"m",` +
			`"choices":[{"index":0,"message":{"role":"assistant","content":"hello through production wiring"},"finish_reason":"stop"}],` +
			`"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}`),
	}, p)

	resp, body := w.postMessages(t, wireSecret, false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /v1/messages = %d (%s), want 200", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "hello through production wiring") {
		t.Fatalf("response %s does not carry the vendor's text", body)
	}
	w.assertTranslatedUpstreamRequest(t, false)

	// The request was served by a credential of the supplied manager: upstream
	// records the result on the auth it selected.
	deadline := time.Now().Add(5 * time.Second)
	for {
		var served int64
		for _, a := range p.CoreAuth.List() {
			served += a.Success
		}
		if served == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the supplied manager recorded %d successful requests, want 1: another manager served it", served)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestStreamingIsFlushedAsTheVendorSends proves the client receives the first
// event while the vendor is still streaming, not once the whole response is
// buffered: with a gap between vendor chunks, the first text delta must reach
// the client before the vendor has begun its last chunk.
func TestStreamingIsFlushedAsTheVendorSends(t *testing.T) {
	const gap = 300 * time.Millisecond
	chunks := [][]byte{streamChunk("first ", ""), streamChunk("second ", ""), streamChunk("third", ""), streamChunk("", "stop")}
	w := startOnTheWire(t, &faketest.Vendor{Chunks: chunks, Latency: gap})

	began := time.Now()
	resp := w.sendMessages(t, wireSecret, true)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /v1/messages stream = %d, want 200", resp.StatusCode)
	}

	reader := bufio.NewReader(resp.Body)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("stream ended before any text delta: %v", err)
		}
		if !strings.Contains(line, `"text_delta"`) {
			continue
		}
		started := w.vendor.ChunksStarted()
		if started >= len(chunks) {
			t.Fatalf("first text delta arrived after %s, once the vendor had begun all %d chunks: the stream is buffered, not flushed", time.Since(began), started)
		}
		t.Logf("first text delta after %s, with %d of %d vendor chunks begun", time.Since(began), started, len(chunks))
		break
	}
	// Drain, so the stream is shown to complete as well.
	rest, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read rest of stream: %v", err)
	}
	if !strings.Contains(string(rest), "message_stop") {
		t.Fatalf("stream did not complete: %s", rest)
	}
}

// anthropicEvents returns the event names of an Anthropic SSE stream and the
// text of its text_delta events, both in order.
func anthropicEvents(t *testing.T, body []byte) (events, texts []string) {
	t.Helper()
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	for scanner.Scan() {
		line := scanner.Text()
		if name, ok := strings.CutPrefix(line, "event: "); ok {
			events = append(events, name)
			continue
		}
		data, ok := strings.CutPrefix(line, "data: ")
		if !ok {
			continue
		}
		var ev struct {
			Type  string `json:"type"`
			Delta struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"delta"`
		}
		if json.Unmarshal([]byte(data), &ev) == nil && ev.Type == "content_block_delta" && ev.Delta.Type == "text_delta" {
			texts = append(texts, ev.Delta.Text)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan stream: %v", err)
	}
	return events, texts
}

// TestBootRoutingStrategyPicksTheCredential: the boot configuration's routing
// strategy decides which credential serves a request from the first one, with
// the core auth manager production supplies — upstream's builder would pick
// the selector only for a manager it built itself. One vendor, two keys:
// fill-first sends every request with the same key; round-robin, the default,
// uses both.
func TestBootRoutingStrategyPicksTheCredential(t *testing.T) {
	for _, c := range []struct {
		strategy string
		keys     int
	}{
		{"fill-first", 1},
		{"", 2},
	} {
		t.Run("strategy="+c.strategy, func(t *testing.T) {
			v := &faketest.Vendor{Payload: []byte(`{"id":"chatcmpl-1","object":"chat.completion","created":1,"model":"m",` +
				`"choices":[{"index":0,"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}],` +
				`"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)}
			srv := faketest.Start(t, v)
			name := "routing-" + strconv.FormatInt(wireSeq.Add(1), 10)
			entry := faketest.Compatibility("fakevendor", srv.URL, "vendor-key-1", "upstream-"+name, "alias-"+name)
			entry.APIKeyEntries = append(entry.APIKeyEntries, cliproxyconfig.OpenAICompatibilityAPIKey{APIKey: "vendor-key-2"})
			cfg := &cliproxyconfig.Config{AuthDir: t.TempDir(), OpenAICompatibility: []cliproxyconfig.OpenAICompatibility{entry}}
			cfg.Routing.Strategy = c.strategy
			manager, store, cooldown := NewCoreAuthManager(cfg)
			w := &onTheWire{
				running: startWith(t, Params{Config: cfg, CoreAuth: manager, Store: store, Cooldown: cooldown}),
				vendor:  v, alias: "alias-" + name, model: "upstream-" + name,
			}
			awaitProviders(t, w.gateway.catalog, w.alias, []string{"fakevendor"})

			for range 4 {
				if resp, body := w.postMessages(t, wireSecret, false); resp.StatusCode != http.StatusOK {
					t.Fatalf("POST /v1/messages = %d (%s), want 200", resp.StatusCode, body)
				}
			}
			keys := map[string]bool{}
			for _, r := range v.Requests() {
				keys[r.Header.Get("Authorization")] = true
			}
			if len(keys) != c.keys {
				t.Fatalf("4 requests reached the vendor with keys %v, want %d distinct", keys, c.keys)
			}
		})
	}
}
