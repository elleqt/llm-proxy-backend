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

	"github.com/elleqt/llm-proxy-backend/internal/infra/gateway/faketest"
	cliproxyconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	"github.com/stretchr/testify/require"
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
// verified against upstream v7.3.18:
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
func startOnTheWireWith(t *testing.T, vendor *faketest.Vendor, params Params) *onTheWire {
	t.Helper()
	srv := faketest.Start(t, vendor)
	// Per-gateway names keep the process-global model registry from routing a
	// test to a vendor an earlier gateway declared.
	name := strings.ToLower(t.Name()) + "-" + strconv.FormatInt(wireSeq.Add(1), 10)
	alias := "alias-" + name
	model := "upstream-" + name

	params.Config.OpenAICompatibility = []cliproxyconfig.OpenAICompatibility{
		faketest.Compatibility("fakevendor", srv.URL, vendorKey, model, alias),
	}
	wire := &onTheWire{running: startWith(t, params), vendor: vendor, alias: alias, model: model}
	// Upstream registers configured models after it starts serving
	// (service_lifecycle.go syncPluginModelRuntime); until then the gate
	// rightly refuses the model as served by no provider.
	awaitProviders(t, wire.gateway.catalog, alias, []string{"fakevendor"})

	return wire
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
// OpenAI-compatible vendor requires upstream to translate both ways. It
// returns the response status, headers and body, the body read and closed.
func (w *onTheWire) postMessages(t *testing.T, key string, stream bool) (int, http.Header, []byte) {
	t.Helper()

	resp := w.sendMessages(t, key, stream)
	defer func() { _ = resp.Body.Close() }()

	out, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "read response")

	return resp.StatusCode, resp.Header, out
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
	require.NoError(t, err, "marshal request")

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, w.baseURL+"/v1/messages", strings.NewReader(string(body)))
	require.NoError(t, err, "build request")

	req.Header.Set("Content-Type", "application/json")

	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err, "POST /v1/messages")

	return resp
}

// assertTranslatedUpstreamRequest checks the one request the vendor saw is an
// OpenAI chat completion for the upstream model name, carrying the vendor key
// rather than the client's.
func (w *onTheWire) assertTranslatedUpstreamRequest(t *testing.T, stream bool) {
	t.Helper()

	reqs := w.vendor.Requests()
	require.Len(t, reqs, 1, "vendor requests")

	got := reqs[0]
	require.Equal(t, http.MethodPost, got.Method, "vendor request method")
	require.Equal(t, "/chat/completions", got.Path, "vendor request path")
	require.Equal(t, "Bearer "+vendorKey, got.Header.Get("Authorization"), "vendor Authorization, want the configured vendor key")

	var body struct {
		Model    string `json:"model"`
		Stream   bool   `json:"stream"`
		Messages []struct {
			Role    string `json:"role"`
			Content any    `json:"content"`
		} `json:"messages"`
	}
	require.NoError(t, json.Unmarshal(got.Body, &body), "vendor body %s is not JSON", got.Body)

	require.Equal(t, w.model, body.Model, "vendor model, want the upstream name for alias %q", w.alias)
	require.Equal(t, stream, body.Stream, "vendor stream")

	require.Len(t, body.Messages, 1, "vendor messages = %s, want the one user message", got.Body)
	require.Equal(t, "user", body.Messages[0].Role, "vendor message role")
	require.Contains(t, string(got.Body), "say hello", "vendor messages, want the one user message")
}

func TestRequestReachesVendorAndReturnsTranslated(t *testing.T) {
	const latency = 50 * time.Millisecond

	wire := startOnTheWire(t, &faketest.Vendor{
		Payload: []byte(`{"id":"chatcmpl-1","object":"chat.completion","created":1,"model":"m",` +
			`"choices":[{"index":0,"message":{"role":"assistant","content":"hello from the vendor"},"finish_reason":"stop"}],` +
			`"usage":{"prompt_tokens":3,"completion_tokens":4,"total_tokens":7}}`),
		Latency: latency,
	})

	// Access control is on the path: without a token nothing reaches the vendor.
	status, _, body := wire.postMessages(t, "", false)
	require.Equal(t, http.StatusUnauthorized, status, "unauthenticated POST /v1/messages (%s)", body)

	require.Empty(t, wire.vendor.Requests(), "vendor received requests from an unauthenticated client")

	began := time.Now()
	status, _, body = wire.postMessages(t, wireSecret, false)
	elapsed := time.Since(began)

	require.Equal(t, http.StatusOK, status, "POST /v1/messages (%s)", body)
	require.GreaterOrEqual(t, elapsed, latency, "response took less than the vendor latency")

	wire.assertTranslatedUpstreamRequest(t, false)

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
	require.NoError(t, json.Unmarshal(body, &msg), "response %s is not JSON", body)

	require.Equal(t, "message", msg.Type, "response = %s", body)
	require.Equal(t, "assistant", msg.Role, "response = %s", body)
	require.Len(t, msg.Content, 1, "response = %s", body)
	require.Equal(t, "text", msg.Content[0].Type, "response = %s", body)
	require.Equal(t, "hello from the vendor", msg.Content[0].Text, "response = %s, want the vendor's text", body)

	require.Equal(t, "end_turn", msg.StopReason, "response = %s", body)
	require.Equal(t, 3, msg.Usage.InputTokens, "response = %s, want the vendor's usage translated", body)
	require.Equal(t, 4, msg.Usage.OutputTokens, "response = %s, want the vendor's usage translated", body)
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
	wire := startOnTheWire(t, &faketest.Vendor{
		Chunks:  [][]byte{streamChunk("first ", ""), streamChunk("second ", ""), streamChunk("third", ""), streamChunk("", "stop")},
		Latency: time.Millisecond,
	})

	status, header, body := wire.postMessages(t, wireSecret, true)
	require.Equal(t, http.StatusOK, status, "POST /v1/messages stream (%s)", body)

	ct := header.Get("Content-Type")
	require.True(t, strings.HasPrefix(ct, "text/event-stream"), "Content-Type = %q, want text/event-stream", ct)

	wire.assertTranslatedUpstreamRequest(t, true)

	events, texts := anthropicEvents(t, body)
	require.Equal(t, []string{"first ", "second ", "third"}, texts, "text deltas in order; events %q", events)

	require.NotEmpty(t, events, "events")
	require.Equal(t, "message_start", events[0], "events = %q", events)
	require.Equal(t, "message_stop", events[len(events)-1], "events = %q", events)
}

func TestVendorFailureReachesTheClient(t *testing.T) {
	w := startOnTheWire(t, &faketest.Vendor{
		FailStatus: http.StatusBadRequest,
		FailBody:   []byte(`{"error":{"message":"vendor refused the prompt","type":"invalid_request_error"}}`),
	})

	status, _, body := w.postMessages(t, wireSecret, false)
	require.Equal(t, http.StatusBadRequest, status, "POST /v1/messages (%s), want the vendor's status", body)
	require.Contains(t, string(body), "vendor refused the prompt", "response does not carry the vendor's error")
}

func TestVendorDyingMidStreamTruncatesTheClientStream(t *testing.T) {
	wire := startOnTheWire(t, &faketest.Vendor{
		Chunks: [][]byte{[]byte(`{"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"m",` +
			`"choices":[{"index":0,"delta":{"content":"partial"},"finish_reason":null}]}`)},
		DieMidStream: true,
	})

	_, _, body := wire.postMessages(t, wireSecret, true)

	events, texts := anthropicEvents(t, body)
	require.Equal(t, []string{"partial"}, texts, "text deltas, want the one chunk sent before the vendor died; events %q", events)
	require.NotContains(t, events, "message_stop", "the stream completed normally although the vendor died")
}

// TestRequestThroughProductionWiringReachesVendor sends a request through a
// gateway built exactly as production builds it — NewCoreAuthManager over the
// configured auth directory, passed with its cooldown store — so the manager on
// the request path is the one production hands in, not upstream's default.
func TestRequestThroughProductionWiringReachesVendor(t *testing.T) {
	params := productionParams(t)
	wire := startOnTheWireWith(t, &faketest.Vendor{
		Payload: []byte(`{"id":"chatcmpl-1","object":"chat.completion","created":1,"model":"m",` +
			`"choices":[{"index":0,"message":{"role":"assistant","content":"hello through production wiring"},"finish_reason":"stop"}],` +
			`"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}`),
	}, params)

	status, _, body := wire.postMessages(t, wireSecret, false)
	require.Equal(t, http.StatusOK, status, "POST /v1/messages (%s)", body)
	require.Contains(t, string(body), "hello through production wiring", "response does not carry the vendor's text")

	wire.assertTranslatedUpstreamRequest(t, false)

	// The request was served by a credential of the supplied manager: upstream
	// records the result on the auth it selected.
	deadline := time.Now().Add(5 * time.Second)

	for {
		var served int64
		for _, a := range params.CoreAuth.List() {
			served += a.Success
		}

		if served == 1 {
			break
		}

		if time.Now().After(deadline) {
			require.Failf(t, "another manager served it", "the supplied manager recorded %d successful requests, want 1", served)
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
	wire := startOnTheWire(t, &faketest.Vendor{Chunks: chunks, Latency: gap})

	began := time.Now()

	resp := wire.sendMessages(t, wireSecret, true)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode, "POST /v1/messages stream")

	reader := bufio.NewReader(resp.Body)
	for {
		line, err := reader.ReadString('\n')
		require.NoError(t, err, "stream ended before any text delta")

		if !strings.Contains(line, `"text_delta"`) {
			continue
		}

		started := wire.vendor.ChunksStarted()
		require.Less(t, started, len(chunks),
			"first text delta arrived after %s, once the vendor had begun all chunks: the stream is buffered, not flushed", time.Since(began))

		t.Logf("first text delta after %s, with %d of %d vendor chunks begun", time.Since(began), started, len(chunks))

		break
	}
	// Drain, so the stream is shown to complete as well.
	rest, err := io.ReadAll(reader)
	require.NoError(t, err, "read rest of stream")
	require.Contains(t, string(rest), "message_stop", "stream did not complete")
}

// anthropicEvents returns the event names of an Anthropic SSE stream and the
// text of its text_delta events, both in order.
func anthropicEvents(t *testing.T, body []byte) ([]string, []string) {
	t.Helper()

	var events, texts []string

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

	require.NoError(t, scanner.Err(), "scan stream")

	return events, texts
}

// TestBootRoutingStrategyPicksTheCredential: the boot configuration's routing
// strategy decides which credential serves a request from the first one, with
// the core auth manager production supplies — upstream's builder would pick
// the selector only for a manager it built itself. One vendor, two keys:
// fill-first sends every request with the same key; round-robin, the default,
// uses both.
func TestBootRoutingStrategyPicksTheCredential(t *testing.T) {
	for _, tc := range []struct {
		strategy string
		keys     int
	}{
		{"fill-first", 1},
		{"", 2},
	} {
		t.Run("strategy="+tc.strategy, func(t *testing.T) {
			vendor := &faketest.Vendor{Payload: []byte(`{"id":"chatcmpl-1","object":"chat.completion","created":1,"model":"m",` +
				`"choices":[{"index":0,"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}],` +
				`"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)}
			srv := faketest.Start(t, vendor)
			name := "routing-" + strconv.FormatInt(wireSeq.Add(1), 10)
			entry := faketest.Compatibility("fakevendor", srv.URL, "vendor-key-1", "upstream-"+name, "alias-"+name)
			entry.APIKeyEntries = append(entry.APIKeyEntries, cliproxyconfig.OpenAICompatibilityAPIKey{APIKey: "vendor-key-2"})
			cfg := &cliproxyconfig.Config{AuthDir: t.TempDir(), OpenAICompatibility: []cliproxyconfig.OpenAICompatibility{entry}}
			cfg.Routing.Strategy = tc.strategy
			manager, store, cooldown := NewCoreAuthManager(cfg)
			wire := &onTheWire{
				running: startWith(t, Params{Config: cfg, CoreAuth: manager, Store: store, Cooldown: cooldown}),
				vendor:  vendor, alias: "alias-" + name, model: "upstream-" + name,
			}
			awaitProviders(t, wire.gateway.catalog, wire.alias, []string{"fakevendor"})

			for range 4 {
				status, _, body := wire.postMessages(t, wireSecret, false)
				require.Equal(t, http.StatusOK, status, "POST /v1/messages (%s)", body)
			}

			keys := map[string]bool{}
			for _, r := range vendor.Requests() {
				keys[r.Header.Get("Authorization")] = true
			}

			require.Len(t, keys, tc.keys, "distinct keys the 4 requests reached the vendor with")
		})
	}
}
