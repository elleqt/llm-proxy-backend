package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/infra/gateway/faketest"
	"github.com/gorilla/websocket"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
	cliproxyconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

// noRedirects reports a redirect as the response it is, not as where it leads.
var noRedirects = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// send makes a request with key as a bearer token ("" for none) and returns
// the status and body; a redirect is not followed.
func (r *running) send(t *testing.T, method, path, key, body string) (int, string) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), method, r.baseURL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("build %s %s: %v", method, path, err)
	}

	req.Header.Set("Content-Type", "application/json")

	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}

	resp, err := noRedirects.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}

	defer func() { _ = resp.Body.Close() }()

	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s %s: %v", method, path, err)
	}

	return resp.StatusCode, string(out)
}

// concrete turns a gin route pattern into a path it matches.
func concrete(pattern string) string {
	segments := strings.Split(pattern, "/")
	for i, s := range segments {
		switch {
		case strings.HasPrefix(s, ":"):
			segments[i] = "x"
		case strings.HasPrefix(s, "*"):
			segments[i] = "x"
		}
	}

	return strings.Join(segments, "/")
}

// TestEveryUpstreamRouteIsClassified walks the routes the real server
// registered — including the websocket relay Run attaches — and fails on any
// the routes table does not list, so an upstream upgrade adding a route fails
// here rather than being served. A listed route upstream no longer registers
// fails too, so the table stays an exact account.
func TestEveryUpstreamRouteIsClassified(t *testing.T) {
	r := startWith(t, productionParams(t))

	registered := make(map[string]bool)

	for _, info := range r.gateway.engine.Load().Routes() {
		key := info.Method + " " + info.Path

		registered[key] = true
		if _, ok := routes[key]; !ok {
			t.Errorf("upstream route %s is not classified", key)
		}
	}

	for key := range routes {
		if !registered[key] {
			t.Errorf("classified route %s is not registered upstream", key)
		}
	}
}

// TestDeniedRoutesAreNotServed: with a valid token, every route classified as
// denied, and paths upstream serves outside its routes (plugin resources,
// management) or on another listener (pprof), answer 404 before upstream. So
// does each of them, and a served route, with a trailing slash: gin would
// otherwise redirect that to the route before the gate runs, and a redirect
// tells a route from an unrouted path.
func TestDeniedRoutesAreNotServed(t *testing.T) {
	srv := startWith(t, productionParams(t))

	var probes [][2]string

	for key, rt := range routes {
		if rt.kind == routeDenied {
			method, pattern, _ := strings.Cut(key, " ")
			probes = append(probes, [2]string{method, concrete(pattern)})
		}
	}

	probes = append(probes,
		[2]string{http.MethodGet, "/debug/pprof/"},
		[2]string{http.MethodGet, "/v0/management/config"},
		[2]string{http.MethodGet, "/v0/resource/plugins/x"},
		[2]string{http.MethodOptions, "/v1/chat/completions"},
	)
	for _, p := range append(slices.Clone(probes), [2]string{http.MethodGet, "/v1/models"}) {
		if !strings.HasSuffix(p[1], "/") {
			probes = append(probes, [2]string{p[0], p[1] + "/"})
		}
	}

	probes = append(probes, [2]string{http.MethodGet, "/V1/WS"})
	for _, p := range probes {
		if code, body := srv.send(t, p[0], p[1], wireSecret, `{"model":"x"}`); code != http.StatusNotFound || body != "" {
			t.Errorf("%s %s with a valid token = %d %q, want an empty 404", p[0], p[1], code, body)
		}
	}
	// The service's own probe stays open, so the 404s are not a dead server.
	if code, _ := srv.send(t, http.MethodGet, "/healthz", "", ""); code != http.StatusOK {
		t.Fatalf("GET /healthz without a token = %d, want 200", code)
	}
}

// TestWebsocketRelayIsRefused: /v1/ws registers whoever connects as an
// "aistudio" provider account, whose socket then receives other users'
// requests. A valid token must not open it — at boot, or after a push that
// turns websocket authentication off — and no such account may appear.
func TestWebsocketRelayIsRefused(t *testing.T) {
	params := productionParams(t)
	srv := startWith(t, params)
	wsURL := "ws" + strings.TrimPrefix(srv.baseURL, "http") + "/v1/ws"
	header := http.Header{"Authorization": {"Bearer " + wireSecret}}

	dial := func(when string) {
		t.Helper()

		conn, resp, err := websocket.DefaultDialer.Dial(wsURL, header)
		if resp != nil {
			_ = resp.Body.Close()
		}

		if err == nil {
			_ = conn.Close()

			t.Fatalf("websocket relay accepted a connection %s", when)
		}

		if resp == nil || resp.StatusCode != http.StatusNotFound {
			t.Fatalf("websocket handshake %s = %v (%v), want 404", when, resp, err)
		}
	}
	dial("at boot")

	open := srv.emptyPush()

	open.WebsocketAuth = false
	if err := srv.gateway.PushConfig(open); err != nil {
		t.Fatalf("PushConfig: %v", err)
	}

	dial("after a push turning ws-auth off")

	for _, a := range params.CoreAuth.List() {
		if a.Provider == "aistudio" {
			t.Fatalf("an aistudio account %q was registered", a.ID)
		}
	}
}

// TestRealtimeClientSecretsAreRefused: a realtime client secret authenticates
// later requests without the access provider and outlives the token that
// minted it, so a valid token must not mint one.
func TestRealtimeClientSecretsAreRefused(t *testing.T) {
	r := start(t, &cliproxyconfig.Config{})

	code, body := r.send(t, http.MethodPost, "/v1/realtime/client_secrets", wireSecret, `{"session":{"type":"realtime","model":"gpt-realtime"}}`)
	if code != http.StatusNotFound || body != "" {
		t.Fatalf("POST /v1/realtime/client_secrets with a valid token = %d %q, want an empty 404", code, body)
	}
}

// vendorPair is a running gateway with two vendors on the wire, each serving
// a model of its own and both serving a shared one, for a user whose policy
// allows only the first vendor.
type vendorPair struct {
	*running

	allowed, other                        *faketest.Vendor
	allowedAlias, otherAlias, sharedAlias string
}

func startVendorPair(t *testing.T) *vendorPair {
	t.Helper()

	payload := []byte(`{"id":"chatcmpl-1","object":"chat.completion","created":1,"model":"m",` +
		`"choices":[{"index":0,"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}],` +
		`"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
	pair := &vendorPair{allowed: &faketest.Vendor{Payload: payload}, other: &faketest.Vendor{Payload: payload}}
	allowedSrv, otherSrv := faketest.Start(t, pair.allowed), faketest.Start(t, pair.other)

	seq := strconv.FormatInt(wireSeq.Add(1), 10)
	allowedName, otherName := "allowed"+seq, "other"+seq
	pair.allowedAlias, pair.otherAlias, pair.sharedAlias = "alias-allowed-"+seq, "alias-other-"+seq, "alias-shared-"+seq
	allowedEntry := faketest.Compatibility(allowedName, allowedSrv.URL, vendorKey, "upstream-allowed-"+seq, pair.allowedAlias)
	otherEntry := faketest.Compatibility(otherName, otherSrv.URL, vendorKey, "upstream-other-"+seq, pair.otherAlias)
	shared := cliproxyconfig.OpenAICompatibilityModel{Name: "upstream-shared-" + seq, Alias: pair.sharedAlias}
	allowedEntry.Models = append(allowedEntry.Models, shared)
	otherEntry.Models = append(otherEntry.Models, shared)

	p := productionParams(t)
	p.Config.OpenAICompatibility = []cliproxyconfig.OpenAICompatibility{allowedEntry, otherEntry}
	p.Resolver = staticResolver(wireSecret, wirePrincipal, allowedName+":*")
	pair.running = startWith(t, p)
	awaitProviders(t, pair.gateway.catalog, pair.allowedAlias, []string{allowedName})
	awaitProviders(t, pair.gateway.catalog, pair.otherAlias, []string{otherName})
	awaitProviders(t, pair.gateway.catalog, pair.sharedAlias, []string{allowedName, otherName})

	return pair
}

// requests reports how many requests each vendor has received: the allowed
// vendor's count, then the other's.
func (v *vendorPair) requests() (int, int) {
	return len(v.allowed.Requests()), len(v.other.Requests())
}

// messages is an Anthropic Messages body for model.
func messages(t *testing.T, model string) string {
	t.Helper()

	body, err := json.Marshal(map[string]any{
		"model": model, "max_tokens": 16,
		"messages": []map[string]any{{"role": "user", "content": "hi"}},
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	return string(body)
}

// TestPolicyDecidesWhichVendorARequestReaches drives the real server with two
// vendors on the wire: a model of the allowed vendor reaches it; a model of
// the other vendor, and one both vendors serve, are refused before either
// vendor sees a request.
func TestPolicyDecidesWhichVendorARequestReaches(t *testing.T) {
	pair := startVendorPair(t)
	for _, model := range []string{pair.otherAlias, pair.sharedAlias} {
		if code, body := pair.send(t, http.MethodPost, "/v1/messages", wireSecret, messages(t, model)); code != http.StatusForbidden {
			t.Fatalf("POST /v1/messages for %s = %d %s, want 403", model, code, body)
		}
	}

	if n, m := pair.requests(); n != 0 || m != 0 {
		t.Fatalf("vendors received %d and %d requests from refused clients, want none", n, m)
	}

	if code, body := pair.send(t, http.MethodPost, "/v1/messages", wireSecret, messages(t, pair.allowedAlias)); code != http.StatusOK {
		t.Fatalf("POST /v1/messages for %s = %d %s, want 200", pair.allowedAlias, code, body)
	}

	if n, m := pair.requests(); n != 1 || m != 0 {
		t.Fatalf("vendors received %d and %d requests, want the allowed vendor exactly 1", n, m)
	}
}

// TestRepeatedModelKeysAreRefused: upstream routes and rewrites the first
// "model" of a body and passes a later one on to the vendor, which may read
// the last one, or match "Model", instead. A body naming "model" twice is
// refused whichever comes first, and reaches no vendor.
func TestRepeatedModelKeysAreRefused(t *testing.T) {
	pair := startVendorPair(t)
	rest := `"max_tokens":16,"messages":[{"role":"user","content":"hi"}]`

	bodies := map[string]string{
		"allowed, then denied":     `{"model":"` + pair.allowedAlias + `",` + rest + `,"model":"` + pair.otherAlias + `"}`,
		"denied, then allowed":     `{"model":"` + pair.otherAlias + `",` + rest + `,"model":"` + pair.allowedAlias + `"}`,
		"a case-variant duplicate": `{"model":"` + pair.allowedAlias + `",` + rest + `,"Model":"` + pair.otherAlias + `"}`,
		"an escaped duplicate":     `{"model":"` + pair.allowedAlias + `",` + rest + `,"mod\u0065l":"` + pair.otherAlias + `"}`,
	}
	for what, body := range bodies {
		for _, path := range []string{"/v1/messages", "/v1/chat/completions"} {
			if code, out := pair.send(t, http.MethodPost, path, wireSecret, body); code != http.StatusBadRequest {
				t.Errorf("POST %s with %s = %d %s, want 400", path, what, code, out)
			}
		}
	}

	if n, m := pair.requests(); n != 0 || m != 0 {
		t.Fatalf("vendors received %d and %d requests carrying a repeated model, want none", n, m)
	}
	// The refusals are the rule, not a broken setup.
	if code, out := pair.send(t, http.MethodPost, "/v1/messages", wireSecret, messages(t, pair.allowedAlias)); code != http.StatusOK {
		t.Fatalf("POST /v1/messages naming the allowed model once = %d %s, want 200", code, out)
	}
}

// TestAccessIsClaimedBeforeTheServerServes: upstream refreshes its access
// manager from the process-global registry just before the server starts
// and reclaims nothing until the watcher exists, 100 ms or more later. A
// provider registered beside ours must already be out of the manager by the
// time the server first answers.
func TestAccessIsClaimedBeforeTheServerServes(t *testing.T) {
	sdkaccess.RegisterProvider(admitAllType, admitAll{})
	t.Cleanup(func() { sdkaccess.UnregisterProvider(admitAllType) })

	t.Setenv("MANAGEMENT_PASSWORD", "")
	port := freePort(t)

	gw, err := New(Params{
		Config:     &cliproxyconfig.Config{Port: port, AuthDir: t.TempDir()},
		ConfigPath: filepath.Join(t.TempDir(), "unused.yaml"),
		Resolver:   wireResolver,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- gw.Run(ctx) }()

	t.Cleanup(func() {
		cancel()
		<-done
	})

	base := "http://127.0.0.1:" + strconv.Itoa(port)
	deadline := time.Now().Add(20 * time.Second)

	for {
		if code, _ := get(t, base+"/healthz"); code == http.StatusOK {
			break
		}

		if time.Now().After(deadline) {
			t.Fatal("the server never answered")
		}

		time.Sleep(time.Millisecond)
	}

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, base+"/v1/models", http.NoBody)
	if res, authErr := gw.access.Authenticate(context.Background(), req); authErr == nil {
		t.Fatalf("the access manager admitted an uncredentialed request as %q while the server was serving", res.Principal)
	}
}
