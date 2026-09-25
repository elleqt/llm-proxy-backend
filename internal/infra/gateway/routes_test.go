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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// noRedirects reports a redirect as the response it is, not as where it leads.
var noRedirects = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// send makes a request with key as a bearer token ("" for none) and returns
// the status and body; a redirect is not followed.
func (r *running) send(t *testing.T, method, path, key, body string) (int, string) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), method, r.baseURL+path, strings.NewReader(body))
	require.NoError(t, err, "build %s %s", method, path)

	req.Header.Set("Content-Type", "application/json")

	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}

	resp, err := noRedirects.Do(req)
	require.NoError(t, err, "%s %s", method, path)

	defer func() { _ = resp.Body.Close() }()

	out, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "read %s %s", method, path)

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

		assert.Contains(t, routes, key, "upstream route %s is not classified", key)
	}

	for key := range routes {
		assert.True(t, registered[key], "classified route %s is not registered upstream", key)
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
		code, body := srv.send(t, p[0], p[1], wireSecret, `{"model":"x"}`)
		assert.Equal(t, http.StatusNotFound, code, "%s %s with a valid token, want an empty 404", p[0], p[1])
		assert.Empty(t, body, "%s %s with a valid token, want an empty 404", p[0], p[1])
	}
	// The service's own probe stays open, so the 404s are not a dead server.
	code, _ := srv.send(t, http.MethodGet, "/healthz", "", "")
	require.Equal(t, http.StatusOK, code, "GET /healthz without a token")
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

			require.Failf(t, "websocket relay accepted a connection", "when: %s", when)
		}

		require.NotNil(t, resp, "websocket handshake %s (%v), want 404", when, err)
		require.Equal(t, http.StatusNotFound, resp.StatusCode, "websocket handshake %s (%v)", when, err)
	}
	dial("at boot")

	open := srv.emptyPush()

	open.WebsocketAuth = false
	require.NoError(t, srv.gateway.PushConfig(open), "PushConfig")

	dial("after a push turning ws-auth off")

	for _, a := range params.CoreAuth.List() {
		require.NotEqual(t, "aistudio", a.Provider, "an aistudio account %q was registered", a.ID)
	}
}

// TestRealtimeClientSecretsAreRefused: a realtime client secret authenticates
// later requests without the access provider and outlives the token that
// minted it, so a valid token must not mint one.
func TestRealtimeClientSecretsAreRefused(t *testing.T) {
	r := start(t, &cliproxyconfig.Config{})

	code, body := r.send(t, http.MethodPost, "/v1/realtime/client_secrets", wireSecret, `{"session":{"type":"realtime","model":"gpt-realtime"}}`)
	require.Equal(t, http.StatusNotFound, code, "POST /v1/realtime/client_secrets with a valid token, want an empty 404")
	require.Empty(t, body, "POST /v1/realtime/client_secrets with a valid token, want an empty 404")
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
	require.NoError(t, err, "marshal request")

	return string(body)
}

// TestPolicyDecidesWhichVendorARequestReaches drives the real server with two
// vendors on the wire: a model of the allowed vendor reaches it; a model of
// the other vendor, and one both vendors serve, are refused before either
// vendor sees a request.
func TestPolicyDecidesWhichVendorARequestReaches(t *testing.T) {
	pair := startVendorPair(t)
	for _, model := range []string{pair.otherAlias, pair.sharedAlias} {
		code, body := pair.send(t, http.MethodPost, "/v1/messages", wireSecret, messages(t, model))
		require.Equal(t, http.StatusForbidden, code, "POST /v1/messages for %s: %s", model, body)
	}

	toAllowed, toOther := pair.requests()
	require.Zero(t, toAllowed, "allowed vendor's requests from refused clients")
	require.Zero(t, toOther, "other vendor's requests from refused clients")

	code, body := pair.send(t, http.MethodPost, "/v1/messages", wireSecret, messages(t, pair.allowedAlias))
	require.Equal(t, http.StatusOK, code, "POST /v1/messages for %s: %s", pair.allowedAlias, body)

	toAllowed, toOther = pair.requests()
	require.Equal(t, 1, toAllowed, "allowed vendor's requests")
	require.Zero(t, toOther, "other vendor's requests")
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
			code, out := pair.send(t, http.MethodPost, path, wireSecret, body)
			assert.Equal(t, http.StatusBadRequest, code, "POST %s with %s: %s", path, what, out)
		}
	}

	toAllowed, toOther := pair.requests()
	require.Zero(t, toAllowed, "allowed vendor's requests carrying a repeated model")
	require.Zero(t, toOther, "other vendor's requests carrying a repeated model")
	// The refusals are the rule, not a broken setup.
	code, out := pair.send(t, http.MethodPost, "/v1/messages", wireSecret, messages(t, pair.allowedAlias))
	require.Equal(t, http.StatusOK, code, "POST /v1/messages naming the allowed model once: %s", out)
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
	require.NoError(t, err, "New")

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
			require.Fail(t, "the server never answered")
		}

		time.Sleep(time.Millisecond)
	}

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, base+"/v1/models", http.NoBody)
	if res, authErr := gw.access.Authenticate(context.Background(), req); authErr == nil {
		require.Failf(t, "the access manager admitted an uncredentialed request while the server was serving", "as %q", res.Principal)
	}
}
