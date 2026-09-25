package gateway

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/infra/gateway/faketest"
	"github.com/google/uuid"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
	cliproxyconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests that push run on gateways without a boot-declared vendor: a push
// shortly after a boot that declared config-derived credentials races inside
// upstream (see startOnTheWire). /v1/models sits behind the same
// access middleware as every proxied route and answers 200 once admitted, so
// it shows admission without a vendor.

// models sends GET /v1/models with key as a bearer token ("" for none) and
// returns the status.
func (r *running) models(t *testing.T, key string) int {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, r.baseURL+"/v1/models", http.NoBody)
	require.NoError(t, err, "build request")

	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err, "GET /v1/models")

	_ = resp.Body.Close()

	return resp.StatusCode
}

// assertClosed requires no credential and an unknown token to get 401 and
// admitted's token to get through. The policy gate answers those 401s before
// upstream's access check runs, so the access manager — the second guard,
// which admits everything when it holds no provider — is asked directly too:
// an uncredentialed request must not pass it either.
func (r *running) assertClosed(t *testing.T, admitted, when string) {
	t.Helper()

	require.Equal(t, http.StatusUnauthorized, r.models(t, ""), "GET /v1/models without a credential %s", when)
	require.Equal(t, http.StatusUnauthorized, r.models(t, "sk-unknown"), "GET /v1/models with an unknown token %s", when)
	require.Equal(t, http.StatusOK, r.models(t, admitted), "GET /v1/models with a valid token %s", when)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/models", http.NoBody)
	if res, authErr := r.gateway.access.Authenticate(context.Background(), req); authErr == nil {
		require.Failf(t, "the access manager admitted an uncredentialed request", "%s as %q", when, res.Principal)
	}
}

// emptyPush is a configuration that changes nothing the tests depend on.
func (r *running) emptyPush() *cliproxyconfig.Config {
	current := r.gateway.CurrentConfig()

	return &cliproxyconfig.Config{AuthDir: current.AuthDir, Port: current.Port}
}

// TestAccessThroughTheServerIsByTokenOnly drives the real embedded server to
// the vendor: no credential and an unknown token are refused before reaching
// it, a valid token reaches it.
func TestAccessThroughTheServerIsByTokenOnly(t *testing.T) {
	wire := startOnTheWire(t, &faketest.Vendor{Payload: []byte(`{"id":"chatcmpl-1","object":"chat.completion","created":1,"model":"m",` +
		`"choices":[{"index":0,"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}],` +
		`"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)})

	for _, tc := range []struct{ key, what string }{{"", "no credential"}, {"sk-unknown", "an unknown token"}} {
		status, _, body := wire.postMessages(t, tc.key, false)
		require.Equal(t, http.StatusUnauthorized, status, "POST /v1/messages with %s (%s)", tc.what, body)
	}

	require.Empty(t, wire.vendor.Requests(), "vendor received requests from refused clients")

	status, _, body := wire.postMessages(t, wireSecret, false)
	require.Equal(t, http.StatusOK, status, "POST /v1/messages with a valid token (%s)", body)

	require.Len(t, wire.vendor.Requests(), 1, "want the valid client's 1 request at the vendor")
}

// TestAccessStaysClosedAcrossAPush: a push is when upstream rebuilds its
// access providers from its registry — and when its plugin host clears the
// registry's exclusive provider. Both refusals and the admission must hold
// before and after.
func TestAccessStaysClosedAcrossAPush(t *testing.T) {
	srv := start(t, &cliproxyconfig.Config{})
	srv.assertClosed(t, wireSecret, "at boot")

	require.NoError(t, srv.gateway.PushConfig(srv.emptyPush()), "PushConfig")

	srv.assertClosed(t, wireSecret, "after a push")
}

// admitAll is an access provider that admits every request: what a plugin's
// frontend auth provider, or upstream's own config-api-key provider, would be
// if it were registered alongside ours.
type admitAll struct{}

const admitAllType = "test-admit-all"

func (admitAll) Identifier() string { return admitAllType }

func (admitAll) Authenticate(context.Context, *http.Request) (*sdkaccess.Result, *sdkaccess.AuthError) {
	return &sdkaccess.Result{Provider: admitAllType, Principal: "anyone"}, nil
}

// TestNoOtherAccessProviderCanAdmit: upstream's registry is process-global
// and any code may register a provider in it, even claim exclusivity. Ours
// must still be the only one the server authenticates with, at boot and after
// a push.
func TestNoOtherAccessProviderCanAdmit(t *testing.T) {
	sdkaccess.RegisterProvider(admitAllType, admitAll{})
	sdkaccess.SetExclusiveProvider(admitAllType)
	t.Cleanup(func() { sdkaccess.UnregisterProvider(admitAllType) })

	srv := start(t, &cliproxyconfig.Config{})
	srv.assertClosed(t, wireSecret, "beside an admit-all provider")

	require.NoError(t, srv.gateway.PushConfig(srv.emptyPush()), "PushConfig")

	srv.assertClosed(t, wireSecret, "beside an admit-all provider after a push")
}

// TestConfigAPIKeysAreRefused: a config key belongs to no user, so no policy
// could apply to it. New and PushConfig refuse it, and a refused push leaves
// the key without effect.
func TestConfigAPIKeysAreRefused(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")

	withKeys := &cliproxyconfig.Config{AuthDir: t.TempDir(), APIKeys: []string{"config-master-key"}}
	_, err := New(Params{Config: withKeys, ConfigPath: filepath.Join(t.TempDir(), "unused.yaml"), Resolver: wireResolver})
	require.ErrorIs(t, err, ErrConfigAPIKeys, "New with api-keys")

	srv := start(t, &cliproxyconfig.Config{})
	before := srv.gateway.CurrentConfig()
	pushed := srv.emptyPush()

	pushed.APIKeys = []string{"config-master-key"}
	require.ErrorIs(t, srv.gateway.PushConfig(pushed), ErrConfigAPIKeys, "PushConfig with api-keys")
	require.Same(t, before, srv.gateway.CurrentConfig(), "CurrentConfig reports the refused configuration")
	require.Equal(t, http.StatusUnauthorized, srv.models(t, "config-master-key"), "GET /v1/models with the refused config key")
}

// TestPluginsAndHomeModeAreRefused: a plugin can register an access provider,
// even an exclusive one, and models of its own; home mode routes every
// request to an external dispatcher without asking the model registry. New
// and PushConfig refuse to enable either.
func TestPluginsAndHomeModeAreRefused(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")

	srv := start(t, &cliproxyconfig.Config{})
	for _, tc := range []struct {
		what   string
		enable func(*cliproxyconfig.Config)
		want   error
	}{
		{"plugins", func(c *cliproxyconfig.Config) { c.Plugins.Enabled = true }, ErrPlugins},
		{"home mode", func(c *cliproxyconfig.Config) { c.Home.Enabled = true }, ErrHomeMode},
	} {
		t.Run(tc.what, func(t *testing.T) {
			boot := &cliproxyconfig.Config{AuthDir: t.TempDir()}
			tc.enable(boot)

			_, err := New(Params{Config: boot, ConfigPath: filepath.Join(t.TempDir(), "unused.yaml"), Resolver: wireResolver})
			require.ErrorIs(t, err, tc.want, "New with %s", tc.what)

			before := srv.gateway.CurrentConfig()
			pushed := srv.emptyPush()
			tc.enable(pushed)

			require.ErrorIs(t, srv.gateway.PushConfig(pushed), tc.want, "PushConfig with %s", tc.what)
			assert.Same(t, before, srv.gateway.CurrentConfig(), "CurrentConfig reports the configuration enabling %s", tc.what)
		})
	}
}

func TestNewRefusesWithoutAResolver(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")

	_, err := New(Params{Config: &cliproxyconfig.Config{AuthDir: t.TempDir()}, ConfigPath: filepath.Join(t.TempDir(), "unused.yaml")})
	require.ErrorIs(t, err, ErrNoResolver, "New without a resolver")
}

// TestEachGatewayAuthenticatesWithItsOwnResolver: the provider is registered
// in a process-global registry on every New. A gateway built later must not
// inherit an earlier gateway's resolver (a registration made once would), and
// the earlier one must keep its own — including across a push, which is when
// upstream re-reads the registry.
func TestEachGatewayAuthenticatesWithItsOwnResolver(t *testing.T) {
	const secretB = "sk-gateway-b"

	first := start(t, &cliproxyconfig.Config{})
	second := startWith(t, Params{
		Config:   &cliproxyconfig.Config{},
		Resolver: staticResolver(secretB, app.Principal{UserID: uuid.New(), TokenID: uuid.New()}),
	})

	second.assertClosed(t, secretB, "at the later gateway")

	require.Equal(t, http.StatusUnauthorized, second.models(t, wireSecret), "the earlier gateway's token at the later gateway")
	require.NoError(t, first.gateway.PushConfig(first.emptyPush()), "PushConfig")

	first.assertClosed(t, wireSecret, "at the earlier gateway after its push")

	require.Equal(t, http.StatusUnauthorized, first.models(t, secretB), "the later gateway's token at the earlier gateway")

	second.assertClosed(t, secretB, "at the later gateway after the earlier one pushed")
}

// pprofOn is a push enabling upstream's pprof server on a free port, and the
// URL it then answers on.
func (r *running) pprofOn(t *testing.T) (*cliproxyconfig.Config, string) {
	t.Helper()
	port := strconv.Itoa(freePort(t))
	cfg := r.emptyPush()
	cfg.Pprof.Enable = true
	cfg.Pprof.Addr = net.JoinHostPort("", port)

	return cfg, "http://" + net.JoinHostPort("", port) + "/debug/pprof/"
}

// awaitPprof waits until url answers 200: upstream starts the pprof server
// listening in the background once a push enables it (pprof_server.go).
func awaitPprof(t *testing.T, url, when string) {
	t.Helper()

	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		code, _ := get(t, url)
		if code == http.StatusOK {
			return
		}

		if time.Now().After(deadline) {
			require.Failf(t, "pprof did not answer", "GET %s %s = %d, want %d", url, when, code, http.StatusOK)
		}
	}
}

// TestPushedConfigReachesTheServer: a pushed value changes what the running
// service does. Upstream's pprof server is off at boot and pushed on.
func TestPushedConfigReachesTheServer(t *testing.T) {
	srv := start(t, &cliproxyconfig.Config{})

	on, url := srv.pprofOn(t)
	code, _ := get(t, url)
	require.Zero(t, code, "GET %s before the push: want nothing listening", url)
	require.NoError(t, srv.gateway.PushConfig(on), "PushConfig")

	awaitPprof(t, url, "after pushing pprof on")
}

// TestPushConfigRejectsWhatUpstreamWouldDrop covers a configuration upstream
// discards without telling the reload caller: the push must fail, and both the
// running service and CurrentConfig must keep the previous configuration.
func TestPushConfigRejectsWhatUpstreamWouldDrop(t *testing.T) {
	srv := start(t, &cliproxyconfig.Config{})

	accepted, url := srv.pprofOn(t)
	require.NoError(t, srv.gateway.PushConfig(accepted), "PushConfig")

	awaitPprof(t, url, "after pushing pprof on")

	// pprof off, so accepting it would stop the pprof server again.
	tooHeavy := 1_000_001
	rejected := srv.emptyPush()

	rejected.OpenAICompatibility = []cliproxyconfig.OpenAICompatibility{{
		Name:          "overweight",
		BaseURL:       "http://" + net.JoinHostPort("", "1"),
		APIKeyEntries: []cliproxyconfig.OpenAICompatibilityAPIKey{{APIKey: "k", Weight: &tooHeavy}},
	}}
	require.Error(t, srv.gateway.PushConfig(rejected), "PushConfig accepted a configuration with an out-of-range credential weight")
	require.Same(t, accepted, srv.gateway.CurrentConfig(), "CurrentConfig reports the rejected configuration")

	code, _ := get(t, url)
	require.Equal(t, http.StatusOK, code, "GET %s: the running service must keep the accepted configuration", url)
}
