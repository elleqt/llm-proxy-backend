package gateway

import (
	"context"
	"errors"
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
	if err != nil {
		t.Fatalf("build request: %v", err)
	}

	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /v1/models: %v", err)
	}

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

	if code := r.models(t, ""); code != http.StatusUnauthorized {
		t.Fatalf("GET /v1/models without a credential %s = %d, want %d", when, code, http.StatusUnauthorized)
	}

	if code := r.models(t, "sk-unknown"); code != http.StatusUnauthorized {
		t.Fatalf("GET /v1/models with an unknown token %s = %d, want %d", when, code, http.StatusUnauthorized)
	}

	if code := r.models(t, admitted); code != http.StatusOK {
		t.Fatalf("GET /v1/models with a valid token %s = %d, want %d", when, code, http.StatusOK)
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/models", http.NoBody)
	if res, err := r.gateway.access.Authenticate(context.Background(), req); err == nil {
		t.Fatalf("the access manager admitted an uncredentialed request %s as %q", when, res.Principal)
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
		if status, _, body := wire.postMessages(t, tc.key, false); status != http.StatusUnauthorized {
			t.Fatalf("POST /v1/messages with %s = %d (%s), want %d", tc.what, status, body, http.StatusUnauthorized)
		}
	}

	if n := len(wire.vendor.Requests()); n != 0 {
		t.Fatalf("vendor received %d requests from refused clients", n)
	}

	if status, _, body := wire.postMessages(t, wireSecret, false); status != http.StatusOK {
		t.Fatalf("POST /v1/messages with a valid token = %d (%s), want 200", status, body)
	}

	if n := len(wire.vendor.Requests()); n != 1 {
		t.Fatalf("vendor received %d requests, want the valid client's 1", n)
	}
}

// TestAccessStaysClosedAcrossAPush: a push is when upstream rebuilds its
// access providers from its registry — and when its plugin host clears the
// registry's exclusive provider. Both refusals and the admission must hold
// before and after.
func TestAccessStaysClosedAcrossAPush(t *testing.T) {
	srv := start(t, &cliproxyconfig.Config{})
	srv.assertClosed(t, wireSecret, "at boot")

	if err := srv.gateway.PushConfig(srv.emptyPush()); err != nil {
		t.Fatalf("PushConfig: %v", err)
	}

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

	if err := srv.gateway.PushConfig(srv.emptyPush()); err != nil {
		t.Fatalf("PushConfig: %v", err)
	}

	srv.assertClosed(t, wireSecret, "beside an admit-all provider after a push")
}

// TestConfigAPIKeysAreRefused: a config key belongs to no user, so no policy
// could apply to it. New and PushConfig refuse it, and a refused push leaves
// the key without effect.
func TestConfigAPIKeysAreRefused(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")

	withKeys := &cliproxyconfig.Config{AuthDir: t.TempDir(), APIKeys: []string{"config-master-key"}}
	if _, err := New(Params{Config: withKeys, ConfigPath: filepath.Join(t.TempDir(), "unused.yaml"), Resolver: wireResolver}); !errors.Is(err, ErrConfigAPIKeys) {
		t.Fatalf("New with api-keys = %v, want ErrConfigAPIKeys", err)
	}

	srv := start(t, &cliproxyconfig.Config{})
	before := srv.gateway.CurrentConfig()
	pushed := srv.emptyPush()

	pushed.APIKeys = []string{"config-master-key"}
	if err := srv.gateway.PushConfig(pushed); !errors.Is(err, ErrConfigAPIKeys) {
		t.Fatalf("PushConfig with api-keys = %v, want ErrConfigAPIKeys", err)
	}

	if srv.gateway.CurrentConfig() != before {
		t.Fatal("CurrentConfig reports the refused configuration")
	}

	if code := srv.models(t, "config-master-key"); code != http.StatusUnauthorized {
		t.Fatalf("GET /v1/models with the refused config key = %d, want %d", code, http.StatusUnauthorized)
	}
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
		boot := &cliproxyconfig.Config{AuthDir: t.TempDir()}
		tc.enable(boot)

		if _, err := New(Params{Config: boot, ConfigPath: filepath.Join(t.TempDir(), "unused.yaml"), Resolver: wireResolver}); !errors.Is(err, tc.want) {
			t.Errorf("New with %s = %v, want %v", tc.what, err, tc.want)
		}

		before := srv.gateway.CurrentConfig()
		pushed := srv.emptyPush()
		tc.enable(pushed)

		if err := srv.gateway.PushConfig(pushed); !errors.Is(err, tc.want) {
			t.Errorf("PushConfig with %s = %v, want %v", tc.what, err, tc.want)
		}

		if srv.gateway.CurrentConfig() != before {
			t.Errorf("CurrentConfig reports the configuration enabling %s", tc.what)
		}
	}
}

func TestNewRefusesWithoutAResolver(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")

	_, err := New(Params{Config: &cliproxyconfig.Config{AuthDir: t.TempDir()}, ConfigPath: filepath.Join(t.TempDir(), "unused.yaml")})
	if !errors.Is(err, ErrNoResolver) {
		t.Fatalf("New without a resolver = %v, want ErrNoResolver", err)
	}
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

	if code := second.models(t, wireSecret); code != http.StatusUnauthorized {
		t.Fatalf("the earlier gateway's token at the later gateway = %d, want %d", code, http.StatusUnauthorized)
	}

	if err := first.gateway.PushConfig(first.emptyPush()); err != nil {
		t.Fatalf("PushConfig: %v", err)
	}

	first.assertClosed(t, wireSecret, "at the earlier gateway after its push")

	if code := first.models(t, secretB); code != http.StatusUnauthorized {
		t.Fatalf("the later gateway's token at the earlier gateway = %d, want %d", code, http.StatusUnauthorized)
	}

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
			t.Fatalf("GET %s %s = %d, want %d", url, when, code, http.StatusOK)
		}
	}
}

// TestPushedConfigReachesTheServer: a pushed value changes what the running
// service does. Upstream's pprof server is off at boot and pushed on.
func TestPushedConfigReachesTheServer(t *testing.T) {
	srv := start(t, &cliproxyconfig.Config{})

	on, url := srv.pprofOn(t)
	if code, _ := get(t, url); code != 0 {
		t.Fatalf("GET %s before the push = %d, want nothing listening", url, code)
	}

	if err := srv.gateway.PushConfig(on); err != nil {
		t.Fatalf("PushConfig: %v", err)
	}

	awaitPprof(t, url, "after pushing pprof on")
}

// TestPushConfigRejectsWhatUpstreamWouldDrop covers a configuration upstream
// discards without telling the reload caller: the push must fail, and both the
// running service and CurrentConfig must keep the previous configuration.
func TestPushConfigRejectsWhatUpstreamWouldDrop(t *testing.T) {
	srv := start(t, &cliproxyconfig.Config{})

	accepted, url := srv.pprofOn(t)
	if err := srv.gateway.PushConfig(accepted); err != nil {
		t.Fatalf("PushConfig: %v", err)
	}

	awaitPprof(t, url, "after pushing pprof on")

	// pprof off, so accepting it would stop the pprof server again.
	tooHeavy := 1_000_001
	rejected := srv.emptyPush()

	rejected.OpenAICompatibility = []cliproxyconfig.OpenAICompatibility{{
		Name:          "overweight",
		BaseURL:       "http://" + net.JoinHostPort("", "1"),
		APIKeyEntries: []cliproxyconfig.OpenAICompatibilityAPIKey{{APIKey: "k", Weight: &tooHeavy}},
	}}
	if err := srv.gateway.PushConfig(rejected); err == nil {
		t.Fatal("PushConfig accepted a configuration with an out-of-range credential weight")
	}

	if got := srv.gateway.CurrentConfig(); got != accepted {
		t.Fatal("CurrentConfig reports the rejected configuration")
	}

	if code, _ := get(t, url); code != http.StatusOK {
		t.Fatalf("GET %s = %d, want %d: the running service must keep the accepted configuration", url, code, http.StatusOK)
	}
}
