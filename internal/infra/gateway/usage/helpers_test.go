package usage

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/infra/gateway"
	"github.com/elleqt/llm-proxy-backend/internal/infra/gateway/faketest"
	cliproxyconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// The helpers below serve a real gateway the way the core gateway package's
// own tests do (wire_test.go, service_test.go), over its exported surface:
// test helpers of another package cannot be imported.

const vendorKey = "vendor-upstream-key"

// mustPolicy is the policy rules parse to; a malformed rule is a broken test.
func mustPolicy(rules ...string) access.Policy {
	policy := make(access.Policy, 0, len(rules))
	for _, s := range rules {
		rule, err := access.ParseRule(s)
		if err != nil {
			panic(err)
		}

		policy = append(policy, rule)
	}

	return policy
}

// onTheWire is a running gateway whose only vendor is an openai-compatibility
// provider "fakevendor", reachable under alias.
type onTheWire struct {
	baseURL string
	alias   string
	model   string
}

// startOnTheWireWith boots a gateway over params, whose Config gains vendor as
// the openai-compatibility provider "fakevendor", and returns once it serves
// the vendor's model. The entry is in the boot configuration, not a pushed
// one: upstream synthesises credentials from configuration on Run, never on
// the reload callback PushConfig drives.
func startOnTheWireWith(t *testing.T, vendor *faketest.Vendor, params gateway.Params) *onTheWire {
	t.Helper()
	srv := faketest.Start(t, vendor)
	name := strings.ToLower(t.Name())
	wire := &onTheWire{alias: "alias-" + name, model: "upstream-" + name}

	params.Config.OpenAICompatibility = []cliproxyconfig.OpenAICompatibility{
		faketest.Compatibility("fakevendor", srv.URL, vendorKey, wire.model, wire.alias),
	}
	gw := startWith(t, params)
	wire.baseURL = gw.baseURL
	// Upstream registers configured models after it starts serving
	// (service_lifecycle.go syncPluginModelRuntime); until then the gate
	// rightly refuses the model as served by no provider.
	awaitProviders(t, gw.gateway.Catalog(), wire.alias, []string{"fakevendor"})

	return wire
}

// running is a started gateway and its base URL.
type running struct {
	gateway *gateway.Gateway
	baseURL string
}

// startWith brings a gateway up on an ephemeral port and blocks until it
// serves requests. It is stopped before the test ends.
func startWith(t *testing.T, params gateway.Params) *running {
	t.Helper()
	// A non-empty MANAGEMENT_PASSWORD makes New refuse to build, because it
	// would enable upstream's management surface; pin it so no test depends on
	// the ambient environment.
	t.Setenv("MANAGEMENT_PASSWORD", "")

	port := freePort(t)

	params.Config.Port = port
	if params.Config.AuthDir == "" {
		params.Config.AuthDir = t.TempDir()
	}
	// The path is required by the upstream builder but must never be created:
	// configuration arrives through PushConfig, not from disk.
	params.ConfigPath = filepath.Join(t.TempDir(), "unused.yaml")

	booted := watchWatcherStarted(t)

	gw, err := gateway.New(params)
	require.NoError(t, err, "New")

	ctx, cancel := context.WithCancel(context.Background())

	runErr := make(chan error, 1)
	go func() { runErr <- gw.Run(ctx) }()

	// Stopping waits at most 30s and, like the core helpers, does not fail
	// the test.
	t.Cleanup(func() {
		cancel()

		select {
		case <-runErr:
		case <-time.After(30 * time.Second):
		}
	})

	waitCtx, cancelWait := context.WithTimeout(ctx, 20*time.Second)
	defer cancelWait()

	require.NoError(t, gw.WaitReload(waitCtx), "watcher was never created")
	// WaitReload returns as the watcher is created; Run then reads the
	// service configuration unlocked to hand it to the watcher, and its next
	// step logs, which orders everything before it ahead of what follows.
	select {
	case <-booted:
	case <-waitCtx.Done():
		require.Fail(t, "upstream never logged that it started the watcher")
	}

	srv := &running{gateway: gw, baseURL: "http://" + net.JoinHostPort("", strconv.Itoa(port))}
	waitHealthy(t, srv.baseURL)

	return srv
}

// watcherStarted is what upstream logs right after handing the watcher its
// configuration (service_lifecycle.go:204).
const watcherStarted = "file watcher started for config and auth directory changes"

// watchWatcherStarted returns a channel closed when upstream next logs
// watcherStarted, through a hook on the standard logger it logs to, removed
// when the test ends.
func watchWatcherStarted(t *testing.T) <-chan struct{} {
	t.Helper()

	hook := &logHook{message: watcherStarted, seen: make(chan struct{})}
	logger := log.StandardLogger()

	hooks := make(log.LevelHooks)
	for level, hs := range logger.Hooks {
		hooks[level] = append([]log.Hook(nil), hs...)
	}

	hooks.Add(hook)
	old := logger.ReplaceHooks(hooks)

	t.Cleanup(func() { logger.ReplaceHooks(old) })

	return hook.seen
}

// logHook closes seen the first time message is logged.
type logHook struct {
	message string
	once    sync.Once
	seen    chan struct{}
}

func (h *logHook) Levels() []log.Level { return log.AllLevels }

func (h *logHook) Fire(e *log.Entry) error {
	if e.Message == h.message {
		h.once.Do(func() { close(h.seen) })
	}

	return nil
}

// freePort reserves and releases a port so the gateway can bind it.
func freePort(t *testing.T) int {
	t.Helper()

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", ":0")
	require.NoError(t, err, "reserve port")

	addr, ok := listener.Addr().(*net.TCPAddr)
	require.True(t, ok, "reserved address %v is not TCP", listener.Addr())

	port := addr.Port

	require.NoError(t, listener.Close(), "release port")

	return port
}

// waitHealthy waits up to 20s for the gateway's health check to answer 200.
func waitHealthy(t *testing.T, baseURL string) {
	t.Helper()

	deadline := time.Now().Add(20 * time.Second)

	for {
		code := healthStatus(t, baseURL+"/healthz")
		if code == http.StatusOK {
			return
		}

		if time.Now().After(deadline) {
			require.Failf(t, "gateway never became healthy", "last status %d", code)
		}

		time.Sleep(20 * time.Millisecond)
	}
}

// healthStatus is the status GET url answers, or 0 when the request could not
// be made.
func healthStatus(t *testing.T, url string) int {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, http.NoBody)
	require.NoError(t, err, "build request GET %s", url)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0
	}

	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	return resp.StatusCode
}

// awaitProviders waits until catalog answers want for model: upstream
// registers a running gateway's configured models after it starts serving.
func awaitProviders(t *testing.T, catalog *gateway.Catalog, model string, want []string) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)

	for {
		got := catalog.ProvidersFor(model)
		if slices.Equal(got, want) {
			return
		}

		if time.Now().After(deadline) {
			require.Failf(t, "providers never matched", "ProvidersFor(%q) = %v, want %v", model, got, want)
		}

		time.Sleep(5 * time.Millisecond)
	}
}

// postMessages sends a non-streaming Anthropic Messages request for the
// vendor's alias, so that reaching the OpenAI-compatible vendor requires
// upstream to translate both ways. It returns the response status and body.
func (w *onTheWire) postMessages(t *testing.T, key string) (int, []byte) {
	t.Helper()

	body, err := json.Marshal(map[string]any{
		"model":      w.alias,
		"max_tokens": 64,
		"stream":     false,
		"messages":   []map[string]any{{"role": "user", "content": "say hello"}},
	})
	require.NoError(t, err, "marshal request")

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, w.baseURL+"/v1/messages", strings.NewReader(string(body)))
	require.NoError(t, err, "build request")

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err, "POST /v1/messages")

	defer func() { _ = resp.Body.Close() }()

	out, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "read response")

	return resp.StatusCode, out
}
