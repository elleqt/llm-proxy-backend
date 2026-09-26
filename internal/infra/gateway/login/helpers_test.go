package login

import (
	"context"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/infra/gateway"
	sdkauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// The helpers below start a real gateway the way the core gateway package's
// own tests do (service_test.go, accounts_test.go), over its exported surface:
// test helpers of another package cannot be imported.

// running is a started gateway.
type running struct {
	gateway *gateway.Gateway
}

// bootSeq keeps the boot credentials of several gateways apart.
var bootSeq atomic.Int64

// refuseAll is the resolver of a gateway whose tests send it no proxied
// request: it refuses every credential, as app.TokenResolver refuses.
type refuseAll struct{}

func (refuseAll) Resolve(context.Context, string) (app.Principal, access.Policy, error) {
	return app.Principal{}, nil, app.ErrInvalidCredentials
}

// productionParams builds Params the way the production entry point does: the
// core auth manager and its cooldown store come from NewCoreAuthManager over
// the token store the gateway is given. The store is upstream's file store
// over the configured auth directory: a real coreauth.Store, which the tests
// read back through List (storedCredential), never from the directory.
func productionParams(t *testing.T) gateway.Params {
	t.Helper()

	authDir := t.TempDir()

	return paramsOver(authDir, authDir)
}

// grantsVolumeParams is productionParams as this release runs: the token
// store (the database in production) lives apart from the auth directory,
// which is the grants volume still holding the previous release's credential
// files.
func grantsVolumeParams(t *testing.T) gateway.Params {
	t.Helper()

	return paramsOver(t.TempDir(), t.TempDir())
}

// paramsOver builds Params with authDir as the configured auth directory and
// upstream's file store over storeDir as the token store.
func paramsOver(authDir, storeDir string) gateway.Params {
	cfg := &cliproxyconfig.Config{AuthDir: authDir}
	store := sdkauth.NewFileTokenStore()
	store.SetBaseDir(storeDir)

	manager, cooldown := gateway.NewCoreAuthManager(cfg, store)

	return gateway.Params{
		Config:   cfg,
		CoreAuth: manager,
		Store:    store,
		Cooldown: cooldown,
	}
}

// storedCredential returns the credential store lists under id — the account
// a restart would load — and whether it lists one.
func storedCredential(t *testing.T, store coreauth.Store, id string) (*coreauth.Auth, bool) {
	t.Helper()

	listed, err := store.List(context.Background())
	require.NoError(t, err, "list the token store")

	for _, auth := range listed {
		if auth.ID == id {
			return auth, true
		}
	}

	return nil, false
}

// startProduction starts a gateway wired as production wires it, once boot
// has finished (startBooted).
func startProduction(t *testing.T) *running {
	t.Helper()

	return startBooted(t, productionParams(t))
}

// startBooted is startWith for a test that changes accounts straight after
// the gateway starts. Upstream goes on booting after the watcher exists and
// registers the models of every account the manager holds, reporting nowhere
// when it is done; an account change meanwhile would race it. So the token
// store holds one credential before boot, and startBooted returns once its
// models are in the registry.
func startBooted(t *testing.T, params gateway.Params) *running {
	t.Helper()

	boot := claudeGrantNamed(t, "boot-"+strconv.FormatInt(bootSeq.Add(1), 10))
	_, err := params.Store.Save(context.Background(), boot)
	require.NoError(t, err, "save the boot credential")

	srv := startWith(t, params)

	for deadline := time.Now().Add(10 * time.Second); registeredModels(boot.ID) == 0; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			require.Fail(t, "boot never registered the models of the account it loaded")
		}
	}

	return srv
}

// claudeGrant is a Claude OAuth account. Claude models come from upstream's
// static catalogue, so registering one needs no network; the token is valid
// for two days so nothing tries to refresh it.
func claudeGrant(t *testing.T) *coreauth.Auth {
	t.Helper()

	return claudeGrantNamed(t, t.Name())
}

// claudeGrantNamed is claudeGrant for a test that needs more than one account.
func claudeGrantNamed(t *testing.T, name string) *coreauth.Auth {
	t.Helper()

	id := "claude-" + strings.ToLower(name) + ".json"
	// The model registry is process-global; never leave this account's models
	// behind for a later test.
	t.Cleanup(func() { cliproxy.GlobalModelRegistry().UnregisterClient(id) })

	return &coreauth.Auth{
		ID:       id,
		FileName: id,
		Provider: "claude",
		Status:   coreauth.StatusActive,
		Metadata: map[string]any{
			"type":         "claude",
			"access_token": "fake-claude-access-token",
			"expired":      time.Now().Add(48 * time.Hour).Format(time.RFC3339),
		},
	}
}

// registeredModels is what upstream routes on: the models the global registry
// holds for account id.
func registeredModels(id string) int {
	return len(cliproxy.GlobalModelRegistry().GetModelsForClient(id))
}

// startWith brings a gateway up on an ephemeral port and blocks until it
// serves requests. It is stopped before the test ends. A gateway without a
// Resolver refuses every credential.
func startWith(t *testing.T, params gateway.Params) *running {
	t.Helper()
	// A non-empty MANAGEMENT_PASSWORD makes gateway.New refuse to build, because it
	// would enable upstream's management surface; pin it so no test depends on
	// the ambient environment.
	t.Setenv("MANAGEMENT_PASSWORD", "")

	port := freePort(t)

	params.Config.Port = port
	if params.Config.AuthDir == "" {
		params.Config.AuthDir = t.TempDir()
	}

	if params.Resolver == nil {
		params.Resolver = refuseAll{}
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

	waitHealthy(t, "http://"+net.JoinHostPort("", strconv.Itoa(port)))

	return &running{gateway: gw}
}

// watcherStarted is what upstream logs right after handing the watcher its
// configuration (service_lifecycle.go:204).
const watcherStarted = "file watcher started for config and auth directory changes"

// watchWatcherStarted returns a channel closed when upstream next logs
// watcherStarted, through a hook on the standard logger it logs to, removed
// when the test ends. Tests are serial, so the next such line is from the
// gateway the caller starts.
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
