package gateway

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/infra/gateway/faketest"
	"github.com/gin-gonic/gin"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	cliproxyconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// running is a started gateway plus the handles a test needs to talk to it.
type running struct {
	gateway    *Gateway
	baseURL    string
	configPath string
	stop       func() error
}

// start brings a gateway up on an ephemeral port and blocks until it serves
// requests. Stopping is idempotent and always happens before the test ends.
func start(t *testing.T, cfg *cliproxyconfig.Config) *running {
	t.Helper()

	return startWith(t, Params{Config: cfg})
}

// startWith is start for tests that need to exercise other Params seams. A
// gateway without a Resolver gets wireResolver.
func startWith(t *testing.T, params Params) *running {
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

	if params.Resolver == nil {
		params.Resolver = wireResolver
	}
	// The path is required by the upstream builder but must never be created:
	// configuration arrives through PushConfig, not from disk.
	params.ConfigPath = filepath.Join(t.TempDir(), "unused.yaml")

	booted := watchWatcherStarted(t)

	gw, err := New(params)
	require.NoError(t, err, "New")

	ctx, cancel := context.WithCancel(context.Background())

	runErr := make(chan error, 1)
	go func() { runErr <- gw.Run(ctx) }()

	var (
		once    sync.Once
		stopErr error
	)

	stop := func() error {
		once.Do(func() {
			cancel()

			select {
			case stopErr = <-runErr:
			case <-time.After(30 * time.Second):
				stopErr = errors.New("gateway did not stop within 30s")
			}
		})

		return stopErr
	}

	t.Cleanup(func() { _ = stop() })

	waitCtx, cancelWait := context.WithTimeout(ctx, 20*time.Second)
	defer cancelWait()

	err = gw.WaitReload(waitCtx)
	require.NoError(t, err, "watcher was never created")
	// WaitReload returns as the watcher is created; Run then reads the
	// service configuration unlocked to hand it to the watcher
	// (service_lifecycle.go:196), and a push writing it would race that read
	// however much later it came, with nothing ordering the two. Its next
	// step logs, which orders everything before it ahead of a push.
	select {
	case <-booted:
	case <-waitCtx.Done():
		require.Fail(t, "upstream never logged that it started the watcher")
	}

	srv := &running{
		gateway:    gw,
		baseURL:    "http://" + net.JoinHostPort("", strconv.Itoa(port)),
		configPath: params.ConfigPath,
		stop:       stop,
	}
	waitHealthy(t, srv.baseURL)

	return srv
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

func waitHealthy(t *testing.T, baseURL string) {
	t.Helper()

	deadline := time.Now().Add(20 * time.Second)

	for {
		code, _ := get(t, baseURL+"/healthz")
		if code == http.StatusOK {
			return
		}

		if time.Now().After(deadline) {
			require.Failf(t, "gateway never became healthy", "last status %d", code)
		}

		time.Sleep(20 * time.Millisecond)
	}
}

// get returns the status code, or 0 when the request could not be made.
func get(t *testing.T, url string) (int, string) {
	t.Helper()

	return do(t, http.MethodGet, url)
}

func do(t *testing.T, method, url string) (int, string) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), method, url, http.NoBody)
	require.NoError(t, err, "build request %s %s", method, url)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, ""
	}

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "read body of %s %s", method, url)

	return resp.StatusCode, string(body)
}

func TestGatewayStartsAndStopsCleanly(t *testing.T) {
	srv := start(t, &cliproxyconfig.Config{})

	code, _ := get(t, srv.baseURL+"/healthz")
	require.Equal(t, http.StatusOK, code, "GET /healthz")

	require.ErrorIs(t, srv.stop(), context.Canceled, "Run returned")

	code, _ = get(t, srv.baseURL+"/healthz")
	require.Zero(t, code, "GET /healthz after stop: want a connection failure")

	err := srv.gateway.PushConfig(&cliproxyconfig.Config{})
	require.ErrorIs(t, err, ErrNotRunning, "PushConfig after Run returned")
}

// TestPushConfigAppliesWithoutAFile: no configuration file is ever created.
// That the pushed value reaches the running server is
// TestPushedConfigReachesTheServer's job.
func TestPushConfigAppliesWithoutAFile(t *testing.T) {
	srv := start(t, &cliproxyconfig.Config{})

	updated := &cliproxyconfig.Config{AuthDir: t.TempDir(), Port: srv.gateway.CurrentConfig().Port}
	err := srv.gateway.PushConfig(updated)
	require.NoError(t, err, "PushConfig")

	require.Same(t, updated, srv.gateway.CurrentConfig(), "CurrentConfig did not return the pushed configuration")

	_, err = os.Stat(srv.configPath)
	require.ErrorIs(t, err, os.ErrNotExist, "os.Stat(%q): want the config file never to exist", srv.configPath)
}

func TestPushConfigBeforeRunReportsNotRunning(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")

	gw, err := New(Params{
		Config:     &cliproxyconfig.Config{AuthDir: t.TempDir()},
		ConfigPath: filepath.Join(t.TempDir(), "unused.yaml"),
		Resolver:   wireResolver,
	})
	require.NoError(t, err, "New")

	err = gw.PushConfig(&cliproxyconfig.Config{})
	require.ErrorIs(t, err, ErrNotRunning, "PushConfig before Run")
}

// TestManagementRoutesAreNotRouted guards the constraint that /v0/management is
// never reachable. Upstream registers those routes only when a secret key, an
// environment secret or a local management password is configured, and this
// package supplies none; the assertion is here because that conditional lives
// upstream and could change under us.
func TestManagementRoutesAreNotRouted(t *testing.T) {
	r := start(t, &cliproxyconfig.Config{})
	assertManagementUnrouted(t, r.baseURL)
}

func assertManagementUnrouted(t *testing.T, baseURL string) {
	t.Helper()

	for _, probe := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/v0/management"},
		{http.MethodGet, "/v0/management/config"},
		{http.MethodPut, "/v0/management/config"},
		{http.MethodGet, "/v0/management/auth-files"},
		{http.MethodPost, "/v0/management/oauth-callback"},
	} {
		code, body := do(t, probe.method, baseURL+probe.path)
		assert.Equal(t, http.StatusNotFound, code, "%s %s (%s)", probe.method, probe.path, body)
	}

	// A served route on the same engine, so the 404s above cannot be explained
	// by the server being down.
	code, _ := get(t, baseURL+"/healthz")
	require.Equal(t, http.StatusOK, code, "GET /healthz")
}

// TestControlPanelIsNotServed: with DisableControlPanel unset, upstream serves
// GET /management.html and on its first request downloads the panel from
// GitHub. A panel asset is planted where upstream looks for it
// (MANAGEMENT_STATIC_PATH), so the page would be served without any network
// access if the gate were open: a 404 can only come from the flag, at boot and
// after a push that tries to switch the panel back on.
func TestControlPanelIsNotServed(t *testing.T) {
	static := t.TempDir()
	err := os.WriteFile(filepath.Join(static, "management.html"), []byte("<html>panel</html>"), 0o600)
	require.NoError(t, err, "plant panel asset")

	t.Setenv("MANAGEMENT_STATIC_PATH", static)

	srv := start(t, &cliproxyconfig.Config{})
	code, body := get(t, srv.baseURL+"/management.html")
	require.Equal(t, http.StatusNotFound, code, "GET /management.html at boot (%q)", body)

	reenable := &cliproxyconfig.Config{AuthDir: srv.gateway.CurrentConfig().AuthDir, Port: srv.gateway.CurrentConfig().Port}

	reenable.RemoteManagement.DisableControlPanel = false
	err = srv.gateway.PushConfig(reenable)
	require.NoError(t, err, "PushConfig")

	code, body = get(t, srv.baseURL+"/management.html")
	require.Equal(t, http.StatusNotFound, code, "GET /management.html after a push re-enabling it (%q)", body)
}

// fakeVendor wires the fake executor into a real upstream auth manager, for
// conductor-level tests only. No HTTP request reaches this path: a request
// resolves its provider from the global model registry by model name, and every
// configuration application replaces executors with upstream's own. The HTTP
// path is covered by faketest.Vendor below.
//
// The route model is left empty on purpose: matching a named model requires the
// upstream global model registry, which lives under internal/ and must not be
// imported. An empty route model makes the conductor select purely on provider.
func fakeVendor(t *testing.T, exec *faketest.Executor) *coreauth.Manager {
	t.Helper()

	manager := coreauth.NewManager(nil, nil, nil)
	manager.RegisterExecutor(exec)

	_, err := manager.Register(context.Background(), &coreauth.Auth{
		ID:         "fake-credential",
		Provider:   exec.Provider,
		Status:     coreauth.StatusActive,
		Attributes: map[string]string{"type": "api_key"},
	})
	require.NoError(t, err, "register fake credential")

	return manager
}

func TestFakeExecutorServesNonStreamingResponse(t *testing.T) {
	exec := &faketest.Executor{
		Provider: "fake-vendor",
		Payload:  []byte(`{"choices":[{"message":{"content":"hello"}}]}`),
		Latency:  time.Millisecond,
	}
	m := fakeVendor(t, exec)

	resp, err := m.Execute(context.Background(), []string{exec.Provider},
		cliproxyexecutor.Request{Payload: []byte(`{"messages":[]}`)},
		cliproxyexecutor.Options{})
	require.NoError(t, err, "Execute")

	require.Equal(t, exec.Payload, resp.Payload, "payload")
}

func TestFakeExecutorServesStreamingResponse(t *testing.T) {
	exec := &faketest.Executor{
		Provider: "fake-vendor-stream",
		Chunks:   [][]byte{[]byte("data: one"), []byte("data: two"), []byte("data: [DONE]")},
		Latency:  time.Millisecond,
	}
	m := fakeVendor(t, exec)

	stream, err := m.ExecuteStream(context.Background(), []string{exec.Provider},
		cliproxyexecutor.Request{Payload: []byte(`{"stream":true}`)},
		cliproxyexecutor.Options{Stream: true})
	require.NoError(t, err, "ExecuteStream")

	var got []string

	for chunk := range stream.Chunks {
		require.NoError(t, chunk.Err, "stream chunk error")

		got = append(got, string(chunk.Payload))
	}

	require.Len(t, got, len(exec.Chunks), "received chunks %q", got)

	for i, want := range exec.Chunks {
		require.Equal(t, string(want), got[i], "chunk %d", i)
	}
}

func TestFakeExecutorReproducesFailures(t *testing.T) {
	want := errors.New("vendor is down")
	exec := &faketest.Executor{Provider: "fake-vendor-down", Err: want}
	m := fakeVendor(t, exec)

	_, err := m.Execute(context.Background(), []string{exec.Provider},
		cliproxyexecutor.Request{}, cliproxyexecutor.Options{})
	require.ErrorIs(t, err, want, "Execute error")

	midStream := errors.New("vendor hung up")
	streaming := &faketest.Executor{
		Provider:  "fake-vendor-halfdead",
		Chunks:    [][]byte{[]byte("data: one")},
		StreamErr: midStream,
	}
	sm := fakeVendor(t, streaming)

	stream, err := sm.ExecuteStream(context.Background(), []string{streaming.Provider},
		cliproxyexecutor.Request{}, cliproxyexecutor.Options{Stream: true})
	require.NoError(t, err, "ExecuteStream")

	var last error

	chunks := 0

	for chunk := range stream.Chunks {
		if chunk.Err != nil {
			last = chunk.Err

			continue
		}

		chunks++
	}

	require.Equal(t, 1, chunks, "payload chunks received")
	require.ErrorIs(t, last, midStream, "terminal chunk error")
}

// TestFakeExecutorStopsStreamingWhenContextIsCancelled tests the double's own
// contract, so it calls the executor directly: the conductor would wait on the
// first chunk, which a latency of an hour never delivers. The producer
// goroutine is the only closer of the channel, so observing the close proves it
// exited rather than leaking.
func TestFakeExecutorStopsStreamingWhenContextIsCancelled(t *testing.T) {
	exec := &faketest.Executor{
		Provider: "fake-vendor-slow",
		Chunks:   [][]byte{[]byte("data: one"), []byte("data: two")},
		Latency:  time.Hour,
	}
	ctx, cancel := context.WithCancel(context.Background())

	stream, err := exec.ExecuteStream(ctx, nil, cliproxyexecutor.Request{}, cliproxyexecutor.Options{Stream: true})
	require.NoError(t, err, "ExecuteStream")

	cancel()

	var got []cliproxyexecutor.StreamChunk

	deadline := time.After(10 * time.Second)

	for {
		select {
		case chunk, ok := <-stream.Chunks:
			if ok {
				got = append(got, chunk)

				continue
			}

			const want = "want exactly one context.Canceled chunk"
			require.Len(t, got, 1, "stream delivered %+v before closing, %s", got, want)
			require.ErrorIs(t, got[0].Err, context.Canceled, "stream delivered %+v before closing, %s", got, want)
			require.Nil(t, got[0].Payload, "stream delivered %+v before closing, %s", got, want)

			return
		case <-deadline:
			require.Failf(t, "producer did not close the stream after cancellation", "received %+v", got)
		}
	}
}

// TestSuppliedCoreAuthManagerIsUsedByTheService proves Params.CoreAuth reaches
// the embedded service: on start-up the service registers its baseline provider
// executors into whichever manager it owns, so they land in ours.
func TestSuppliedCoreAuthManagerIsUsedByTheService(t *testing.T) {
	manager := coreauth.NewManager(nil, nil, nil)
	_, ok := manager.Executor("claude")
	require.False(t, ok, "fresh manager already carries a baseline executor")

	startWith(t, Params{Config: &cliproxyconfig.Config{}, CoreAuth: manager})

	_, ok = manager.Executor("claude")
	require.True(t, ok, "supplied core auth manager received no executors; the service built its own")
}

// TestMiddlewareIsAppliedToRequests: Params.Middleware runs on requests the
// policy gate admits.
func TestMiddlewareIsAppliedToRequests(t *testing.T) {
	srv := startWith(t, Params{
		Config: &cliproxyconfig.Config{},
		Middleware: []gin.HandlerFunc{func(c *gin.Context) {
			c.Header("X-Gateway-Middleware", "applied")
			c.Next()
		}},
	})

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.baseURL+"/healthz", http.NoBody)
	require.NoError(t, err, "build GET /healthz")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err, "GET /healthz")

	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, "applied", resp.Header.Get("X-Gateway-Middleware"), "X-Gateway-Middleware")
}

// TestNewCoreAuthManagerUsesTheAuthDirectory proves the manager it returns
// persists credentials into the supplied directory, which is what the upstream
// builder's default path arranges via SetBaseDir. The cooldown store is nil
// here because the default file token store does not implement
// coreauth.CooldownStateStoreProvider — the upstream default path gets nil too.
func TestNewCoreAuthManagerUsesTheAuthDirectory(t *testing.T) {
	authDir := t.TempDir()

	m, _, _ := NewCoreAuthManager(&cliproxyconfig.Config{AuthDir: authDir})
	require.NotNil(t, m, "NewCoreAuthManager returned no manager")

	_, err := m.Register(context.Background(), &coreauth.Auth{
		ID:       "persisted-credential.json",
		Provider: "fake-vendor",
		Status:   coreauth.StatusActive,
		FileName: "persisted-credential.json",
		Metadata: map[string]any{"access_token": "fake-token"},
	})
	require.NoError(t, err, "register")

	entries, err := os.ReadDir(authDir)
	require.NoError(t, err, "read auth dir")

	require.NotEmpty(t, entries, "no credential was written to %q; the auth directory was not applied", authDir)
}

// TestPushConfigCannotEnableManagement: a remote-management secret key is what
// makes upstream register /v0/management on reload, and in later tasks the
// pushed configuration is built from operator-editable rows.
func TestPushConfigCannotEnableManagement(t *testing.T) {
	srv := start(t, &cliproxyconfig.Config{})
	before := srv.gateway.CurrentConfig()

	withSecret := &cliproxyconfig.Config{AuthDir: t.TempDir(), Port: before.Port}

	withSecret.RemoteManagement.SecretKey = "operator-supplied-secret"
	err := srv.gateway.PushConfig(withSecret)
	require.ErrorIs(t, err, ErrManagementSecret, "PushConfig with a secret key")

	require.Same(t, before, srv.gateway.CurrentConfig(), "CurrentConfig reports the rejected configuration")

	assertManagementUnrouted(t, srv.baseURL)

	initial := &cliproxyconfig.Config{AuthDir: t.TempDir()}

	initial.RemoteManagement.SecretKey = "operator-supplied-secret"
	_, err = New(Params{Config: initial, ConfigPath: filepath.Join(t.TempDir(), "unused.yaml")})
	require.ErrorIs(t, err, ErrManagementSecret, "New with a secret key")
}

// TestWaitReloadReportsABootFailure: upstream's Run returns before creating the
// watcher when the auth directory is unusable, so the reload callback never
// arrives. WaitReload must hand back Run's error rather than wait out ctx.
func TestWaitReloadReportsABootFailure(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")

	notADir := filepath.Join(t.TempDir(), "auth-file")
	err := os.WriteFile(notADir, nil, 0o600)
	require.NoError(t, err, "create file")

	gw, err := New(Params{
		Config:     &cliproxyconfig.Config{Port: freePort(t), AuthDir: notADir},
		ConfigPath: filepath.Join(t.TempDir(), "unused.yaml"),
		Resolver:   wireResolver,
	})
	require.NoError(t, err, "New")

	ctx := t.Context()

	runErr := make(chan error, 1)
	go func() { runErr <- gw.Run(ctx) }()

	waitCtx, cancelWait := context.WithTimeout(ctx, 30*time.Second)
	defer cancelWait()

	waitErr := gw.WaitReload(waitCtx)

	var ran error
	select {
	case ran = <-runErr:
	case <-time.After(30 * time.Second):
		require.Fail(t, "Run did not return on an unusable auth directory")
	}

	require.Error(t, ran, "Run returned nil on an unusable auth directory")
	require.ErrorIs(t, waitErr, ran, "WaitReload: want Run's error")

	err = gw.PushConfig(&cliproxyconfig.Config{})
	require.ErrorIs(t, err, ErrNotRunning, "PushConfig after a failed boot")
}
