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

	"github.com/gin-gonic/gin"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	cliproxyconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"

	"github.com/elleqt/llm-proxy-backend/internal/infra/gateway/faketest"
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
func startWith(t *testing.T, p Params) *running {
	t.Helper()
	// A non-empty MANAGEMENT_PASSWORD makes New refuse to build, because it
	// would enable upstream's management surface; pin it so no test depends on
	// the ambient environment.
	t.Setenv("MANAGEMENT_PASSWORD", "")

	port := freePort(t)
	p.Config.Port = port
	if p.Config.AuthDir == "" {
		p.Config.AuthDir = t.TempDir()
	}
	if p.Resolver == nil {
		p.Resolver = wireResolver
	}
	// The path is required by the upstream builder but must never be created:
	// configuration arrives through PushConfig, not from disk.
	p.ConfigPath = filepath.Join(t.TempDir(), "unused.yaml")

	g, err := New(p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- g.Run(ctx) }()

	var once sync.Once
	var stopErr error
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
	if err := g.WaitReload(waitCtx); err != nil {
		t.Fatalf("watcher was never created: %v", err)
	}

	r := &running{
		gateway:    g,
		baseURL:    "http://" + net.JoinHostPort("", strconv.Itoa(port)),
		configPath: p.ConfigPath,
		stop:       stop,
	}
	waitHealthy(t, r.baseURL)
	return r
}

// freePort reserves and releases a port so the gateway can bind it.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatalf("release port: %v", err)
	}
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
			t.Fatalf("gateway never became healthy, last status %d", code)
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
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatalf("build request %s %s: %v", method, url, err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, ""
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body of %s %s: %v", method, url, err)
	}
	return resp.StatusCode, string(body)
}

func TestGatewayStartsAndStopsCleanly(t *testing.T) {
	r := start(t, &cliproxyconfig.Config{})

	if code, _ := get(t, r.baseURL+"/healthz"); code != http.StatusOK {
		t.Fatalf("GET /healthz = %d, want %d", code, http.StatusOK)
	}

	if err := r.stop(); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v, want context.Canceled", err)
	}
	if code, _ := get(t, r.baseURL+"/healthz"); code != 0 {
		t.Fatalf("GET /healthz after stop = %d, want a connection failure", code)
	}
	if err := r.gateway.PushConfig(&cliproxyconfig.Config{}); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("PushConfig after Run returned = %v, want ErrNotRunning", err)
	}
}

// TestPushConfigAppliesWithoutAFile: no configuration file is ever created.
// That the pushed value reaches the running server is
// TestPushedConfigReachesTheServer's job.
func TestPushConfigAppliesWithoutAFile(t *testing.T) {
	r := start(t, &cliproxyconfig.Config{})

	updated := &cliproxyconfig.Config{AuthDir: t.TempDir(), Port: r.gateway.CurrentConfig().Port}
	if err := r.gateway.PushConfig(updated); err != nil {
		t.Fatalf("PushConfig: %v", err)
	}
	if got := r.gateway.CurrentConfig(); got != updated {
		t.Fatalf("CurrentConfig did not return the pushed configuration")
	}
	if _, err := os.Stat(r.configPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("os.Stat(%q) = %v, want the config file never to exist", r.configPath, err)
	}
}

func TestPushConfigBeforeRunReportsNotRunning(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	g, err := New(Params{
		Config:     &cliproxyconfig.Config{AuthDir: t.TempDir()},
		ConfigPath: filepath.Join(t.TempDir(), "unused.yaml"),
		Resolver:   wireResolver,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := g.PushConfig(&cliproxyconfig.Config{}); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("PushConfig before Run = %v, want ErrNotRunning", err)
	}
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
		if code != http.StatusNotFound {
			t.Errorf("%s %s = %d (%s), want %d", probe.method, probe.path, code, body, http.StatusNotFound)
		}
	}

	// A served route on the same engine, so the 404s above cannot be explained
	// by the server being down.
	if code, _ := get(t, baseURL+"/healthz"); code != http.StatusOK {
		t.Fatalf("GET /healthz = %d, want %d", code, http.StatusOK)
	}
}

// TestControlPanelIsNotServed: with DisableControlPanel unset, upstream serves
// GET /management.html and on its first request downloads the panel from
// GitHub. A panel asset is planted where upstream looks for it
// (MANAGEMENT_STATIC_PATH), so the page would be served without any network
// access if the gate were open: a 404 can only come from the flag, at boot and
// after a push that tries to switch the panel back on.
func TestControlPanelIsNotServed(t *testing.T) {
	static := t.TempDir()
	if err := os.WriteFile(filepath.Join(static, "management.html"), []byte("<html>panel</html>"), 0o600); err != nil {
		t.Fatalf("plant panel asset: %v", err)
	}
	t.Setenv("MANAGEMENT_STATIC_PATH", static)

	r := start(t, &cliproxyconfig.Config{})
	if code, body := get(t, r.baseURL+"/management.html"); code != http.StatusNotFound {
		t.Fatalf("GET /management.html at boot = %d (%q), want %d", code, body, http.StatusNotFound)
	}

	reenable := &cliproxyconfig.Config{AuthDir: r.gateway.CurrentConfig().AuthDir, Port: r.gateway.CurrentConfig().Port}
	reenable.RemoteManagement.DisableControlPanel = false
	if err := r.gateway.PushConfig(reenable); err != nil {
		t.Fatalf("PushConfig: %v", err)
	}
	if code, body := get(t, r.baseURL+"/management.html"); code != http.StatusNotFound {
		t.Fatalf("GET /management.html after a push re-enabling it = %d (%q), want %d", code, body, http.StatusNotFound)
	}
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
	m := coreauth.NewManager(nil, nil, nil)
	m.RegisterExecutor(exec)
	if _, err := m.Register(context.Background(), &coreauth.Auth{
		ID:         "fake-credential",
		Provider:   exec.Provider,
		Status:     coreauth.StatusActive,
		Attributes: map[string]string{"type": "api_key"},
	}); err != nil {
		t.Fatalf("register fake credential: %v", err)
	}
	return m
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
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if string(resp.Payload) != string(exec.Payload) {
		t.Fatalf("payload = %q, want %q", resp.Payload, exec.Payload)
	}
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
	if err != nil {
		t.Fatalf("ExecuteStream: %v", err)
	}

	var got []string
	for chunk := range stream.Chunks {
		if chunk.Err != nil {
			t.Fatalf("stream chunk error: %v", chunk.Err)
		}
		got = append(got, string(chunk.Payload))
	}
	if len(got) != len(exec.Chunks) {
		t.Fatalf("received %d chunks (%q), want %d", len(got), got, len(exec.Chunks))
	}
	for i, want := range exec.Chunks {
		if got[i] != string(want) {
			t.Fatalf("chunk %d = %q, want %q", i, got[i], want)
		}
	}
}

func TestFakeExecutorReproducesFailures(t *testing.T) {
	want := errors.New("vendor is down")
	exec := &faketest.Executor{Provider: "fake-vendor-down", Err: want}
	m := fakeVendor(t, exec)

	if _, err := m.Execute(context.Background(), []string{exec.Provider},
		cliproxyexecutor.Request{}, cliproxyexecutor.Options{}); !errors.Is(err, want) {
		t.Fatalf("Execute error = %v, want %v", err, want)
	}

	midStream := errors.New("vendor hung up")
	streaming := &faketest.Executor{
		Provider:  "fake-vendor-halfdead",
		Chunks:    [][]byte{[]byte("data: one")},
		StreamErr: midStream,
	}
	sm := fakeVendor(t, streaming)
	stream, err := sm.ExecuteStream(context.Background(), []string{streaming.Provider},
		cliproxyexecutor.Request{}, cliproxyexecutor.Options{Stream: true})
	if err != nil {
		t.Fatalf("ExecuteStream: %v", err)
	}
	var last error
	chunks := 0
	for chunk := range stream.Chunks {
		if chunk.Err != nil {
			last = chunk.Err
			continue
		}
		chunks++
	}
	if chunks != 1 {
		t.Fatalf("received %d payload chunks, want 1", chunks)
	}
	if !errors.Is(last, midStream) {
		t.Fatalf("terminal chunk error = %v, want %v", last, midStream)
	}
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
	if err != nil {
		t.Fatalf("ExecuteStream: %v", err)
	}
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
			if len(got) != 1 || !errors.Is(got[0].Err, context.Canceled) || got[0].Payload != nil {
				t.Fatalf("stream delivered %+v before closing, want exactly one context.Canceled chunk", got)
			}
			return
		case <-deadline:
			t.Fatalf("producer did not close the stream after cancellation; received %+v", got)
		}
	}
}

// TestSuppliedCoreAuthManagerIsUsedByTheService proves Params.CoreAuth reaches
// the embedded service: on start-up the service registers its baseline provider
// executors into whichever manager it owns, so they land in ours.
func TestSuppliedCoreAuthManagerIsUsedByTheService(t *testing.T) {
	m := coreauth.NewManager(nil, nil, nil)
	if _, ok := m.Executor("claude"); ok {
		t.Fatal("fresh manager already carries a baseline executor")
	}

	startWith(t, Params{Config: &cliproxyconfig.Config{}, CoreAuth: m})

	if _, ok := m.Executor("claude"); !ok {
		t.Fatal("supplied core auth manager received no executors; the service built its own")
	}
}

// TestMiddlewareIsAppliedToRequests: Params.Middleware runs on requests the
// policy gate admits.
func TestMiddlewareIsAppliedToRequests(t *testing.T) {
	r := startWith(t, Params{
		Config: &cliproxyconfig.Config{},
		Middleware: []gin.HandlerFunc{func(c *gin.Context) {
			c.Header("X-Gateway-Middleware", "applied")
			c.Next()
		}},
	})

	resp, err := http.Get(r.baseURL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got := resp.Header.Get("X-Gateway-Middleware"); got != "applied" {
		t.Fatalf("X-Gateway-Middleware = %q, want %q", got, "applied")
	}
}

// TestNewCoreAuthManagerUsesTheAuthDirectory proves the manager it returns
// persists credentials into the supplied directory, which is what the upstream
// builder's default path arranges via SetBaseDir. The cooldown store is nil
// here because the default file token store does not implement
// coreauth.CooldownStateStoreProvider — the upstream default path gets nil too.
func TestNewCoreAuthManagerUsesTheAuthDirectory(t *testing.T) {
	authDir := t.TempDir()
	m, _, _ := NewCoreAuthManager(&cliproxyconfig.Config{AuthDir: authDir})
	if m == nil {
		t.Fatal("NewCoreAuthManager returned no manager")
	}

	if _, err := m.Register(context.Background(), &coreauth.Auth{
		ID:       "persisted-credential.json",
		Provider: "fake-vendor",
		Status:   coreauth.StatusActive,
		FileName: "persisted-credential.json",
		Metadata: map[string]any{"access_token": "fake-token"},
	}); err != nil {
		t.Fatalf("register: %v", err)
	}

	entries, err := os.ReadDir(authDir)
	if err != nil {
		t.Fatalf("read auth dir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatalf("no credential was written to %q; the auth directory was not applied", authDir)
	}
}

// TestPushConfigCannotEnableManagement: a remote-management secret key is what
// makes upstream register /v0/management on reload, and in later tasks the
// pushed configuration is built from operator-editable rows.
func TestPushConfigCannotEnableManagement(t *testing.T) {
	r := start(t, &cliproxyconfig.Config{})
	before := r.gateway.CurrentConfig()

	withSecret := &cliproxyconfig.Config{AuthDir: t.TempDir(), Port: before.Port}
	withSecret.RemoteManagement.SecretKey = "operator-supplied-secret"
	if err := r.gateway.PushConfig(withSecret); !errors.Is(err, ErrManagementSecret) {
		t.Fatalf("PushConfig with a secret key = %v, want ErrManagementSecret", err)
	}
	if r.gateway.CurrentConfig() != before {
		t.Fatal("CurrentConfig reports the rejected configuration")
	}
	assertManagementUnrouted(t, r.baseURL)

	initial := &cliproxyconfig.Config{AuthDir: t.TempDir()}
	initial.RemoteManagement.SecretKey = "operator-supplied-secret"
	if _, err := New(Params{Config: initial, ConfigPath: filepath.Join(t.TempDir(), "unused.yaml")}); !errors.Is(err, ErrManagementSecret) {
		t.Fatalf("New with a secret key = %v, want ErrManagementSecret", err)
	}
}

// TestWaitReloadReportsABootFailure: upstream's Run returns before creating the
// watcher when the auth directory is unusable, so the reload callback never
// arrives. WaitReload must hand back Run's error rather than wait out ctx.
func TestWaitReloadReportsABootFailure(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	notADir := filepath.Join(t.TempDir(), "auth-file")
	if err := os.WriteFile(notADir, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	g, err := New(Params{
		Config:     &cliproxyconfig.Config{Port: freePort(t), AuthDir: notADir},
		ConfigPath: filepath.Join(t.TempDir(), "unused.yaml"),
		Resolver:   wireResolver,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- g.Run(ctx) }()

	waitCtx, cancelWait := context.WithTimeout(ctx, 30*time.Second)
	defer cancelWait()
	waitErr := g.WaitReload(waitCtx)

	var ran error
	select {
	case ran = <-runErr:
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not return on an unusable auth directory")
	}
	if ran == nil {
		t.Fatal("Run returned nil on an unusable auth directory")
	}
	if !errors.Is(waitErr, ran) {
		t.Fatalf("WaitReload = %v, want Run's error %v", waitErr, ran)
	}
	if err := g.PushConfig(&cliproxyconfig.Config{}); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("PushConfig after a failed boot = %v, want ErrNotRunning", err)
	}
}
