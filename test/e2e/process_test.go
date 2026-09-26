package e2e

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/iface/http/api"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// TestTheProcessKeepsItsListenersApartAndStopsCleanly is the process as an
// operator runs it: each listener serves only its own API, metrics only on the
// metrics listener, the gate's refusals counted there, the routing strategy an
// administrator stored in force from boot, and a SIGTERM lets the proxied
// request in flight finish before Run returns cleanly.
func TestTheProcessKeepsItsListenersApartAndStopsCleanly(t *testing.T) {
	if !inFreshProcess(t) {
		return
	}

	proc := startProcess(t, "routing:\n  strategy: fill-first\n", nil)
	proc.signInAsBootstrapAdmin(t)
	secret := proc.issueToken(t, "ops").Secret
	proc.setPolicy(t, proc.adminEmail, proc.a.policyName+":*", proc.b.policyName+":*")
	eventually(t, "both vendors' models are listed", func() bool {
		m := proc.models(t, secret)

		return m[proc.a.alias] && m[proc.b.alias]
	})

	// The proxied listener serves no web API, the web listener no proxied API,
	// and neither serves metrics: each answers 404 as for any unknown path.
	for _, tc := range []struct{ method, target, body string }{
		{http.MethodGet, proc.apiURL + "/api/auth/config", ""},
		{http.MethodGet, proc.apiURL + "/api/me", ""},
		{http.MethodPost, proc.apiURL + "/api/auth/login", `{"email":"` + proc.adminEmail + `","password":"a password I chose myself"}`},
		{http.MethodGet, proc.apiURL + "/api/admin/users", ""},
		{http.MethodGet, proc.apiURL + "/metrics", ""},
		{http.MethodGet, proc.webURL + "/v1/models", ""},
		{http.MethodPost, proc.webURL + "/v1/chat/completions", `{"model":"` + proc.a.alias + `","messages":[{"role":"user","content":"hi"}]}`},
		{http.MethodGet, proc.webURL + "/metrics", ""},
		{http.MethodGet, proc.metricsURL + "/v1/models", ""},
		{http.MethodGet, proc.metricsURL + "/api/auth/config", ""},
	} {
		code, body := send(t, tc.method, tc.target, secret, tc.body)
		require.Equal(t, http.StatusNotFound, code, "%s %s (%s)", tc.method, tc.target, body)
	}

	// The strategy stored in the settings is the one routing requests, with no
	// configuration pushed since boot: fill-first keeps every request on vendor
	// A's first key, where the default round-robin would alternate between both.
	for range 4 {
		require.Equal(t, http.StatusOK, proc.chat(t, secret, proc.a.alias), "POST /v1/chat/completions (A)")
	}

	keys := map[string]bool{}
	for _, r := range proc.a.fake.Requests() {
		keys[r.Header.Get("Authorization")] = true
	}

	require.Len(t, keys, 1, "vendor A's keys over 4 requests; the stored fill-first strategy is not in force")

	// The metrics listener exposes the service's families, the usage sink's
	// health counters among them, the requests just served, and the gate's
	// refusals under the refused user.
	require.Equal(t, http.StatusForbidden, proc.chat(t, secret, "e2e-model-nobody-serves"), "a model no vendor serves")

	eventually(t, "the served requests are counted", func() bool { return proc.metricFamilies(t)["llmproxy_requests_total"] })

	families := proc.metricFamilies(t)
	for _, want := range []string{"llmproxy_build_info", "llmproxy_usage_dropped_total", "llmproxy_usage_panics_total"} {
		require.True(t, families[want], "metrics families %v lack %s", families, want)
	}

	denied := `llmproxy_policy_denied_total{model="unknown",reason="unknown_model",user="` + proc.adminEmail + `"} 1`
	require.Contains(t, proc.scrapeMetrics(t), denied, "metrics lack the gate's refusal")

	// SIGTERM while a request is with the slow vendor: the request completes
	// before Run returns, and Run returns without error.
	inFlight := proc.sendSlowRequest(t, secret)
	eventually(t, "the request reaches vendor B", func() bool { return len(proc.b.fake.Requests()) == 1 })

	require.NoError(t, syscall.Kill(os.Getpid(), syscall.SIGTERM))
	require.NoError(t, proc.awaitReturn(60*time.Second), "Run after SIGTERM")

	select {
	case res := <-inFlight:
		require.Equal(t, "200 OK", res.status, "the request in flight at SIGTERM")
		// The client reads the last bytes a moment after the server has
		// written them; a stop that did not wait would return a whole vendor
		// latency earlier. Half that latency is the margin: wide enough for a
		// loaded runner under -race, far short of what an undrained stop shows.
		require.LessOrEqual(t, res.at.Sub(proc.returnedAt), slowVendorLatency/2,
			"the request in flight at SIGTERM completed that long after Run returned: it was not drained")
	case <-time.After(slowVendorLatency + 5*time.Second):
		require.Fail(t, "the request in flight at SIGTERM never completed")
	}

	for _, target := range []string{proc.apiURL + "/healthz", proc.webURL + "/api/auth/config", proc.metricsURL + "/metrics"} {
		if resp, err := get(t, target); err == nil {
			_ = resp.Body.Close()
			require.Failf(t, "a listener outlived Run", "GET %s after Run returned: %d, want the listener closed", target, resp.StatusCode)
		}
	}
}

// TestASecondSignalEndsTheProcessAtOnce: while the process drains after a
// SIGTERM, a second SIGTERM is not caught — it ends the process by the signal,
// without waiting for the drain.
func TestASecondSignalEndsTheProcessAtOnce(t *testing.T) {
	if !isChild() {
		out, err := runChild(t)

		var exit *exec.ExitError
		require.ErrorAs(t, err, &exit, "want killed by the second SIGTERM\n%s", out)

		status, ok := exit.Sys().(syscall.WaitStatus)
		require.True(t, ok, "the process ended with %v, want killed by the second SIGTERM\n%s", err, out)
		require.True(t, status.Signaled(), "the process ended with %v, want killed by the second SIGTERM\n%s", err, out)
		require.Equal(t, syscall.SIGTERM, status.Signal(), "the process ended with %v, want killed by the second SIGTERM\n%s", err, out)

		return
	}

	proc := startProcess(t, "", nil)
	proc.signInAsBootstrapAdmin(t)
	secret := proc.issueToken(t, "ops").Secret
	proc.setPolicy(t, proc.adminEmail, proc.b.policyName+":*")
	eventually(t, "vendor B's model is listed", func() bool { return proc.models(t, secret)[proc.b.alias] })

	proc.sendSlowRequest(t, secret)
	eventually(t, "the request reaches vendor B", func() bool { return len(proc.b.fake.Requests()) == 1 })

	require.NoError(t, syscall.Kill(os.Getpid(), syscall.SIGTERM))

	eventually(t, "the process begins to stop", func() bool { return strings.Contains(proc.out.String(), "stopping") })

	require.NoError(t, syscall.Kill(os.Getpid(), syscall.SIGTERM))
	// Only reached if the second signal was caught.
	err := proc.awaitReturn(60 * time.Second)
	require.Failf(t, "the process outlived a second SIGTERM", "Run returned %v after draining", err)
}

// slowResult is how a request to the slow vendor ended, and when.
type slowResult struct {
	status string
	at     time.Time
}

// sendSlowRequest sends a chat completion to slow vendor B and reports how it
// ended. It fails no test itself: it runs off the test goroutine.
func (p *process) sendSlowRequest(t *testing.T, secret string) <-chan slowResult {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, p.apiURL+"/v1/chat/completions", strings.NewReader(
		`{"model":"`+p.b.alias+`","messages":[{"role":"user","content":"say hello"}]}`))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+secret)

	result := make(chan slowResult, 1)

	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			result <- slowResult{status: err.Error(), at: time.Now()}

			return
		}

		_, _ = io.Copy(io.Discard, resp.Body)

		_ = resp.Body.Close()
		result <- slowResult{status: resp.Status, at: time.Now()}
	}()

	return result
}

// TestLocalLoginOffLeavesOnlyFederatedSignIn: with LLMPROXY_LOCAL_LOGIN=false the
// login screen is told there is no password form and the password sign-in route
// does not exist, while the bootstrap administrator is still created — with a
// warning that it cannot sign in until local login is turned back on.
func TestLocalLoginOffLeavesOnlyFederatedSignIn(t *testing.T) {
	if !inFreshProcess(t) {
		return
	}

	proc := startProcess(t, "", map[string]string{"LLMPROXY_LOCAL_LOGIN": "false"})

	var cfg api.AuthConfig
	proc.webJSON(t, http.MethodGet, "/api/auth/config", "", http.StatusOK, &cfg)

	require.False(t, cfg.LocalLogin, "GET /api/auth/config offers the password form with local login off")

	var refused api.Error
	proc.webJSON(t, http.MethodPost, "/api/auth/login",
		`{"email":"`+proc.adminEmail+`","password":"`+proc.adminPassword+`"}`, http.StatusNotFound, &refused)

	require.Equal(t, "not_found", refused.Code, "POST /api/auth/login")
	require.Contains(t, proc.out.String(), "LLMPROXY_LOCAL_LOGIN is false", "no warning that the bootstrap administrator cannot sign in")
}

// catalogueHost is where upstream's model catalogue updaters fetch from first
// (internal/registry model_updater.go modelsURLs, v7.3.18), as a CONNECT asks
// for it.
const catalogueHost = "raw.githubusercontent.com:443"

// updaterStarts is what each of upstream's three model catalogue updaters logs
// once its first fetch is over, failed or not.
var updaterStarts = []string{
	"periodic model refresh started",
	"periodic Codex client model refresh started",
	"periodic Devin model refresh started",
}

// refusingProxy is an HTTP(S) proxy that refuses every request with 502 and
// records the hosts asked for, so nothing the process sends through it reaches
// the internet.
type refusingProxy struct {
	mu    sync.Mutex
	hosts []string
}

func (p *refusingProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.hosts = append(p.hosts, r.Host)
	p.mu.Unlock()
	w.WriteHeader(http.StatusBadGateway)
}

func (p *refusingProxy) asked() []string {
	p.mu.Lock()
	defer p.mu.Unlock()

	return slices.Clone(p.hosts)
}

// startBehindRefusingProxy boots the process with
// LLMPROXY_MODEL_CATALOG_UPDATES=updates and every outbound request not to a
// loopback address sent through a refusingProxy, which a refused fetch leaves
// the updaters to log updaterStarts at once. It returns the proxy and a hook per
// line of updaterStarts, installed before the process boots.
func startBehindRefusingProxy(t *testing.T, updates string) (*refusingProxy, []*logSeen) {
	t.Helper()

	proxy := &refusingProxy{}
	srv := httptest.NewServer(proxy)
	t.Cleanup(srv.Close)

	hooks := make([]*logSeen, len(updaterStarts))
	for i, msg := range updaterStarts {
		hooks[i] = &logSeen{msg: msg, seen: make(chan struct{})}
		logrus.AddHook(hooks[i])
	}

	startProcess(t, "", map[string]string{
		"LLMPROXY_MODEL_CATALOG_UPDATES": updates,
		"HTTPS_PROXY":                    srv.URL,
		"HTTP_PROXY":                     srv.URL,
		"NO_PROXY":                       "",
		"no_proxy":                       "",
	})

	return proxy, hooks
}

// TestModelCatalogUpdatersStartWhenOn: with LLMPROXY_MODEL_CATALOG_UPDATES on,
// the process starts all three of upstream's model catalogue updaters, which
// fetch the published catalogue. Each updater starts once per process, so this
// is the one boot with them on.
func TestModelCatalogUpdatersStartWhenOn(t *testing.T) {
	if !inFreshProcess(t) {
		return
	}

	proxy, hooks := startBehindRefusingProxy(t, "on")
	for _, h := range hooks {
		select {
		case <-h.seen:
		case <-time.After(30 * time.Second):
			require.Failf(t, "an updater never started", "upstream never logged %q", h.msg)
		}
	}

	require.Contains(t, proxy.asked(), catalogueHost, "the proxy was not asked for the catalogue host")
}

// TestModelCatalogUpdatersStayOffWhenOff: with LLMPROXY_MODEL_CATALOG_UPDATES
// off, no updater starts and nothing is fetched. On, the lines follow the start
// within milliseconds, the fetch being refused at once.
func TestModelCatalogUpdatersStayOffWhenOff(t *testing.T) {
	if !inFreshProcess(t) {
		return
	}

	proxy, hooks := startBehindRefusingProxy(t, "off")

	time.Sleep(3 * time.Second)

	for _, h := range hooks {
		select {
		case <-h.seen:
			require.Failf(t, "an updater started with the updates off", "upstream logged %q", h.msg)
		default:
		}
	}

	require.Empty(t, proxy.asked(), "the process fetched through the proxy with the updates off")
}
