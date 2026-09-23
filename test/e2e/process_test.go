package e2e

import (
	"errors"
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

	"github.com/sirupsen/logrus"

	"github.com/elleqt/llm-proxy-backend/internal/iface/http/api"
)

// upstreamShutdownWindow is the deadline upstream gives its own shutdown,
// counted from when its Run started (sdk/cliproxy/service_lifecycle.go Run,
// v7.3.12), not from the stop. It is a constant in upstream's code and cannot be
// shortened for a test: a process stopped by cancelling upstream's Run after
// that long drains nothing, so the drain test waits it out. That wait is most of
// this package's run time; -short skips the drain leg for a quick local loop, and
// the full run (make test, CI) keeps it: it is the only proof that a stop after
// the window still drains.
const upstreamShutdownWindow = 30 * time.Second

// TestTheProcessKeepsItsListenersApartAndStopsCleanly is the process as an
// operator runs it: each listener serves only its own API, metrics only on the
// metrics listener, the gate's refusals counted there, the routing strategy an
// administrator stored in force from boot, and a SIGTERM — sent once the
// process has been up longer than upstream's own shutdown window — lets the
// proxied request in flight finish before Run returns cleanly.
func TestTheProcessKeepsItsListenersApartAndStopsCleanly(t *testing.T) {
	if !inFreshProcess(t) {
		return
	}
	p := startProcess(t, "routing:\n  strategy: fill-first\n", nil)
	p.signInAsBootstrapAdmin(t)
	secret := p.issueToken(t, "ops").Secret
	p.setPolicy(t, p.adminEmail, p.a.policyName+":*", p.b.policyName+":*")
	eventually(t, "both vendors' models are listed", func() bool {
		m := p.models(t, secret)
		return m[p.a.alias] && m[p.b.alias]
	})

	// The proxied listener serves no web API, the web listener no proxied API,
	// and neither serves metrics: each answers 404 as for any unknown path.
	for _, c := range []struct{ method, target, body string }{
		{http.MethodGet, p.apiURL + "/api/auth/config", ""},
		{http.MethodGet, p.apiURL + "/api/me", ""},
		{http.MethodPost, p.apiURL + "/api/auth/login", `{"email":"` + p.adminEmail + `","password":"a password I chose myself"}`},
		{http.MethodGet, p.apiURL + "/api/admin/users", ""},
		{http.MethodGet, p.apiURL + "/metrics", ""},
		{http.MethodGet, p.webURL + "/v1/models", ""},
		{http.MethodPost, p.webURL + "/v1/chat/completions", `{"model":"` + p.a.alias + `","messages":[{"role":"user","content":"hi"}]}`},
		{http.MethodGet, p.webURL + "/metrics", ""},
		{http.MethodGet, p.metricsURL + "/v1/models", ""},
		{http.MethodGet, p.metricsURL + "/api/auth/config", ""},
	} {
		if code, body := send(t, c.method, c.target, secret, c.body); code != http.StatusNotFound {
			t.Fatalf("%s %s = %d (%s), want 404", c.method, c.target, code, body)
		}
	}

	// The strategy stored in the settings is the one routing requests, with no
	// configuration pushed since boot: fill-first keeps every request on vendor
	// A's first key, where the default round-robin would alternate between both.
	for range 4 {
		if code := p.chat(t, secret, p.a.alias); code != http.StatusOK {
			t.Fatalf("POST /v1/chat/completions (A) = %d, want 200", code)
		}
	}
	keys := map[string]bool{}
	for _, r := range p.a.fake.Requests() {
		keys[r.Header.Get("Authorization")] = true
	}
	if len(keys) != 1 {
		t.Fatalf("vendor A saw keys %v over 4 requests; the stored fill-first strategy is not in force", keys)
	}

	// The metrics listener exposes the service's families, the usage sink's
	// health counters among them, the requests just served, and the gate's
	// refusals under the refused user.
	if code := p.chat(t, secret, "e2e-model-nobody-serves"); code != http.StatusForbidden {
		t.Fatalf("a model no vendor serves = %d, want 403", code)
	}
	eventually(t, "the served requests are counted", func() bool { return p.metricFamilies(t)["llmproxy_requests_total"] })
	families := p.metricFamilies(t)
	for _, want := range []string{"llmproxy_build_info", "llmproxy_usage_dropped_total", "llmproxy_usage_panics_total"} {
		if !families[want] {
			t.Fatalf("metrics families %v lack %s", families, want)
		}
	}
	if want := `llmproxy_policy_denied_total{model="unknown",reason="unknown_model",user="` + p.adminEmail + `"} 1`; !strings.Contains(p.scrapeMetrics(t), want) {
		t.Fatalf("metrics lack %s", want)
	}

	// Past upstream's own shutdown window, SIGTERM while a request is with the
	// slow vendor: the request completes before Run returns, and Run returns
	// without error.
	if testing.Short() {
		t.Log("-short: the drain leg, which waits out upstream's shutdown window, is skipped")
		return
	}
	time.Sleep(time.Until(p.readyAt.Add(upstreamShutdownWindow + time.Second)))
	inFlight := p.sendSlowRequest(t, secret)
	eventually(t, "the request reaches vendor B", func() bool { return len(p.b.fake.Requests()) == 1 })
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := p.awaitReturn(60 * time.Second); err != nil {
		t.Fatalf("Run after SIGTERM = %v, want nil", err)
	}
	select {
	case r := <-inFlight:
		if r.status != "200 OK" {
			t.Fatalf("the request in flight at SIGTERM = %s, want 200 OK", r.status)
		}
		// The client reads the last bytes a moment after the server has
		// written them; a stop that did not wait would return a whole vendor
		// latency earlier. Half that latency is the margin: wide enough for a
		// loaded runner under -race, far short of what an undrained stop shows.
		if late := r.at.Sub(p.returnedAt); late > slowVendorLatency/2 {
			t.Fatalf("the request in flight at SIGTERM completed %s after Run returned: it was not drained", late)
		}
	case <-time.After(slowVendorLatency + 5*time.Second):
		t.Fatal("the request in flight at SIGTERM never completed")
	}
	for _, target := range []string{p.apiURL + "/healthz", p.webURL + "/api/auth/config", p.metricsURL + "/metrics"} {
		if resp, err := http.Get(target); err == nil {
			_ = resp.Body.Close()
			t.Fatalf("GET %s after Run returned: %d, want the listener closed", target, resp.StatusCode)
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
		if !errors.As(err, &exit) || !exit.Sys().(syscall.WaitStatus).Signaled() ||
			exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGTERM {
			t.Fatalf("the process ended with %v, want killed by the second SIGTERM\n%s", err, out)
		}
		return
	}
	p := startProcess(t, "", nil)
	p.signInAsBootstrapAdmin(t)
	secret := p.issueToken(t, "ops").Secret
	p.setPolicy(t, p.adminEmail, p.b.policyName+":*")
	eventually(t, "vendor B's model is listed", func() bool { return p.models(t, secret)[p.b.alias] })

	p.sendSlowRequest(t, secret)
	eventually(t, "the request reaches vendor B", func() bool { return len(p.b.fake.Requests()) == 1 })
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the process begins to stop", func() bool { return strings.Contains(p.out.String(), "stopping") })
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	// Only reached if the second signal was caught.
	err := p.awaitReturn(60 * time.Second)
	t.Fatalf("the process outlived a second SIGTERM; Run returned %v after draining", err)
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
	req, err := http.NewRequest(http.MethodPost, p.apiURL+"/v1/chat/completions", strings.NewReader(
		`{"model":"`+p.b.alias+`","messages":[{"role":"user","content":"say hello"}]}`))
	if err != nil {
		t.Fatal(err)
	}
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
	p := startProcess(t, "", map[string]string{"LLMPROXY_LOCAL_LOGIN": "false"})

	var cfg api.AuthConfig
	p.webJSON(t, http.MethodGet, "/api/auth/config", "", http.StatusOK, &cfg)
	if cfg.LocalLogin {
		t.Fatal("GET /api/auth/config offers the password form with local login off")
	}
	var refused api.Error
	p.webJSON(t, http.MethodPost, "/api/auth/login",
		`{"email":"`+p.adminEmail+`","password":"`+p.adminPassword+`"}`, http.StatusNotFound, &refused)
	if refused.Code != "not_found" {
		t.Fatalf("POST /api/auth/login: code %q, want not_found", refused.Code)
	}
	if out := p.out.String(); !strings.Contains(out, "LLMPROXY_LOCAL_LOGIN is false") {
		t.Fatalf("no warning that the bootstrap administrator cannot sign in:\n%s", out)
	}
}

// catalogueHost is where upstream's model catalogue updaters fetch from first
// (internal/registry model_updater.go modelsURLs, v7.3.12), as a CONNECT asks
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
			t.Fatalf("upstream never logged %q", h.msg)
		}
	}
	if hosts := proxy.asked(); !slices.Contains(hosts, catalogueHost) {
		t.Fatalf("the proxy was asked for %v, not the catalogue host %s", hosts, catalogueHost)
	}
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
			t.Fatalf("upstream logged %q with the updates off", h.msg)
		default:
		}
	}
	if hosts := proxy.asked(); len(hosts) > 0 {
		t.Fatalf("the process fetched through the proxy with the updates off: %v", hosts)
	}
}
