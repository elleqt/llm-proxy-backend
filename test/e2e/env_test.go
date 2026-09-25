// Package e2e drives the whole process as cmd/gateway runs it — internal/boot.Run,
// configured through its environment variables — in front of wire-level fake
// vendors and a real Postgres, over its three listeners.
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/boot"
	"github.com/elleqt/llm-proxy-backend/internal/config"
	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/iface/http/api"
	"github.com/elleqt/llm-proxy-backend/internal/infra/gateway/faketest"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/pgtest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	cliproxyconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	"github.com/sirupsen/logrus"
)

// childEnv marks the fresh process a test runs its body in.
const childEnv = "LLMPROXY_E2E_CHILD"

// inFreshProcess re-runs the calling test alone in a new process and requires it
// to pass, unless this already is that process: upstream delivers usage records
// through one process-global dispatcher that a gateway's shutdown stops for good,
// and its model registry and access registry are process-global too, so each boot
// gets a process of its own. The processes run in parallel. It reports whether
// the caller is the child and must run the body.
func inFreshProcess(t *testing.T) bool {
	t.Helper()

	if isChild() {
		return true
	}

	out, err := runChild(t)
	if err != nil || !strings.Contains(string(out), "--- PASS: "+t.Name()) {
		t.Fatalf("in a fresh process: %v\n%s", err, out)
	}

	return false
}

func isChild() bool { return os.Getenv(childEnv) != "" }

// runChild runs the calling test alone in a new process, in parallel with the
// other tests, and returns what it printed and how it ended. -short carries over.
func runChild(t *testing.T) ([]byte, error) {
	t.Helper()
	t.Parallel()

	args := []string{"-test.run=^" + t.Name() + "$", "-test.count=1", "-test.v"}
	if testing.Short() {
		args = append(args, "-test.short")
	}

	cmd := exec.CommandContext(t.Context(), os.Args[0], args...)

	cmd.Env = append(os.Environ(), childEnv+"=1")

	return cmd.CombinedOutput()
}

// vendorPayload is a chat completion that spent 7 tokens.
const vendorPayload = `{"id":"chatcmpl-1","object":"chat.completion","created":1,"model":"m",` +
	`"choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],` +
	`"usage":{"prompt_tokens":3,"completion_tokens":4,"total_tokens":7}}`

// slowVendorLatency is how long vendor B takes to answer, so a request to it is
// still in flight, for that long, when the process is told to stop.
const slowVendorLatency = 2 * time.Second

// vendor is one fake vendor as the process knows it.
type vendor struct {
	policyName string // the provider name a policy grants
	alias      string // the model name clients ask for
	fake       *faketest.Vendor
}

// output is the process's Output: the log and the bootstrap banner, kept for the
// test to search and echoed to the test log.
type output struct {
	t   *testing.T
	mu  sync.Mutex
	buf bytes.Buffer
}

func (o *output) Write(data []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.t.Logf("process: %s", bytes.TrimSpace(data))

	return o.buf.Write(data)
}

func (o *output) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()

	return o.buf.String()
}

// process is the running service and the handles a test needs.
type process struct {
	pool                       *pgxpool.Pool
	users                      *postgres.UserRepo
	out                        *output
	apiURL, webURL, metricsURL string
	browser                    *http.Client // a browser: a cookie jar on the web listener
	a, b                       vendor
	// adminEmail and adminPassword are the bootstrap administrator's.
	adminEmail, adminPassword string

	// readyAt is when all three listeners first answered; returnedAt is when Run
	// returned, read after p.done delivers.
	readyAt, returnedAt time.Time

	done     chan error
	stopOnce sync.Once
	stopErr  error
	cancel   context.CancelFunc
}

// bootstrapBanner finds the temporary password in the process's output.
var bootstrapBanner = regexp.MustCompile(`temporary password: (\S+)`)

// startProcess stores settingsDoc (unless empty) as the administrator's upstream
// settings, then boots the process as cmd/gateway does, configured through the
// environment, with two fake vendors in its boot configuration (boot-only vendors):
// A behind two keys, B slow. env overrides the environment it sets. It returns
// once all three listeners serve.
func startProcess(t *testing.T, settingsDoc string, env map[string]string) *process {
	t.Helper()

	pool := pgtest.NewTestPool(t)
	if settingsDoc != "" {
		if err := postgres.NewSettingsRepo(pool).SetUpstreamDocument(context.Background(), settingsDoc, uuid.Nil, time.Now()); err != nil {
			t.Fatalf("store settings: %v", err)
		}
	}

	proc := &process{
		pool:       pool,
		users:      postgres.NewUserRepo(pool),
		out:        &output{t: t},
		adminEmail: "admin@example.com",
		a:          vendor{policyName: "vendora", alias: "e2e-model-a", fake: &faketest.Vendor{Payload: []byte(vendorPayload)}},
		b: vendor{
			policyName: "vendorb", alias: "e2e-model-b",
			fake: &faketest.Vendor{Payload: []byte(vendorPayload), Latency: slowVendorLatency},
		},
	}
	srvA, srvB := faketest.Start(t, proc.a.fake), faketest.Start(t, proc.b.fake)
	entryA := faketest.Compatibility(proc.a.policyName, srvA.URL, "vendor-key-a1", "upstream-model-a", proc.a.alias)
	entryA.APIKeyEntries = append(entryA.APIKeyEntries, cliproxyconfig.OpenAICompatibilityAPIKey{APIKey: "vendor-key-a2"})
	entryB := faketest.Compatibility(proc.b.policyName, srvB.URL, "vendor-key-b", "upstream-model-b", proc.b.alias)

	apiAddr, webAddr, metricsAddr := freeAddr(t), freeAddr(t), freeAddr(t)
	proc.apiURL, proc.webURL, proc.metricsURL = "http://"+apiAddr, "http://"+webAddr, "http://"+metricsAddr
	vars := map[string]string{
		"LLMPROXY_DATABASE_URL":              pool.Config().ConnString(),
		"LLMPROXY_LISTEN_ADDR":               apiAddr,
		"LLMPROXY_WEB_ADDR":                  webAddr,
		"LLMPROXY_METRICS_ADDR":              metricsAddr,
		"LLMPROXY_PUBLIC_API_URL":            proc.apiURL,
		"LLMPROXY_RUNTIME_DIR":               t.TempDir(),
		"LLMPROXY_AUTH_DIR":                  t.TempDir(),
		"LLMPROXY_BOOTSTRAP_ADMIN_EMAIL":     proc.adminEmail,
		"LLMPROXY_PASSWORD_HASH_CONCURRENCY": "2",
		// The web listener here is plain http, as behind the local stack's nginx.
		"LLMPROXY_COOKIE_SECURE": "false",
		"LLMPROXY_SESSION_KEY":   "",
		"LLMPROXY_OIDC_ISSUER":   "",
		"LLMPROXY_LOCAL_LOGIN":   "",
		// The default text log, whatever format the caller's environment set.
		"LLMPROXY_LOG_FORMAT": "",
		// Never the network: a test that wants a catalog serves one and sets these.
		"LLMPROXY_PRICES_CATALOG_URL":      config.PriceCatalogOff,
		"LLMPROXY_PRICES_CATALOG_INTERVAL": "",
		// A set one makes the gateway refuse to start.
		"MANAGEMENT_PASSWORD": "",
		// On, upstream's model catalogue updaters fetch from the internet; the
		// tests of that switch turn it on behind a local proxy.
		"LLMPROXY_MODEL_CATALOG_UPDATES": "off",
	}
	maps.Copy(vars, env)

	for k, v := range vars {
		t.Setenv(k, v)
	}

	// Upstream finishes starting after its listener answers: it starts its file
	// watcher last and logs that it did. A stop before then races upstream's own
	// startup, so the process counts as started only once that line is logged.
	watching := &logSeen{msg: "file watcher started", seen: make(chan struct{})}
	logrus.AddHook(watching)

	ctx, cancel := context.WithCancel(context.Background())

	proc.cancel, proc.done = cancel, make(chan error, 1)
	go func() {
		err := boot.Run(ctx, boot.Options{Output: proc.out, Compatibility: []cliproxyconfig.OpenAICompatibility{entryA, entryB}})

		proc.returnedAt = time.Now()
		proc.done <- err
	}()

	t.Cleanup(func() {
		if err := proc.stop(); err != nil {
			t.Errorf("the process stopped with %v", err)
		}
	})

	for _, probe := range []string{proc.apiURL + "/healthz", proc.webURL + "/api/auth/config", proc.metricsURL + "/metrics"} {
		eventually(t, "GET "+probe+" answers 200", func() bool {
			select {
			case err := <-proc.done:
				t.Fatalf("the process stopped while starting: %v", err)
			default:
			}

			resp, err := get(t, probe)
			if err != nil {
				return false
			}

			_ = resp.Body.Close()

			return resp.StatusCode == http.StatusOK
		})
	}

	select {
	case <-watching.seen:
	case err := <-proc.done:
		t.Fatalf("the process stopped while starting: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("upstream never finished starting: no file watcher")
	}

	m := bootstrapBanner.FindStringSubmatch(proc.out.String())
	if m == nil {
		t.Fatal("the process printed no bootstrap password")
	}

	proc.adminPassword = m[1]
	proc.readyAt = time.Now()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}

	proc.browser = &http.Client{Jar: jar, Timeout: 30 * time.Second}

	return proc
}

// logSeen is a logrus hook that closes seen the first time a message containing
// msg is logged.
type logSeen struct {
	msg  string
	once sync.Once
	seen chan struct{}
}

func (h *logSeen) Levels() []logrus.Level { return logrus.AllLevels }

func (h *logSeen) Fire(e *logrus.Entry) error {
	if strings.Contains(e.Message, h.msg) {
		h.once.Do(func() { close(h.seen) })
	}

	return nil
}

// stop cancels Run, if nothing stopped it yet, and returns its result.
func (p *process) stop() error {
	p.cancel()

	return p.awaitReturn(60 * time.Second)
}

// awaitReturn waits, once, for Run to return and returns its result.
func (p *process) awaitReturn(within time.Duration) error {
	p.stopOnce.Do(func() {
		select {
		case p.stopErr = <-p.done:
		case <-time.After(within):
			p.stopErr = fmt.Errorf("Run did not return within %s", within)
		}
	})

	return p.stopErr
}

func freeAddr(t *testing.T) string {
	t.Helper()

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}

	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	return addr
}

// get is http.Get bound to the test's context.
func get(t *testing.T, target string) (*http.Response, error) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	return http.DefaultClient.Do(req)
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting until %s", what)
		}

		time.Sleep(20 * time.Millisecond)
	}
}

// webCall is one request to the web API as the browser makes it.
func (p *process) webCall(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), method, p.webURL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}

	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := p.browser.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}

	defer func() { _ = resp.Body.Close() }()

	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	return resp.StatusCode, out
}

// webJSON is webCall that requires status and decodes the body into v.
func (p *process) webJSON(t *testing.T, method, path, body string, status int, dest any) {
	t.Helper()

	code, out := p.webCall(t, method, path, body)
	if code != status {
		t.Fatalf("%s %s = %d (%s), want %d", method, path, code, out, status)
	}

	if dest != nil {
		if err := json.Unmarshal(out, dest); err != nil {
			t.Fatalf("%s %s: decode: %v (%s)", method, path, err, out)
		}
	}
}

// signInAsBootstrapAdmin signs in with the one-time password, which opens a
// restricted session, and changes the password, which lifts the restriction.
func (p *process) signInAsBootstrapAdmin(t *testing.T) {
	t.Helper()
	p.claimTemporaryPassword(t, p.adminPassword, "a password I chose myself")
}

// claimTemporaryPassword signs the administrator in with a temporary password,
// which opens a restricted session, and changes it to chosen, which lifts the
// restriction.
func (p *process) claimTemporaryPassword(t *testing.T, temporary, chosen string) {
	t.Helper()

	var me api.Me
	p.webJSON(t, http.MethodPost, "/api/auth/login",
		`{"email":"`+p.adminEmail+`","password":"`+temporary+`"}`, http.StatusOK, &me)

	if !me.Restricted {
		t.Fatal("the session a temporary password opens is not restricted")
	}

	var refused api.Error
	p.webJSON(t, http.MethodGet, "/api/me/tokens", "", http.StatusForbidden, &refused)

	if refused.Code != "password_change_required" {
		t.Fatalf("restricted session on /api/me/tokens: code %q, want password_change_required", refused.Code)
	}

	p.webJSON(t, http.MethodPost, "/api/auth/password", `{"newPassword":"`+chosen+`"}`, http.StatusNoContent, nil)
	p.webJSON(t, http.MethodGet, "/api/me", "", http.StatusOK, &me)

	if me.Restricted {
		t.Fatal("the session is still restricted after the password change")
	}
}

// issueToken issues an API token in the cabinet and returns its secret.
func (p *process) issueToken(t *testing.T, label string) api.IssuedToken {
	t.Helper()

	var issued api.IssuedToken
	p.webJSON(t, http.MethodPost, "/api/me/tokens", `{"label":"`+label+`"}`, http.StatusCreated, &issued)

	return issued
}

// sessionCookie is the session cookie the browser holds now.
func (p *process) sessionCookie(t *testing.T) *http.Cookie {
	t.Helper()

	u, err := url.Parse(p.webURL)
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range p.browser.Jar.Cookies(u) {
		if c.Name == "llmproxy_session" {
			return c
		}
	}

	t.Fatal("the browser holds no session cookie")

	return nil
}

// chat sends a chat completion for model through the proxied API with secret.
func (p *process) chat(t *testing.T, secret, model string) int {
	t.Helper()
	code, _ := send(t, http.MethodPost, p.apiURL+"/v1/chat/completions", secret,
		`{"model":"`+model+`","messages":[{"role":"user","content":"say hello"}]}`)

	return code
}

// send is one request to any listener, with secret as a bearer token unless empty.
func send(t *testing.T, method, target, secret, body string) (int, []byte) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), method, target, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}

	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}

	defer func() { _ = resp.Body.Close() }()

	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	return resp.StatusCode, out
}

// models lists the model ids /v1/models shows the holder of secret.
func (p *process) models(t *testing.T, secret string) map[string]bool {
	t.Helper()
	code, body := send(t, http.MethodGet, p.apiURL+"/v1/models", secret, "")

	var list struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("GET /v1/models: status %d, decode: %v", code, err)
	}

	out := map[string]bool{}
	for _, m := range list.Data {
		out[m.ID] = true
	}

	return out
}

// setPolicy is the administrator's policy edit, made in the store directly.
func (p *process) setPolicy(t *testing.T, email string, rules ...string) {
	t.Helper()

	ctx := context.Background()

	user, err := p.users.ByEmail(ctx, email)
	if err != nil {
		t.Fatal(err)
	}

	policy := make(access.Policy, 0, len(rules))
	for _, raw := range rules {
		r, err := access.ParseRule(raw)
		if err != nil {
			t.Fatal(err)
		}

		policy = append(policy, r)
	}

	if err := p.users.UpdatePolicy(ctx, user.ID, policy); err != nil {
		t.Fatal(err)
	}
}

// scrapeMetrics returns what the metrics listener serves on /metrics.
func (p *process) scrapeMetrics(t *testing.T) string {
	t.Helper()

	code, body := send(t, http.MethodGet, p.metricsURL+"/metrics", "", "")
	if code != http.StatusOK {
		t.Fatalf("GET /metrics on the metrics listener = %d", code)
	}

	return string(body)
}

// metricFamilies is the set of families the metrics listener exposes.
func (p *process) metricFamilies(t *testing.T) map[string]bool {
	t.Helper()

	out := map[string]bool{}

	for line := range strings.Lines(p.scrapeMetrics(t)) {
		if rest, ok := strings.CutPrefix(line, "# TYPE "); ok {
			out[strings.Fields(rest)[0]] = true
		}
	}

	return out
}
