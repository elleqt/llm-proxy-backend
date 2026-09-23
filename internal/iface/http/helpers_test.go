package http

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/app/mocks"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/elleqt/llm-proxy-backend/internal/iface/http/api"
)

// testClock only moves when a test moves it.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// testLog keeps every warning and shows it in the test's output, so a panic the
// router recovered from (an unexpected mock call, say) is visible.
type testLog struct {
	t     *testing.T
	mu    sync.Mutex
	lines []string
}

func (l *testLog) Warnf(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	l.t.Log("router log: " + line)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, line)
}

func (l *testLog) Infof(format string, args ...any) {
	l.t.Log("router log: " + fmt.Sprintf(format, args...))
}
func (l *testLog) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

// cheapHasher stands in for argon2, which is under test in internal/app: the router
// only needs "this password matches that hash".
func cheapHasher() *app.PasswordHasher {
	return app.NewPasswordHasher(8,
		func(plain string) (string, error) {
			if plain == "" {
				return "", identity.ErrEmptyPassword
			}
			return "plain:" + plain, nil
		},
		func(hash, plain string) bool { return hash == "plain:"+plain })
}

const (
	testMaxFailures = 5
	testLockFor     = 15 * time.Minute
	testKey         = "0123456789abcdef0123456789abcdef-test-key"
	testAPIURL      = "https://api.example.com"
	testClientAddr  = "192.0.2.10:40000"
)

// testEnv is the router over real services whose every port is a generated mock.
type testEnv struct {
	t        *testing.T
	clock    *testClock
	log      *testLog
	users    *mocks.UserRepo
	pwds     *mocks.PasswordRepo
	sessions *mocks.SessionRepo
	tokens   *mocks.TokenRepo
	audit    *mocks.AuditSink
	attempts *mocks.LoginAttemptRepo
	usage    *mocks.UsageRepo
	idp      *mocks.IdentityProvider
	idents   *mocks.IdentityRepo
	activity *mocks.ActivityRepo
	catalog  *mocks.ModelCatalog
	settings *mocks.SettingsRepo
	gateway  *mocks.ConfigPusher
	prices   *mocks.PriceRepo
	priceSet *mocks.PriceSink
	// The price catalog: priceSrc is nil in Deps under withoutPriceCatalog.
	priceCat       *mocks.PriceCatalogRepo
	priceSrc       *mocks.PriceCatalogSource
	priceMet       *mocks.PriceCatalogMetrics
	noPriceCatalog bool
	accounts       *mocks.VendorAccounts
	logins         *mocks.VendorLogins
	quota          *mocks.VendorQuota
	acctMet        *mocks.AccountMetrics
	// adminCfg is the federated sign-in the administration API is built with.
	adminCfg app.AdminUsersConfig
	deps     Deps
	handler  http.Handler
}

type envOption func(*testEnv)

// withOIDC turns federated sign-in on, with the identity provider a mock.
func withOIDC(e *testEnv) {
	svc, err := app.NewOIDCService(e.users, e.idents, e.sessions, e.idp, e.audit, e.clock, app.OIDCConfig{AllowSignUp: false})
	if err != nil {
		e.t.Fatalf("NewOIDCService: %v", err)
	}
	e.deps.OIDC = svc
	e.deps.OIDCDisplayName = "Example SSO"
	e.deps.SessionKey = []byte(testKey)
}

func withRate(r RateLimit) envOption { return func(e *testEnv) { e.deps.SignInRate = r } }

func withInsecureCookies(e *testEnv) { e.deps.CookieSecure = false }

// withoutPriceCatalog configures no price catalog source.
func withoutPriceCatalog(e *testEnv) { e.noPriceCatalog = true }

func withAdminConfig(cfg app.AdminUsersConfig) envOption {
	return func(e *testEnv) { e.adminCfg = cfg }
}

// auditInto appends every audit event to events.
func auditInto(events *[]app.AuditEvent) envOption {
	return func(e *testEnv) {
		e.audit.EXPECT().Record(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, ev app.AuditEvent) error {
			*events = append(*events, ev)
			return nil
		})
	}
}

func newEnv(t *testing.T, opts ...envOption) *testEnv {
	t.Helper()
	e := &testEnv{
		t:        t,
		clock:    &testClock{now: time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)},
		log:      &testLog{t: t},
		users:    mocks.NewUserRepo(t),
		pwds:     mocks.NewPasswordRepo(t),
		sessions: mocks.NewSessionRepo(t),
		tokens:   mocks.NewTokenRepo(t),
		audit:    mocks.NewAuditSink(t),
		attempts: mocks.NewLoginAttemptRepo(t),
		usage:    mocks.NewUsageRepo(t),
		idp:      mocks.NewIdentityProvider(t),
		idents:   mocks.NewIdentityRepo(t),
		activity: mocks.NewActivityRepo(t),
		catalog:  mocks.NewModelCatalog(t),
		settings: mocks.NewSettingsRepo(t),
		gateway:  mocks.NewConfigPusher(t),
		prices:   mocks.NewPriceRepo(t),
		priceSet: mocks.NewPriceSink(t),
		priceCat: mocks.NewPriceCatalogRepo(t),
		priceSrc: mocks.NewPriceCatalogSource(t),
		priceMet: mocks.NewPriceCatalogMetrics(t),
		accounts: mocks.NewVendorAccounts(t),
		logins:   mocks.NewVendorLogins(t),
		quota:    mocks.NewVendorQuota(t),
		acctMet:  mocks.NewAccountMetrics(t),
	}
	e.deps = Deps{
		Auth: app.NewAuthService(e.users, e.pwds, app.NewThrottle(e.attempts, testMaxFailures, testLockFor, e.clock),
			cheapHasher(), e.sessions, e.audit, e.clock),
		Tokens:       app.NewTokenService(e.users, e.tokens, e.audit, e.clock, e.log),
		Usage:        app.NewUsageService(e.usage),
		LocalLogin:   true,
		Clock:        e.clock,
		Log:          e.log,
		PublicAPIURL: testAPIURL,
		CookieSecure: true,
	}
	for _, o := range opts {
		o(e)
	}
	e.deps.AdminUsers = app.NewAdminUsers(e.users, e.pwds, e.idents, e.sessions, e.activity, e.deps.Tokens,
		cheapHasher(), e.audit, e.clock, e.catalog, e.adminCfg)
	e.deps.Settings = app.NewSettings(e.settings, e.gateway, e.audit, e.clock)
	var priceSrc app.PriceCatalogSource = e.priceSrc
	if e.noPriceCatalog {
		priceSrc = nil
	}
	e.deps.Prices = app.NewPrices(e.prices, e.priceCat, priceSrc, e.priceSet, e.priceMet, e.audit, e.clock, e.log)
	e.deps.Providers = app.NewProviders(e.accounts, e.logins, e.quota, e.acctMet, e.audit, e.clock, e.log)
	e.audit.EXPECT().Record(mock.Anything, mock.Anything).Return(nil).Maybe()
	h, err := NewRouter(e.deps)
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	e.handler = h
	return e
}

func person(email string) identity.User {
	return identity.User{
		ID:           uuid.New(),
		Kind:         identity.KindHuman,
		Email:        email,
		DisplayName:  "A Person",
		Role:         identity.RoleUser,
		Status:       identity.StatusActive,
		PolicySource: identity.PolicyLocal,
	}
}

// admin is an active administrator with a full session's standing.
func admin() identity.User {
	u := person("admin@example.com")
	u.Role = identity.RoleAdmin
	return u
}

// signedIn makes the store hold a live session for u and returns its cookie.
func (e *testEnv) signedIn(u identity.User) *http.Cookie {
	id := "session-of-" + u.ID.String()
	e.sessions.EXPECT().ByHash(mock.Anything, app.HashSessionID(id)).
		Return(app.Session{IDHash: app.HashSessionID(id), UserID: u.ID, ExpiresAt: e.clock.Now().Add(time.Hour)}, nil).Maybe()
	e.users.EXPECT().ByID(mock.Anything, u.ID).Return(u, nil).Maybe()
	return &http.Cookie{Name: sessionCookieName, Value: id}
}

// do sends a request through the router. POST, PUT and PATCH declare a JSON body, as
// the frontend's client does, unless a modifier changes it; nothing else declares one.
func (e *testEnv) do(method, path, body string, mods ...func(*http.Request)) *httptest.ResponseRecorder {
	e.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = testClientAddr
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		req.Header.Set("Content-Type", "application/json")
	}
	for _, m := range mods {
		m(req)
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	return rec
}

func withCookie(c *http.Cookie) func(*http.Request) {
	return func(r *http.Request) { r.AddCookie(c) }
}

func fromIP(ip string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("X-Real-IP", ip) }
}

// apiError asserts rec is a JSON Error with status and code, and returns it.
func apiError(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) api.Error {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, status, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json; body %q", ct, rec.Body)
	}
	var e api.Error
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatalf("body is not a JSON Error: %v; body %q", err, rec.Body)
	}
	if e.Code != code || e.Message == "" {
		t.Fatalf("error = %+v, want code %q and a message", e, code)
	}
	return e
}

// decodeBody asserts rec is a JSON status response and decodes it into v.
func decodeBody(t *testing.T, rec *httptest.ResponseRecorder, status int, v any) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, status, rec.Body)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("decode %T: %v; body %q", v, err, rec.Body)
	}
}

// cookieNamed returns the Set-Cookie for name, failing if there is none.
func cookieNamed(t *testing.T, rec *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no %s cookie was set; headers %v", name, rec.Header())
	return nil
}
