package config

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestLoadRequiresDatabaseURL(t *testing.T) {
	t.Setenv("LLMPROXY_DATABASE_URL", "")
	if _, err := Load(); err == nil {
		t.Fatal("expected error when LLMPROXY_DATABASE_URL is empty")
	}
}

func TestLoadDefaults(t *testing.T) {
	setWebEnv(t, nil)
	t.Setenv("LLMPROXY_LISTEN_ADDR", "")
	t.Setenv("LLMPROXY_RUNTIME_DIR", "")
	t.Setenv("LLMPROXY_AUTH_DIR", "")
	t.Setenv("LLMPROXY_PASSWORD_HASH_CONCURRENCY", "")
	t.Setenv("LLMPROXY_DATABASE_URL", "postgres://u:p@localhost:5432/db")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ListenAddr != ":8080" {
		t.Fatalf("ListenAddr = %q, want \":8080\"", cfg.ListenAddr)
	}
	// Metrics stay off every non-loopback interface unless the operator says so.
	if cfg.MetricsAddr != "127.0.0.1:9090" {
		t.Fatalf("MetricsAddr = %q, want 127.0.0.1:9090", cfg.MetricsAddr)
	}
	if cfg.RuntimeDir != "/var/lib/llmproxy/runtime" {
		t.Fatalf("RuntimeDir = %q", cfg.RuntimeDir)
	}
	if cfg.AuthDir != "/var/lib/llmproxy/auths" {
		t.Fatalf("AuthDir = %q, want \"/var/lib/llmproxy/auths\"", cfg.AuthDir)
	}
	// Zero would deadlock every sign-in on the semaphore.
	if cfg.PasswordHashConcurrency < 1 {
		t.Fatalf("PasswordHashConcurrency = %d, want a positive default", cfg.PasswordHashConcurrency)
	}
}

func TestLoadOverrides(t *testing.T) {
	setWebEnv(t, nil)
	t.Setenv("LLMPROXY_LISTEN_ADDR", "127.0.0.1:9191")
	t.Setenv("LLMPROXY_METRICS_ADDR", ":9292")
	t.Setenv("LLMPROXY_DATABASE_URL", "postgres://user:pass@db.example.com:5432/gateway")
	t.Setenv("LLMPROXY_RUNTIME_DIR", "/tmp/runtime")
	t.Setenv("LLMPROXY_AUTH_DIR", "/tmp/auths")
	t.Setenv("LLMPROXY_BOOTSTRAP_ADMIN_EMAIL", "admin@example.com")
	t.Setenv("LLMPROXY_PASSWORD_HASH_CONCURRENCY", "3")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host, port := cfg.ListenHostPort(); host != "127.0.0.1" || port != 9191 {
		t.Fatalf("ListenHostPort() = %q, %d; want 127.0.0.1, 9191", host, port)
	}
	if cfg.MetricsAddr != ":9292" {
		t.Fatalf("MetricsAddr = %q, want \":9292\"", cfg.MetricsAddr)
	}
	if cfg.DatabaseURL != "postgres://user:pass@db.example.com:5432/gateway" {
		t.Fatalf("DatabaseURL = %q", cfg.DatabaseURL)
	}
	if cfg.RuntimeDir != "/tmp/runtime" {
		t.Fatalf("RuntimeDir = %q, want \"/tmp/runtime\"", cfg.RuntimeDir)
	}
	if cfg.AuthDir != "/tmp/auths" {
		t.Fatalf("AuthDir = %q, want \"/tmp/auths\"", cfg.AuthDir)
	}
	// The name is fixed by docker-compose.yml and .env.example; reading any other
	// spelling silently disables the bootstrap on a fresh install.
	if cfg.BootstrapAdminEmail != "admin@example.com" {
		t.Fatalf("BootstrapAdminEmail = %q, want \"admin@example.com\"", cfg.BootstrapAdminEmail)
	}
	if cfg.PasswordHashConcurrency != 3 {
		t.Fatalf("PasswordHashConcurrency = %d, want 3", cfg.PasswordHashConcurrency)
	}
}

// A non-positive capacity would deadlock every sign-in; refusing to start says so.
func TestLoadRejectsANonPositiveHashConcurrency(t *testing.T) {
	setWebEnv(t, nil)
	t.Setenv("LLMPROXY_DATABASE_URL", "postgres://u:p@localhost:5432/db")
	for _, raw := range []string{"0", "-1", "many"} {
		t.Setenv("LLMPROXY_PASSWORD_HASH_CONCURRENCY", raw)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "LLMPROXY_PASSWORD_HASH_CONCURRENCY") {
			t.Fatalf("%q: err = %v, want one naming LLMPROXY_PASSWORD_HASH_CONCURRENCY", raw, err)
		}
	}
}

// The catalog is on unless turned off; off ignores the interval, and an interval
// short enough to hammer the source, or a URL that is not one, stops the start.
func TestPriceCatalogIsOnUnlessOffAndItsIntervalIsBounded(t *testing.T) {
	setWebEnv(t, nil)
	t.Setenv("LLMPROXY_DATABASE_URL", "postgres://u:p@localhost:5432/db")
	load := func(url, interval string) (PriceCatalog, error) {
		t.Helper()
		t.Setenv("LLMPROXY_PRICES_CATALOG_URL", url)
		t.Setenv("LLMPROXY_PRICES_CATALOG_INTERVAL", interval)
		cfg, err := Load()
		return cfg.PriceCatalog, err
	}

	if got, err := load("", ""); err != nil || !got.Enabled() || got.URL != DefaultPriceCatalogURL || got.Interval != 6*time.Hour {
		t.Fatalf("defaults = %+v, %v; want the default URL every 6h", got, err)
	}
	if got, err := load("http://catalog.example.com/models.json", "5m"); err != nil || got.Interval != 5*time.Minute {
		t.Fatalf("5m = %+v, %v; want accepted", got, err)
	}
	if got, err := load(PriceCatalogOff, "nonsense"); err != nil || got.Enabled() {
		t.Fatalf("off = %+v, %v; want disabled, the interval ignored", got, err)
	}
	for _, c := range []struct{ url, interval, name string }{
		{"", "4m59s", "LLMPROXY_PRICES_CATALOG_INTERVAL"},
		{"", "6", "LLMPROXY_PRICES_CATALOG_INTERVAL"},
		{"catalog.example.com/models.json", "", "LLMPROXY_PRICES_CATALOG_URL"},
		{"ftp://catalog.example.com/models.json", "", "LLMPROXY_PRICES_CATALOG_URL"},
	} {
		if _, err := load(c.url, c.interval); err == nil || !strings.Contains(err.Error(), c.name) {
			t.Errorf("%q every %q: err = %v, want one naming %s", c.url, c.interval, err, c.name)
		}
	}
}

// Catalogue updates reach the network, so they stop only when the operator says
// off; a misspelt value stops the start rather than silently choosing either way.
func TestModelCatalogUpdatesAreOnUnlessTurnedOff(t *testing.T) {
	setWebEnv(t, nil)
	t.Setenv("LLMPROXY_DATABASE_URL", "postgres://u:p@localhost:5432/db")
	for raw, want := range map[string]bool{"": true, ModelCatalogUpdatesOn: true, ModelCatalogUpdatesOff: false} {
		t.Setenv("LLMPROXY_MODEL_CATALOG_UPDATES", raw)
		cfg, err := Load()
		if err != nil {
			t.Fatalf("%q: %v", raw, err)
		}
		if cfg.ModelCatalogUpdates != want {
			t.Fatalf("%q: ModelCatalogUpdates = %v, want %v", raw, cfg.ModelCatalogUpdates, want)
		}
	}
	for _, raw := range []string{"false", "OFF", "no"} {
		t.Setenv("LLMPROXY_MODEL_CATALOG_UPDATES", raw)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "LLMPROXY_MODEL_CATALOG_UPDATES") {
			t.Fatalf("%q: err = %v, want one naming LLMPROXY_MODEL_CATALOG_UPDATES", raw, err)
		}
	}
}

// A listen address the server cannot bind as given is refused at start, naming the
// variable, rather than failing later inside upstream or binding a random port.
func TestLoadRejectsAMalformedListenAddress(t *testing.T) {
	for _, name := range []string{"LLMPROXY_LISTEN_ADDR", "LLMPROXY_WEB_ADDR", "LLMPROXY_METRICS_ADDR"} {
		for _, bad := range []string{"8080", ":http", ":0", ":70000", "::1:8080"} {
			setWebEnv(t, map[string]string{name: bad})
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("%s=%q: err = %v, want one naming %s", name, bad, err, name)
			}
		}
	}
}

// Upstream joins the proxied listener's host and port with a bare colon
// (internal/api/server.go NewServer), so an IPv6 host must reach it bracketed, or
// its listener fails with "too many colons".
func TestAnIPv6ListenAddressReachesUpstreamBracketed(t *testing.T) {
	setWebEnv(t, map[string]string{"LLMPROXY_LISTEN_ADDR": "[::1]:9191"})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if host, port := cfg.ListenHostPort(); host != "[::1]" || port != 9191 {
		t.Fatalf("ListenHostPort() = %q, %d; want [::1], 9191", host, port)
	}
}

const testSecret = "s3cret-client-value"

// setOIDCEnv sets a complete, valid OIDC configuration and then applies overrides; an
// override of "" unsets that variable for the test.
func setOIDCEnv(t *testing.T, overrides map[string]string) {
	t.Helper()
	env := map[string]string{
		"LLMPROXY_DATABASE_URL":        "postgres://u:p@localhost:5432/db",
		"LLMPROXY_OIDC_ISSUER":         "https://idp.example.com/realms/example",
		"LLMPROXY_OIDC_CLIENT_ID":      "llm-proxy",
		"LLMPROXY_OIDC_CLIENT_SECRET":  testSecret,
		"LLMPROXY_OIDC_REDIRECT_URL":   "https://proxy.example.com/api/auth/oidc/callback",
		"LLMPROXY_OIDC_REQUIRED_GROUP": "",
		"LLMPROXY_OIDC_ALLOW_SIGNUP":   "",
		"LLMPROXY_OIDC_DEFAULT_POLICY": "",
		"LLMPROXY_OIDC_GROUP_POLICY":   "",
		"LLMPROXY_OIDC_GROUPS_CLAIM":   "",
		"LLMPROXY_OIDC_DISPLAY_NAME":   "",
	}
	setWebEnv(t, nil)
	maps.Copy(env, overrides)
	for k, v := range env {
		t.Setenv(k, v)
	}
}

func TestOIDCEnabledButIncompleteNamesTheMissingVariable(t *testing.T) {
	for _, name := range []string{
		"LLMPROXY_OIDC_CLIENT_ID",
		"LLMPROXY_OIDC_CLIENT_SECRET",
		"LLMPROXY_OIDC_REDIRECT_URL",
	} {
		t.Run(name, func(t *testing.T) {
			setOIDCEnv(t, map[string]string{name: ""})
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("err = %v, want an error naming %s", err, name)
			}
		})
	}
}

// Without an issuer OIDC is off, and the variables that only mean something when it
// is on must not be able to stop the gateway from starting.
func TestOIDCDisabledIgnoresTheOtherVariables(t *testing.T) {
	setOIDCEnv(t, map[string]string{
		"LLMPROXY_OIDC_ISSUER":       "",
		"LLMPROXY_OIDC_GROUP_POLICY": "not a mapping",
	})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.OIDC.Enabled() {
		t.Fatalf("OIDC = %+v, want disabled", cfg.OIDC)
	}
}

func TestOIDCParsesTheDocumentedExample(t *testing.T) {
	setOIDCEnv(t, map[string]string{
		"LLMPROXY_OIDC_GROUP_POLICY":   "/team-a=claude:*;/everyone=*:*",
		"LLMPROXY_OIDC_DEFAULT_POLICY": "claude:claude-sonnet-5, openai:gpt-*",
		"LLMPROXY_OIDC_ALLOW_SIGNUP":   "true",
		"LLMPROXY_OIDC_DISPLAY_NAME":   " Example SSO ",
	})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	o := cfg.OIDC
	want := map[string][]string{
		"/team-a":   {"claude:*"},
		"/everyone": {"*:*"},
	}
	if !maps.EqualFunc(o.GroupPolicy, want, slices.Equal[[]string]) {
		t.Fatalf("GroupPolicy = %v, want %v", o.GroupPolicy, want)
	}
	if want := []string{"claude:claude-sonnet-5", "openai:gpt-*"}; !slices.Equal(o.DefaultPolicy, want) {
		t.Fatalf("DefaultPolicy = %q, want %q", o.DefaultPolicy, want)
	}
	if !o.AllowSignUp || o.GroupsClaim != "groups" {
		t.Fatalf("AllowSignUp = %v, GroupsClaim = %q; want true and the default claim", o.AllowSignUp, o.GroupsClaim)
	}
	if o.DisplayName != "Example SSO" {
		t.Fatalf("DisplayName = %q, want Example SSO", o.DisplayName)
	}
}

// An operator who pastes the secret into the wrong variable gets an error that names
// the variable and does not repeat what they pasted.
func TestOIDCErrorsNeverQuoteTheSecret(t *testing.T) {
	for _, name := range []string{
		"LLMPROXY_OIDC_REDIRECT_URL",
		"LLMPROXY_OIDC_ALLOW_SIGNUP",
		"LLMPROXY_OIDC_GROUP_POLICY",
	} {
		t.Run(name, func(t *testing.T) {
			setOIDCEnv(t, map[string]string{name: testSecret})
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("err = %v, want an error naming %s", err, name)
			}
			if strings.Contains(err.Error(), testSecret) {
				t.Fatalf("error quotes the secret: %v", err)
			}
		})
	}
}

// testSessionKey is 40 bytes: a valid LLMPROXY_SESSION_KEY. No assertion may print it.
const testSessionKey = "k3y-material-that-must-never-be-printed!"

// setWebEnv sets a complete, valid web listener configuration and then applies
// overrides; an override of "" unsets that variable for the test.
func setWebEnv(t *testing.T, overrides map[string]string) {
	t.Helper()
	env := map[string]string{
		"LLMPROXY_DATABASE_URL":   "postgres://u:p@localhost:5432/db",
		"LLMPROXY_WEB_ADDR":       "",
		"LLMPROXY_LISTEN_ADDR":    "",
		"LLMPROXY_METRICS_ADDR":   "",
		"LLMPROXY_PUBLIC_API_URL": "https://api.example.com",
		"LLMPROXY_COOKIE_SECURE":  "",
		"LLMPROXY_SESSION_KEY":    testSessionKey,
		"LLMPROXY_LOCAL_LOGIN":    "",
	}
	maps.Copy(env, overrides)
	for k, v := range env {
		t.Setenv(k, v)
	}
}

func TestWebDefaultsToALoopbackListenerWithSecureCookies(t *testing.T) {
	setWebEnv(t, map[string]string{"LLMPROXY_SESSION_KEY": ""})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Web.Addr != "127.0.0.1:8081" || !cfg.Web.CookieSecure {
		t.Fatalf("Web.Addr = %q, CookieSecure = %t; want 127.0.0.1:8081 and true", cfg.Web.Addr, cfg.Web.CookieSecure)
	}
	// Without OIDC nothing is sealed, so no key is demanded.
	if cfg.Web.SessionKey != nil {
		t.Fatal("a session key appeared from nowhere")
	}
}

// The contract promises apiBaseURL without a trailing slash; clients append paths.
func TestWebPublicAPIURLIsRequiredAndLosesItsTrailingSlash(t *testing.T) {
	setWebEnv(t, map[string]string{"LLMPROXY_PUBLIC_API_URL": "https://api.example.com/llm/"})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Web.PublicAPIURL != "https://api.example.com/llm" {
		t.Fatalf("PublicAPIURL = %q, want https://api.example.com/llm", cfg.Web.PublicAPIURL)
	}

	for _, bad := range []string{"", "api.example.com", "ftp://api.example.com", "https://u:pw@api.example.com"} {
		setWebEnv(t, map[string]string{"LLMPROXY_PUBLIC_API_URL": bad})
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "LLMPROXY_PUBLIC_API_URL") {
			t.Fatalf("%q: err = %v, want one naming LLMPROXY_PUBLIC_API_URL", bad, err)
		}
	}
}

func TestWebOffIgnoresTheOtherVariables(t *testing.T) {
	setWebEnv(t, map[string]string{
		"LLMPROXY_WEB_ADDR":       WebAddrOff,
		"LLMPROXY_PUBLIC_API_URL": "",
		"LLMPROXY_COOKIE_SECURE":  "maybe",
	})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Web.Enabled() {
		t.Fatalf("Web.Addr = %q, want the listener off", cfg.Web.Addr)
	}
}

func TestWebCookieSecureCanBeTurnedOffOnlyExplicitly(t *testing.T) {
	setWebEnv(t, map[string]string{"LLMPROXY_COOKIE_SECURE": "false"})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Web.CookieSecure {
		t.Fatal("CookieSecure = true, want false")
	}
	setWebEnv(t, map[string]string{"LLMPROXY_COOKIE_SECURE": "no thanks"})
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "LLMPROXY_COOKIE_SECURE") {
		t.Fatalf("err = %v, want one naming LLMPROXY_COOKIE_SECURE", err)
	}
}

// Local sign-in is on unless turned off explicitly, and a value that is not a
// boolean stops the start rather than silently choosing either way.
func TestWebLocalLoginIsOnUnlessTurnedOff(t *testing.T) {
	for raw, want := range map[string]bool{"": true, "true": true, "false": false} {
		setWebEnv(t, map[string]string{"LLMPROXY_LOCAL_LOGIN": raw})
		cfg, err := Load()
		if err != nil {
			t.Fatalf("%q: Load: %v", raw, err)
		}
		if cfg.Web.LocalLogin != want {
			t.Fatalf("LLMPROXY_LOCAL_LOGIN=%q: LocalLogin = %t, want %t", raw, cfg.Web.LocalLogin, want)
		}
	}
	setWebEnv(t, map[string]string{"LLMPROXY_LOCAL_LOGIN": "off"})
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "LLMPROXY_LOCAL_LOGIN") {
		t.Fatalf("err = %v, want one naming LLMPROXY_LOCAL_LOGIN", err)
	}
}

// The key seals the OIDC challenge. OIDC without one cannot start; a short one is
// refused whatever else is configured. Neither error repeats what was set.
func TestWebSessionKeyIsRequiredForOIDCAndNeverQuoted(t *testing.T) {
	short := testSessionKey[:MinSessionKeyLen-1]
	for name, overrides := range map[string]map[string]string{
		"missing with OIDC": {"LLMPROXY_SESSION_KEY": ""},
		"short with OIDC":   {"LLMPROXY_SESSION_KEY": short},
	} {
		t.Run(name, func(t *testing.T) {
			setOIDCEnv(t, overrides)
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), "LLMPROXY_SESSION_KEY") {
				t.Fatalf("err = %v, want one naming LLMPROXY_SESSION_KEY", err)
			}
			if strings.Contains(err.Error(), short) {
				t.Fatal("the error quotes the key")
			}
		})
	}
	t.Run("short without OIDC", func(t *testing.T) {
		setWebEnv(t, map[string]string{"LLMPROXY_SESSION_KEY": short})
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "LLMPROXY_SESSION_KEY") {
			t.Fatalf("err = %v, want one naming LLMPROXY_SESSION_KEY", err)
		}
	})

	setOIDCEnv(t, nil)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(cfg.Web.SessionKey) != testSessionKey {
		t.Fatal("SessionKey is not the configured key")
	}
}

// Config is the kind of value that ends up in a startup log line or a panic. The
// session key must not come with it, however it is formatted.
func TestFormattingTheConfigNeverPrintsTheSessionKey(t *testing.T) {
	setWebEnv(t, nil)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if strings.Contains(fmt.Sprintf(verb, cfg), testSessionKey) {
			t.Fatalf("formatting the config with %s prints the session key", verb)
		}
	}
}
