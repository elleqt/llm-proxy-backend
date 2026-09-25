package config

import (
	"bytes"
	"fmt"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadRequiresDatabaseURL(t *testing.T) {
	t.Setenv("LLMPROXY_DATABASE_URL", "")

	_, err := Load()
	require.Error(t, err, "expected error when LLMPROXY_DATABASE_URL is empty")
}

func TestLoadDefaults(t *testing.T) {
	setWebEnv(t, nil)
	t.Setenv("LLMPROXY_LISTEN_ADDR", "")
	t.Setenv("LLMPROXY_RUNTIME_DIR", "")
	t.Setenv("LLMPROXY_AUTH_DIR", "")
	t.Setenv("LLMPROXY_PASSWORD_HASH_CONCURRENCY", "")
	t.Setenv("LLMPROXY_DATABASE_URL", "postgres://u:p@localhost:5432/db")

	cfg, err := Load()
	require.NoError(t, err)

	require.Equal(t, ":8080", cfg.ListenAddr, "ListenAddr")
	// Metrics stay off every non-loopback interface unless the operator says so.
	require.Equal(t, "127.0.0.1:9090", cfg.MetricsAddr, "MetricsAddr")
	require.Equal(t, "/var/lib/llmproxy/runtime", cfg.RuntimeDir, "RuntimeDir")
	require.Equal(t, "/var/lib/llmproxy/auths", cfg.AuthDir, "AuthDir")
	// Zero would deadlock every sign-in on the semaphore.
	require.GreaterOrEqual(t, cfg.PasswordHashConcurrency, 1, "PasswordHashConcurrency, want a positive default")
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
	require.NoError(t, err)

	host, port := cfg.ListenHostPort()
	require.Equal(t, "127.0.0.1", host, "ListenHostPort() host")
	require.Equal(t, 9191, port, "ListenHostPort() port")
	require.Equal(t, ":9292", cfg.MetricsAddr, "MetricsAddr")
	require.Equal(t, "postgres://user:pass@db.example.com:5432/gateway", cfg.DatabaseURL, "DatabaseURL")
	require.Equal(t, "/tmp/runtime", cfg.RuntimeDir, "RuntimeDir")
	require.Equal(t, "/tmp/auths", cfg.AuthDir, "AuthDir")
	// The name is fixed by the docker-compose files; reading any other
	// spelling silently disables the bootstrap on a fresh install.
	require.Equal(t, "admin@example.com", cfg.BootstrapAdminEmail, "BootstrapAdminEmail")
	require.Equal(t, 3, cfg.PasswordHashConcurrency, "PasswordHashConcurrency")
}

// A non-positive capacity would deadlock every sign-in; refusing to start says so.
func TestLoadRejectsANonPositiveHashConcurrency(t *testing.T) {
	setWebEnv(t, nil)
	t.Setenv("LLMPROXY_DATABASE_URL", "postgres://u:p@localhost:5432/db")

	for _, raw := range []string{"0", "-1", "many"} {
		t.Setenv("LLMPROXY_PASSWORD_HASH_CONCURRENCY", raw)

		_, err := Load()
		require.ErrorContains(t, err, "LLMPROXY_PASSWORD_HASH_CONCURRENCY", "%q", raw)
	}
}

// gateway reset-password is how an operator gets back in when something is wrong,
// so a setting only the server reads — here an incomplete OIDC configuration and a
// malformed listener — must not stop it, while the two it uses are read as Load
// reads them.
func TestLoadDatabaseReadsOnlyWhatTheDatabaseNeeds(t *testing.T) {
	setOIDCEnv(t, map[string]string{"LLMPROXY_OIDC_CLIENT_SECRET": "", "LLMPROXY_LISTEN_ADDR": "8080"})

	_, err := Load()
	require.Error(t, err, "Load accepted the broken server settings this test relies on")

	t.Setenv("LLMPROXY_PASSWORD_HASH_CONCURRENCY", "3")

	db, err := LoadDatabase()
	require.NoError(t, err, "LoadDatabase")
	require.Equal(t, "postgres://u:p@localhost:5432/db", db.URL, "LoadDatabase URL")
	require.Equal(t, 3, db.PasswordHashConcurrency, "LoadDatabase PasswordHashConcurrency")

	t.Setenv("LLMPROXY_DATABASE_URL", "")

	_, err = LoadDatabase()
	require.Error(t, err, "LoadDatabase accepted no LLMPROXY_DATABASE_URL")
}

// reset-password warns when the password it issues cannot be used: the server takes
// no password sign-in with local login off or the web listener off. A value the
// server would refuse is not the command's to judge, and fails nothing.
func TestLoadDatabaseTellsWhetherTheServerTakesPasswords(t *testing.T) {
	for _, tc := range []struct {
		webAddr, localLogin string
		want                bool
	}{
		{"", "", true},
		{"", "true", true},
		{"", "false", false},
		{WebAddrOff, "true", false},
		{"", "maybe", true},
	} {
		setWebEnv(t, map[string]string{"LLMPROXY_WEB_ADDR": tc.webAddr, "LLMPROXY_LOCAL_LOGIN": tc.localLogin})

		db, err := LoadDatabase()
		require.NoError(t, err, "web %q, local login %q", tc.webAddr, tc.localLogin)
		require.Equal(t, tc.want, db.LocalLogin, "web %q, local login %q: LocalLogin", tc.webAddr, tc.localLogin)
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

	got, err := load("", "")
	require.NoError(t, err, "defaults")
	require.True(t, got.Enabled(), "defaults: want enabled")
	require.Equal(t, DefaultPriceCatalogURL, got.URL, "defaults: want the default URL")
	require.Equal(t, 6*time.Hour, got.Interval, "defaults: want every 6h")

	got, err = load("http://catalog.example.com/models.json", "5m")
	require.NoError(t, err, "5m: want accepted")
	require.Equal(t, 5*time.Minute, got.Interval, "5m: want accepted")

	got, err = load(PriceCatalogOff, "nonsense")
	require.NoError(t, err, "off: want the interval ignored")
	require.False(t, got.Enabled(), "off: want disabled")

	for _, tc := range []struct{ url, interval, name string }{
		{"", "4m59s", "LLMPROXY_PRICES_CATALOG_INTERVAL"},
		{"", "6", "LLMPROXY_PRICES_CATALOG_INTERVAL"},
		{"catalog.example.com/models.json", "", "LLMPROXY_PRICES_CATALOG_URL"},
		{"ftp://catalog.example.com/models.json", "", "LLMPROXY_PRICES_CATALOG_URL"},
	} {
		_, err := load(tc.url, tc.interval)
		assert.ErrorContains(t, err, tc.name, "%q every %q", tc.url, tc.interval)
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
		require.NoError(t, err, "%q", raw)
		require.Equal(t, want, cfg.ModelCatalogUpdates, "%q: ModelCatalogUpdates", raw)
	}

	for _, raw := range []string{"false", "OFF", "no"} {
		t.Setenv("LLMPROXY_MODEL_CATALOG_UPDATES", raw)

		_, err := Load()
		require.ErrorContains(t, err, "LLMPROXY_MODEL_CATALOG_UPDATES", "%q", raw)
	}
}

// The log format is text unless the operator asks for json; a misspelt value
// stops the start rather than silently choosing either way.
func TestLogFormatIsTextUnlessJSON(t *testing.T) {
	setWebEnv(t, nil)
	t.Setenv("LLMPROXY_DATABASE_URL", "postgres://u:p@localhost:5432/db")

	for raw, want := range map[string]string{"": LogFormatText, LogFormatText: LogFormatText, LogFormatJSON: LogFormatJSON} {
		t.Setenv("LLMPROXY_LOG_FORMAT", raw)

		cfg, err := Load()
		require.NoError(t, err, "%q", raw)
		require.Equal(t, want, cfg.LogFormat, "%q: LogFormat", raw)
	}

	for _, raw := range []string{"JSON", "logfmt", "yaml"} {
		t.Setenv("LLMPROXY_LOG_FORMAT", raw)

		_, err := Load()
		require.ErrorContains(t, err, "LLMPROXY_LOG_FORMAT", "%q", raw)
	}
}

// A listen address the server cannot bind as given is refused at start, naming the
// variable, rather than failing later inside upstream or binding a random port.
func TestLoadRejectsAMalformedListenAddress(t *testing.T) {
	for _, name := range []string{"LLMPROXY_LISTEN_ADDR", "LLMPROXY_WEB_ADDR", "LLMPROXY_METRICS_ADDR"} {
		for _, bad := range []string{"8080", ":http", ":0", ":70000", "::1:8080"} {
			setWebEnv(t, map[string]string{name: bad})

			_, err := Load()
			require.ErrorContains(t, err, name, "%s=%q", name, bad)
		}
	}
}

// Upstream joins the proxied listener's host and port with a bare colon
// (internal/api/server.go NewServer), so an IPv6 host must reach it bracketed, or
// its listener fails with "too many colons".
func TestAnIPv6ListenAddressReachesUpstreamBracketed(t *testing.T) {
	setWebEnv(t, map[string]string{"LLMPROXY_LISTEN_ADDR": "[::1]:9191"})

	cfg, err := Load()
	require.NoError(t, err, "Load")

	host, port := cfg.ListenHostPort()
	require.Equal(t, "[::1]", host, "ListenHostPort() host")
	require.Equal(t, 9191, port, "ListenHostPort() port")
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
			require.ErrorContains(t, err, name)
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
	require.NoError(t, err, "Load")
	require.False(t, cfg.OIDC.Enabled(), "OIDC = %+v, want disabled", cfg.OIDC)
}

func TestOIDCParsesTheDocumentedExample(t *testing.T) {
	setOIDCEnv(t, map[string]string{
		"LLMPROXY_OIDC_GROUP_POLICY":   "/team-a=claude:*;/everyone=*:*",
		"LLMPROXY_OIDC_DEFAULT_POLICY": "claude:claude-sonnet-5, openai:gpt-*",
		"LLMPROXY_OIDC_ALLOW_SIGNUP":   "true",
		"LLMPROXY_OIDC_DISPLAY_NAME":   " Example SSO ",
	})

	cfg, err := Load()
	require.NoError(t, err, "Load")

	oidc := cfg.OIDC

	require.Equal(t, map[string][]string{
		"/team-a":   {"claude:*"},
		"/everyone": {"*:*"},
	}, oidc.GroupPolicy, "GroupPolicy")
	require.Equal(t, []string{"claude:claude-sonnet-5", "openai:gpt-*"}, oidc.DefaultPolicy, "DefaultPolicy")
	require.True(t, oidc.AllowSignUp, "AllowSignUp")
	require.Equal(t, "groups", oidc.GroupsClaim, "GroupsClaim, want the default claim")
	require.Equal(t, "Example SSO", oidc.DisplayName, "DisplayName")
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
			require.ErrorContains(t, err, name)
			require.NotContains(t, err.Error(), testSecret, "error quotes the secret")
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
	require.NoError(t, err, "Load")
	require.Equal(t, "127.0.0.1:8081", cfg.Web.Addr, "Web.Addr")
	require.True(t, cfg.Web.CookieSecure, "CookieSecure")
	// Without OIDC nothing is sealed, so no key is demanded.
	require.Nil(t, cfg.Web.SessionKey, "a session key appeared from nowhere")
}

// The contract promises apiBaseURL without a trailing slash; clients append paths.
func TestWebPublicAPIURLIsRequiredAndLosesItsTrailingSlash(t *testing.T) {
	setWebEnv(t, map[string]string{"LLMPROXY_PUBLIC_API_URL": "https://api.example.com/llm/"})

	cfg, err := Load()
	require.NoError(t, err, "Load")
	require.Equal(t, "https://api.example.com/llm", cfg.Web.PublicAPIURL, "PublicAPIURL")

	for _, bad := range []string{"", "api.example.com", "ftp://api.example.com", "https://u:pw@api.example.com"} {
		setWebEnv(t, map[string]string{"LLMPROXY_PUBLIC_API_URL": bad})

		_, err := Load()
		require.ErrorContains(t, err, "LLMPROXY_PUBLIC_API_URL", "%q", bad)
	}
}

func TestWebOffIgnoresTheOtherVariables(t *testing.T) {
	setWebEnv(t, map[string]string{
		"LLMPROXY_WEB_ADDR":       WebAddrOff,
		"LLMPROXY_PUBLIC_API_URL": "",
		"LLMPROXY_COOKIE_SECURE":  "maybe",
	})

	cfg, err := Load()
	require.NoError(t, err, "Load")
	require.False(t, cfg.Web.Enabled(), "Web.Addr = %q, want the listener off", cfg.Web.Addr)
}

func TestWebCookieSecureCanBeTurnedOffOnlyExplicitly(t *testing.T) {
	setWebEnv(t, map[string]string{"LLMPROXY_COOKIE_SECURE": "false"})

	cfg, err := Load()
	require.NoError(t, err, "Load")
	require.False(t, cfg.Web.CookieSecure, "CookieSecure")

	setWebEnv(t, map[string]string{"LLMPROXY_COOKIE_SECURE": "no thanks"})

	_, err = Load()
	require.ErrorContains(t, err, "LLMPROXY_COOKIE_SECURE")
}

// Local sign-in is on unless turned off explicitly, and a value that is not a
// boolean stops the start rather than silently choosing either way.
func TestWebLocalLoginIsOnUnlessTurnedOff(t *testing.T) {
	for raw, want := range map[string]bool{"": true, "true": true, "false": false} {
		setWebEnv(t, map[string]string{"LLMPROXY_LOCAL_LOGIN": raw})

		cfg, err := Load()
		require.NoError(t, err, "%q: Load", raw)
		require.Equal(t, want, cfg.Web.LocalLogin, "LLMPROXY_LOCAL_LOGIN=%q: LocalLogin", raw)
	}

	setWebEnv(t, map[string]string{"LLMPROXY_LOCAL_LOGIN": "off"})

	_, err := Load()
	require.ErrorContains(t, err, "LLMPROXY_LOCAL_LOGIN")
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
			require.ErrorContains(t, err, "LLMPROXY_SESSION_KEY")
			// Not NotContains: its failure message would print the key.
			quoted := strings.Contains(err.Error(), short)
			require.False(t, quoted, "the error quotes the key")
		})
	}

	t.Run("short without OIDC", func(t *testing.T) {
		setWebEnv(t, map[string]string{"LLMPROXY_SESSION_KEY": short})

		_, err := Load()
		require.ErrorContains(t, err, "LLMPROXY_SESSION_KEY")
	})

	setOIDCEnv(t, nil)

	cfg, err := Load()
	require.NoError(t, err, "Load")
	// Not Equal: its failure message would print the key.
	require.True(t, bytes.Equal([]byte(testSessionKey), cfg.Web.SessionKey), "SessionKey is not the configured key")
}

// Config is the kind of value that ends up in a startup log line or a panic. The
// session key must not come with it, however it is formatted.
func TestFormattingTheConfigNeverPrintsTheSessionKey(t *testing.T) {
	setWebEnv(t, nil)

	cfg, err := Load()
	require.NoError(t, err, "Load")

	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		// Not NotContains: its failure message would print the key.
		printed := strings.Contains(fmt.Sprintf(verb, cfg), testSessionKey)
		require.False(t, printed, "formatting the config with %s prints the session key", verb)
	}
}
