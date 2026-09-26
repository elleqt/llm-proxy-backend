package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	// ListenAddr is LLMPROXY_LISTEN_ADDR, default :8080: the proxied API, the one
	// listener published to the reverse proxy.
	ListenAddr string
	// MetricsAddr is LLMPROXY_METRICS_ADDR, default 127.0.0.1:9090: /metrics, for a
	// scraper inside the deployment network only.
	MetricsAddr string
	DatabaseURL string
	// CredentialsKey is LLMPROXY_CREDENTIALS_KEY, at least MinCredentialsKeyLen
	// bytes: the key the vendor accounts' OAuth credentials are sealed with in the
	// database (credentials.NewSealer). Required; a lost or changed key means
	// signing every vendor account in again.
	CredentialsKey Secret
	// RuntimeDir is LLMPROXY_RUNTIME_DIR: the working directory upstream requires a
	// path for. Nothing is written to it (the gateway installs no request logger)
	// and no configuration file is read from it.
	RuntimeDir string
	// AuthDir is LLMPROXY_AUTH_DIR: the vendor sign-in's scratch directory; in its
	// .login subdirectory upstream hands the OAuth callback to the login for about a
	// second. The vendor accounts themselves are in Postgres (gateway.CredentialStore).
	// COMPAT(credentials-import): it is also the source of the one-shot import of the
	// account files an earlier release kept here; remove next release (RELEASING.md).
	AuthDir string
	// BootstrapAdminEmail is LLMPROXY_BOOTSTRAP_ADMIN_EMAIL: the address of the first
	// administrator, created with a one-time password when no administrator exists.
	// Optional. Empty disables the bootstrap, which leaves an installation without an
	// administrator unreachable except through the database.
	BootstrapAdminEmail string
	// PasswordHashConcurrency is LLMPROXY_PASSWORD_HASH_CONCURRENCY: how many argon2
	// derivations (about 19 MiB each) may run at once. Defaults to the CPU count.
	PasswordHashConcurrency int
	// ModelCatalogUpdates is LLMPROXY_MODEL_CATALOG_UPDATES, on unless it is
	// ModelCatalogUpdatesOff: whether the embedded gateway keeps its model
	// catalogue current from upstream's published catalogue, fetched over the
	// network at start and every three hours. Off, it serves the catalogue
	// compiled into the build.
	ModelCatalogUpdates bool
	// LogFormat is LLMPROXY_LOG_FORMAT, LogFormatText unless it is LogFormatJSON:
	// how the process log's records are written.
	LogFormat    string
	OIDC         OIDC
	Web          Web
	PriceCatalog PriceCatalog
}

// PriceCatalogOff is the LLMPROXY_PRICES_CATALOG_URL value that turns the price
// catalog off.
const PriceCatalogOff = "off"

// DefaultPriceCatalogURL is the model catalog of oh-my-pi (MIT), whose per-model
// costs are the catalog's prices.
const DefaultPriceCatalogURL = "https://raw.githubusercontent.com/can1357/oh-my-pi/main/packages/catalog/src/models.json"

// MinPriceCatalogInterval is the shortest LLMPROXY_PRICES_CATALOG_INTERVAL accepted.
const MinPriceCatalogInterval = 5 * time.Minute

// PriceCatalog configures the automatically updated price catalog. It is on unless
// LLMPROXY_PRICES_CATALOG_URL is PriceCatalogOff; while it is off Interval is
// ignored and not validated.
type PriceCatalog struct {
	// URL is LLMPROXY_PRICES_CATALOG_URL, default DefaultPriceCatalogURL: an
	// absolute http(s) URL. Empty when off.
	URL string
	// Interval is LLMPROXY_PRICES_CATALOG_INTERVAL, default 6h, at least
	// MinPriceCatalogInterval: how often the catalog is checked.
	Interval time.Duration
}

func (p PriceCatalog) Enabled() bool { return p.URL != "" }

// WebAddrOff is the LLMPROXY_WEB_ADDR value that turns the web listener off.
const WebAddrOff = "off"

// ModelCatalogUpdatesOff is the LLMPROXY_MODEL_CATALOG_UPDATES value that turns
// the model catalogue updates off; ModelCatalogUpdatesOn, or no value, keeps them on.
const (
	ModelCatalogUpdatesOff = "off"
	ModelCatalogUpdatesOn  = "on"
)

// LogFormatText and LogFormatJSON are the LLMPROXY_LOG_FORMAT values: one
// key=value line per record, or one JSON object per record. No value is text.
const (
	LogFormatText = "text"
	LogFormatJSON = "json"
)

// Web configures the browser-facing API's listener (internal/iface/http). It is on
// unless LLMPROXY_WEB_ADDR is WebAddrOff; while it is off every other field is
// ignored and not validated.
type Web struct {
	// Addr is LLMPROXY_WEB_ADDR, default 127.0.0.1:8081. The listener is meant to be
	// reachable only from the frontend's reverse proxy, which is also what makes its
	// X-Real-IP header trustworthy.
	Addr string
	// PublicAPIURL is LLMPROXY_PUBLIC_API_URL: the absolute http(s) base URL clients
	// reach the proxied API at, without a trailing slash. Required.
	PublicAPIURL string
	// CookieSecure is LLMPROXY_COOKIE_SECURE, default true. false is for local
	// development over plain http only.
	CookieSecure bool
	// SessionKey is LLMPROXY_SESSION_KEY, at least MinSessionKeyLen bytes. It seals
	// the OpenID Connect login challenge cookie, so it is required only when OIDC is
	// enabled.
	SessionKey Secret
	// LocalLogin is LLMPROXY_LOCAL_LOGIN, default true: whether people may sign in
	// with an email and a password. false leaves OpenID Connect as the only way in;
	// setting it back to true is the way back in if the identity provider fails.
	LocalLogin bool
}

func (w Web) Enabled() bool { return w.Addr != "" }

// MinSessionKeyLen is the shortest LLMPROXY_SESSION_KEY accepted: 32 bytes, the size
// of the AES-256 key derived from it.
const MinSessionKeyLen = 32

// MinCredentialsKeyLen is the shortest LLMPROXY_CREDENTIALS_KEY accepted: 32 bytes,
// the size of the AES-256 key derived from it. credentials.MinSealerKeyLen is the
// same floor.
const MinCredentialsKeyLen = 32

// composeCredentialsKey is the placeholder LLMPROXY_CREDENTIALS_KEY the shipped
// compose files carry. It passes the length check but is public, so Load refuses it.
const composeCredentialsKey = "change-me-credentials-key-at-least-32-bytes" //nolint:gosec // G101: the public placeholder refused here, not a credential.

// Secret is key material that must not reach a log line: whatever verb formats it,
// it prints as a placeholder.
type Secret []byte

func (Secret) String() string   { return "[redacted]" }
func (Secret) GoString() string { return "[redacted]" }

// OIDC is the federated sign-in configuration. It is enabled iff Issuer is set; every
// other field is ignored — and not validated — while it is not.
type OIDC struct {
	Issuer        string
	ClientID      string
	ClientSecret  string
	RedirectURL   string
	RequiredGroup string
	AllowSignUp   bool
	// DefaultPolicy and GroupPolicy hold rule strings as written. Their syntax is
	// checked by auth.NewOIDC, which owns what they mean.
	DefaultPolicy []string
	GroupPolicy   map[string][]string
	GroupsClaim   string
	// DisplayName is LLMPROXY_OIDC_DISPLAY_NAME: the sign-in button's label, such as
	// the identity provider's name. Empty leaves the label to the frontend.
	DisplayName string
}

func (o OIDC) Enabled() bool { return o.Issuer != "" }

// ListenHostPort is ListenAddr as the embedded upstream server takes it. Upstream
// joins the two as "host:port" (internal/api/server.go NewServer), so an IPv6
// host keeps its brackets.
func (c Config) ListenHostPort() (string, int) {
	host, port, _ := splitAddr(c.ListenAddr)
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}

	return host, port
}

// splitAddr splits a listen address host:port whose port is a number from 1 to
// 65535; the host may be empty (every interface).
func splitAddr(addr string) (string, int, bool) {
	host, raw, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, false
	}

	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, false
	}

	return host, port, true
}

// errConfig prefixes every error Load and LoadDatabase return, so each message
// reads "config: <variable> …". The messages name the variable and never quote
// its value.
var errConfig = errors.New("config")

// checkAddr refuses a listen address splitAddr cannot split — an IPv6 host must
// be in brackets — naming the variable.
func checkAddr(name, addr string) error {
	if _, _, ok := splitAddr(addr); !ok {
		return fmt.Errorf("%w: %s must be host:port with a port from 1 to 65535", errConfig, name)
	}

	return nil
}

// parseHTTPURL parses raw as an absolute http(s) URL with a host; ok is false
// for anything else.
func parseHTTPURL(raw string) (*url.URL, bool) {
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
		return nil, false
	}

	return parsed, true
}

func Load() (Config, error) {
	db, err := LoadDatabase()
	if err != nil {
		return Config{}, err
	}

	key, err := loadCredentialsKey()
	if err != nil {
		return Config{}, err
	}

	cfg := Config{
		ListenAddr:              envOr("LLMPROXY_LISTEN_ADDR", ":8080"),
		MetricsAddr:             envOr("LLMPROXY_METRICS_ADDR", "127.0.0.1:9090"),
		DatabaseURL:             db.URL,
		CredentialsKey:          key,
		RuntimeDir:              envOr("LLMPROXY_RUNTIME_DIR", "/var/lib/llmproxy/runtime"),
		AuthDir:                 envOr("LLMPROXY_AUTH_DIR", "/var/lib/llmproxy/auths"),
		BootstrapAdminEmail:     strings.TrimSpace(os.Getenv("LLMPROXY_BOOTSTRAP_ADMIN_EMAIL")),
		PasswordHashConcurrency: db.PasswordHashConcurrency,
	}
	if err := checkAddr("LLMPROXY_LISTEN_ADDR", cfg.ListenAddr); err != nil {
		return Config{}, err
	}

	if err := checkAddr("LLMPROXY_METRICS_ADDR", cfg.MetricsAddr); err != nil {
		return Config{}, err
	}

	switch os.Getenv("LLMPROXY_MODEL_CATALOG_UPDATES") {
	case "", ModelCatalogUpdatesOn:
		cfg.ModelCatalogUpdates = true
	case ModelCatalogUpdatesOff:
	default:
		return Config{}, fmt.Errorf("%w: LLMPROXY_MODEL_CATALOG_UPDATES must be on or off", errConfig)
	}

	switch os.Getenv("LLMPROXY_LOG_FORMAT") {
	case "", LogFormatText:
		cfg.LogFormat = LogFormatText
	case LogFormatJSON:
		cfg.LogFormat = LogFormatJSON
	default:
		return Config{}, fmt.Errorf("%w: LLMPROXY_LOG_FORMAT must be text or json", errConfig)
	}

	oidc, err := loadOIDC()
	if err != nil {
		return Config{}, err
	}

	cfg.OIDC = oidc

	web, err := loadWeb(oidc.Enabled())
	if err != nil {
		return Config{}, err
	}

	cfg.Web = web

	catalog, err := loadPriceCatalog()
	if err != nil {
		return Config{}, err
	}

	cfg.PriceCatalog = catalog

	return cfg, nil
}

// Database is the part of the configuration a command that only works on the
// accounts in the database needs (gateway reset-password): where the database is,
// how many password derivations may run at once, and whether the server accepts a
// password sign-in at all.
type Database struct {
	URL                     string
	PasswordHashConcurrency int
	// LocalLogin is false when the web listener is off (LLMPROXY_WEB_ADDR) or
	// LLMPROXY_LOCAL_LOGIN is false: the server then signs nobody in with a password.
	// Read leniently: a value the server would refuse to start with counts as on.
	LocalLogin bool
}

// LoadDatabase reads LLMPROXY_DATABASE_URL and LLMPROXY_PASSWORD_HASH_CONCURRENCY
// exactly as Load does, and LocalLogin as Load does but without ever failing on it:
// a variable only the listeners, the gateway or OIDC read cannot stop such a command.
func LoadDatabase() (Database, error) {
	db := Database{URL: os.Getenv("LLMPROXY_DATABASE_URL"), PasswordHashConcurrency: runtime.NumCPU(), LocalLogin: true}
	if db.URL == "" {
		return Database{}, fmt.Errorf("%w: LLMPROXY_DATABASE_URL is required", errConfig)
	}

	if raw := os.Getenv("LLMPROXY_PASSWORD_HASH_CONCURRENCY"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			return Database{}, fmt.Errorf("%w: LLMPROXY_PASSWORD_HASH_CONCURRENCY must be a positive integer", errConfig)
		}

		db.PasswordHashConcurrency = n
	}

	if envOr("LLMPROXY_WEB_ADDR", defaultWebAddr) == WebAddrOff {
		db.LocalLogin = false
	} else if on, err := localLogin(); err == nil {
		db.LocalLogin = on
	}

	return db, nil
}

// loadCredentialsKey reads LLMPROXY_CREDENTIALS_KEY. Load reads it right after
// LLMPROXY_DATABASE_URL, so a process started with no environment at all still
// reports the database URL first (the CI image smoke test checks that message);
// LoadDatabase does not read it, so gateway reset-password runs without it. The
// compose files' placeholder is refused. Its errors name the variable and never
// quote the value.
func loadCredentialsKey() (Secret, error) {
	key := os.Getenv("LLMPROXY_CREDENTIALS_KEY")

	switch {
	case key == "":
		return nil, fmt.Errorf("%w: LLMPROXY_CREDENTIALS_KEY is required", errConfig)
	case len(key) < MinCredentialsKeyLen:
		return nil, fmt.Errorf("%w: LLMPROXY_CREDENTIALS_KEY must be at least %d bytes", errConfig, MinCredentialsKeyLen)
	case key == composeCredentialsKey:
		return nil, fmt.Errorf("%w: LLMPROXY_CREDENTIALS_KEY is still the compose files' placeholder: "+
			"generate a key (openssl rand -hex 32) and keep it with your other secrets", errConfig)
	}

	return Secret(key), nil
}

// loadPriceCatalog reads the LLMPROXY_PRICES_CATALOG_* variables.
func loadPriceCatalog() (PriceCatalog, error) {
	raw := envOr("LLMPROXY_PRICES_CATALOG_URL", DefaultPriceCatalogURL)
	if raw == PriceCatalogOff {
		return PriceCatalog{}, nil
	}

	if _, ok := parseHTTPURL(raw); !ok {
		return PriceCatalog{}, fmt.Errorf("%w: LLMPROXY_PRICES_CATALOG_URL must be an absolute http(s) URL or off", errConfig)
	}

	interval, err := time.ParseDuration(envOr("LLMPROXY_PRICES_CATALOG_INTERVAL", "6h"))
	if err != nil || interval < MinPriceCatalogInterval {
		return PriceCatalog{}, fmt.Errorf("%w: LLMPROXY_PRICES_CATALOG_INTERVAL must be a duration of at least %s",
			errConfig, MinPriceCatalogInterval)
	}

	return PriceCatalog{URL: raw, Interval: interval}, nil
}

// loadWeb reads the web listener's variables. Like loadOIDC, its errors name the
// variable and never quote a value: LLMPROXY_SESSION_KEY is one of them.
func loadWeb(oidcEnabled bool) (Web, error) {
	web := Web{Addr: envOr("LLMPROXY_WEB_ADDR", defaultWebAddr), CookieSecure: true, LocalLogin: true}
	if web.Addr == WebAddrOff {
		return Web{}, nil
	}

	if err := checkAddr("LLMPROXY_WEB_ADDR", web.Addr); err != nil {
		return Web{}, err
	}

	raw := os.Getenv("LLMPROXY_PUBLIC_API_URL")
	if raw == "" {
		return Web{}, fmt.Errorf("%w: LLMPROXY_PUBLIC_API_URL is required while the web listener is on", errConfig)
	}

	if parsed, ok := parseHTTPURL(raw); !ok || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return Web{}, fmt.Errorf("%w: LLMPROXY_PUBLIC_API_URL must be an absolute http(s) URL without query, fragment or credentials",
			errConfig)
	}

	web.PublicAPIURL = strings.TrimRight(raw, "/")

	if raw := os.Getenv("LLMPROXY_COOKIE_SECURE"); raw != "" {
		v, err := strconv.ParseBool(raw)
		if err != nil {
			return Web{}, fmt.Errorf("%w: LLMPROXY_COOKIE_SECURE must be true or false", errConfig)
		}

		web.CookieSecure = v
	}

	var err error
	if web.LocalLogin, err = localLogin(); err != nil {
		return Web{}, err
	}

	key := os.Getenv("LLMPROXY_SESSION_KEY")
	switch {
	case key == "" && oidcEnabled:
		return Web{}, fmt.Errorf("%w: LLMPROXY_SESSION_KEY is required when LLMPROXY_OIDC_ISSUER is set", errConfig)
	case key != "" && len(key) < MinSessionKeyLen:
		return Web{}, fmt.Errorf("%w: LLMPROXY_SESSION_KEY must be at least %d bytes", errConfig, MinSessionKeyLen)
	case key != "":
		web.SessionKey = Secret(key)
	}

	return web, nil
}

const defaultWebAddr = "127.0.0.1:8081"

// localLogin reads LLMPROXY_LOCAL_LOGIN, on unless false.
func localLogin() (bool, error) {
	raw := os.Getenv("LLMPROXY_LOCAL_LOGIN")
	if raw == "" {
		return true, nil
	}

	v, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%w: LLMPROXY_LOCAL_LOGIN must be true or false", errConfig)
	}

	return v, nil
}

// loadOIDC reads the LLMPROXY_OIDC_* variables. Errors name the variable and never
// quote a value: the client secret is one of them, and the others sit next to it in
// the same environment dump an operator pastes into a ticket.
func loadOIDC() (OIDC, error) {
	oidc := OIDC{Issuer: os.Getenv("LLMPROXY_OIDC_ISSUER")}
	if !oidc.Enabled() {
		return OIDC{}, nil
	}

	oidc.ClientID = os.Getenv("LLMPROXY_OIDC_CLIENT_ID")
	oidc.ClientSecret = os.Getenv("LLMPROXY_OIDC_CLIENT_SECRET")
	oidc.RedirectURL = os.Getenv("LLMPROXY_OIDC_REDIRECT_URL")
	oidc.RequiredGroup = os.Getenv("LLMPROXY_OIDC_REQUIRED_GROUP")
	oidc.GroupsClaim = envOr("LLMPROXY_OIDC_GROUPS_CLAIM", "groups")
	oidc.DisplayName = strings.TrimSpace(os.Getenv("LLMPROXY_OIDC_DISPLAY_NAME"))

	for _, req := range []struct{ name, value string }{
		{"LLMPROXY_OIDC_CLIENT_ID", oidc.ClientID},
		{"LLMPROXY_OIDC_CLIENT_SECRET", oidc.ClientSecret},
		{"LLMPROXY_OIDC_REDIRECT_URL", oidc.RedirectURL},
	} {
		if req.value == "" {
			return OIDC{}, fmt.Errorf("%w: %s is required when LLMPROXY_OIDC_ISSUER is set", errConfig, req.name)
		}
	}

	if _, ok := parseHTTPURL(oidc.RedirectURL); !ok {
		return OIDC{}, fmt.Errorf("%w: LLMPROXY_OIDC_REDIRECT_URL must be an absolute http(s) URL", errConfig)
	}

	if raw := os.Getenv("LLMPROXY_OIDC_ALLOW_SIGNUP"); raw != "" {
		v, err := strconv.ParseBool(raw)
		if err != nil {
			return OIDC{}, fmt.Errorf("%w: LLMPROXY_OIDC_ALLOW_SIGNUP must be true or false", errConfig)
		}

		oidc.AllowSignUp = v
	}

	oidc.DefaultPolicy = splitList(os.Getenv("LLMPROXY_OIDC_DEFAULT_POLICY"), ",")

	gp, err := parseGroupPolicy(os.Getenv("LLMPROXY_OIDC_GROUP_POLICY"))
	if err != nil {
		return OIDC{}, err
	}

	oidc.GroupPolicy = gp

	return oidc, nil
}

// parseGroupPolicy reads `group=rule,rule;group=rule`. Only the structure is checked
// here; rule syntax is auth.NewOIDC's.
func parseGroupPolicy(raw string) (map[string][]string, error) {
	entries := splitList(raw, ";")
	if len(entries) == 0 {
		return nil, nil //nolint:nilnil // no group policy is a nil map, not an error
	}

	const bad = "%w: LLMPROXY_OIDC_GROUP_POLICY entry %d: %s"

	out := make(map[string][]string, len(entries))
	for idx, entry := range entries {
		group, rules, found := strings.Cut(entry, "=")

		group = strings.TrimSpace(group)
		if !found || group == "" {
			return nil, fmt.Errorf(bad, errConfig, idx+1, "want group=rule[,rule]")
		}

		if _, dup := out[group]; dup {
			return nil, fmt.Errorf(bad, errConfig, idx+1, "group mapped twice")
		}

		list := splitList(rules, ",")
		if len(list) == 0 {
			return nil, fmt.Errorf(bad, errConfig, idx+1, "group maps to no rules")
		}

		out[group] = list
	}

	return out, nil
}

// splitList splits on sep, trims, and drops empty items, so a trailing separator or
// a space after a comma is not an entry.
func splitList(raw, sep string) []string {
	var out []string

	for item := range strings.SplitSeq(raw, sep) {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}

	return out
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}

	return fallback
}
