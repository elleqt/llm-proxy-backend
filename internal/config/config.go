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
	// RuntimeDir is LLMPROXY_RUNTIME_DIR: upstream's working directory, where its
	// request logs go. No configuration file is read from it.
	RuntimeDir string
	AuthDir    string
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
	OIDC                OIDC
	Web                 Web
	PriceCatalog        PriceCatalog
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
	// checked by app.NewOIDCService, which owns what they mean.
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

// checkAddr refuses a listen address splitAddr cannot split — an IPv6 host must
// be in brackets — naming the variable.
func checkAddr(name, addr string) error {
	if _, _, ok := splitAddr(addr); !ok {
		return fmt.Errorf("config: %s must be host:port with a port from 1 to 65535", name)
	}
	return nil
}

func Load() (Config, error) {
	db, err := LoadDatabase()
	if err != nil {
		return Config{}, err
	}
	cfg := Config{
		ListenAddr:              envOr("LLMPROXY_LISTEN_ADDR", ":8080"),
		MetricsAddr:             envOr("LLMPROXY_METRICS_ADDR", "127.0.0.1:9090"),
		DatabaseURL:             db.URL,
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
		return Config{}, errors.New("config: LLMPROXY_MODEL_CATALOG_UPDATES must be on or off")
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
// and how many password derivations may run at once.
type Database struct {
	URL                     string
	PasswordHashConcurrency int
}

// LoadDatabase reads LLMPROXY_DATABASE_URL and LLMPROXY_PASSWORD_HASH_CONCURRENCY
// exactly as Load does, and nothing else: a variable only the listeners, the gateway
// or OIDC read cannot stop such a command.
func LoadDatabase() (Database, error) {
	db := Database{URL: os.Getenv("LLMPROXY_DATABASE_URL"), PasswordHashConcurrency: runtime.NumCPU()}
	if db.URL == "" {
		return Database{}, errors.New("config: LLMPROXY_DATABASE_URL is required")
	}
	if raw := os.Getenv("LLMPROXY_PASSWORD_HASH_CONCURRENCY"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			return Database{}, errors.New("config: LLMPROXY_PASSWORD_HASH_CONCURRENCY must be a positive integer")
		}
		db.PasswordHashConcurrency = n
	}
	return db, nil
}

// loadPriceCatalog reads the LLMPROXY_PRICES_CATALOG_* variables.
func loadPriceCatalog() (PriceCatalog, error) {
	raw := envOr("LLMPROXY_PRICES_CATALOG_URL", DefaultPriceCatalogURL)
	if raw == PriceCatalogOff {
		return PriceCatalog{}, nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return PriceCatalog{}, errors.New("config: LLMPROXY_PRICES_CATALOG_URL must be an absolute http(s) URL or off")
	}
	interval, err := time.ParseDuration(envOr("LLMPROXY_PRICES_CATALOG_INTERVAL", "6h"))
	if err != nil || interval < MinPriceCatalogInterval {
		return PriceCatalog{}, fmt.Errorf("config: LLMPROXY_PRICES_CATALOG_INTERVAL must be a duration of at least %s", MinPriceCatalogInterval)
	}
	return PriceCatalog{URL: raw, Interval: interval}, nil
}

// loadWeb reads the web listener's variables. Like loadOIDC, its errors name the
// variable and never quote a value: LLMPROXY_SESSION_KEY is one of them.
func loadWeb(oidcEnabled bool) (Web, error) {
	w := Web{Addr: envOr("LLMPROXY_WEB_ADDR", "127.0.0.1:8081"), CookieSecure: true, LocalLogin: true}
	if w.Addr == WebAddrOff {
		return Web{}, nil
	}
	if err := checkAddr("LLMPROXY_WEB_ADDR", w.Addr); err != nil {
		return Web{}, err
	}

	raw := os.Getenv("LLMPROXY_PUBLIC_API_URL")
	if raw == "" {
		return Web{}, errors.New("config: LLMPROXY_PUBLIC_API_URL is required while the web listener is on")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" ||
		u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return Web{}, errors.New("config: LLMPROXY_PUBLIC_API_URL must be an absolute http(s) URL without query, fragment or credentials")
	}
	w.PublicAPIURL = strings.TrimRight(raw, "/")

	if raw := os.Getenv("LLMPROXY_COOKIE_SECURE"); raw != "" {
		v, err := strconv.ParseBool(raw)
		if err != nil {
			return Web{}, errors.New("config: LLMPROXY_COOKIE_SECURE must be true or false")
		}
		w.CookieSecure = v
	}
	if raw := os.Getenv("LLMPROXY_LOCAL_LOGIN"); raw != "" {
		v, err := strconv.ParseBool(raw)
		if err != nil {
			return Web{}, errors.New("config: LLMPROXY_LOCAL_LOGIN must be true or false")
		}
		w.LocalLogin = v
	}

	key := os.Getenv("LLMPROXY_SESSION_KEY")
	switch {
	case key == "" && oidcEnabled:
		return Web{}, errors.New("config: LLMPROXY_SESSION_KEY is required when LLMPROXY_OIDC_ISSUER is set")
	case key != "" && len(key) < MinSessionKeyLen:
		return Web{}, fmt.Errorf("config: LLMPROXY_SESSION_KEY must be at least %d bytes", MinSessionKeyLen)
	case key != "":
		w.SessionKey = Secret(key)
	}
	return w, nil
}

// loadOIDC reads the LLMPROXY_OIDC_* variables. Errors name the variable and never
// quote a value: the client secret is one of them, and the others sit next to it in
// the same environment dump an operator pastes into a ticket.
func loadOIDC() (OIDC, error) {
	o := OIDC{Issuer: os.Getenv("LLMPROXY_OIDC_ISSUER")}
	if !o.Enabled() {
		return OIDC{}, nil
	}
	o.ClientID = os.Getenv("LLMPROXY_OIDC_CLIENT_ID")
	o.ClientSecret = os.Getenv("LLMPROXY_OIDC_CLIENT_SECRET")
	o.RedirectURL = os.Getenv("LLMPROXY_OIDC_REDIRECT_URL")
	o.RequiredGroup = os.Getenv("LLMPROXY_OIDC_REQUIRED_GROUP")
	o.GroupsClaim = envOr("LLMPROXY_OIDC_GROUPS_CLAIM", "groups")
	o.DisplayName = strings.TrimSpace(os.Getenv("LLMPROXY_OIDC_DISPLAY_NAME"))

	for _, req := range []struct{ name, value string }{
		{"LLMPROXY_OIDC_CLIENT_ID", o.ClientID},
		{"LLMPROXY_OIDC_CLIENT_SECRET", o.ClientSecret},
		{"LLMPROXY_OIDC_REDIRECT_URL", o.RedirectURL},
	} {
		if req.value == "" {
			return OIDC{}, fmt.Errorf("config: %s is required when LLMPROXY_OIDC_ISSUER is set", req.name)
		}
	}
	if u, err := url.Parse(o.RedirectURL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return OIDC{}, errors.New("config: LLMPROXY_OIDC_REDIRECT_URL must be an absolute http(s) URL")
	}

	if raw := os.Getenv("LLMPROXY_OIDC_ALLOW_SIGNUP"); raw != "" {
		v, err := strconv.ParseBool(raw)
		if err != nil {
			return OIDC{}, errors.New("config: LLMPROXY_OIDC_ALLOW_SIGNUP must be true or false")
		}
		o.AllowSignUp = v
	}

	o.DefaultPolicy = splitList(os.Getenv("LLMPROXY_OIDC_DEFAULT_POLICY"), ",")

	gp, err := parseGroupPolicy(os.Getenv("LLMPROXY_OIDC_GROUP_POLICY"))
	if err != nil {
		return OIDC{}, err
	}
	o.GroupPolicy = gp
	return o, nil
}

// parseGroupPolicy reads `group=rule,rule;group=rule`. Only the structure is checked
// here; rule syntax is app.NewOIDCService's.
func parseGroupPolicy(raw string) (map[string][]string, error) {
	entries := splitList(raw, ";")
	if len(entries) == 0 {
		return nil, nil
	}
	const bad = "config: LLMPROXY_OIDC_GROUP_POLICY entry %d: %s"
	out := make(map[string][]string, len(entries))
	for i, entry := range entries {
		group, rules, found := strings.Cut(entry, "=")
		group = strings.TrimSpace(group)
		if !found || group == "" {
			return nil, fmt.Errorf(bad, i+1, "want group=rule[,rule]")
		}
		if _, dup := out[group]; dup {
			return nil, fmt.Errorf(bad, i+1, "group mapped twice")
		}
		list := splitList(rules, ",")
		if len(list) == 0 {
			return nil, fmt.Errorf(bad, i+1, "group maps to no rules")
		}
		out[group] = list
	}
	return out, nil
}

// splitList splits on sep, trims, and drops empty items, so a trailing separator or
// a space after a comma is not an entry.
func splitList(raw, sep string) []string {
	var out []string
	for _, item := range strings.Split(raw, sep) {
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
