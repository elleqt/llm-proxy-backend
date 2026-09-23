// Package metrics exposes the gateway's Prometheus metric families.
//
// Every family is registered on a registry the caller owns, never on the global
// default one, and Handler serves exactly that registry. Label values are what the
// caller hands in — a human-readable user label, a provider key, an account name —
// and never a token, a principal or anything else that would authenticate.
package metrics

import (
	"net/http"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/elleqt/llm-proxy-backend/internal/app"
)

const namespace = "llmproxy"

// Registry is what New needs from its registry: somewhere to register the families
// and something Handler can gather them from. *prometheus.Registry is one.
type Registry interface {
	prometheus.Registerer
	prometheus.Gatherer
}

// Option adjusts New.
type Option func(*config)

type config struct {
	clock      app.Clock
	version    string
	knownModel func(model string) (string, bool)
	prices     PriceLookup
}

// WithClock sets the clock that stamps vendor quota observations.
func WithClock(c app.Clock) Option { return func(cfg *config) { cfg.clock = c } }

// WithVersion sets the build_info version label. Without it the module version from
// the binary's build information is used.
func WithVersion(v string) Option { return func(cfg *config) { cfg.version = v } }

// WithKnownModel sets the canonicaliser that decides whether a model name reaching
// ObservePolicyDenied may become a label value, and which label. It returns the
// catalogue's canonical name for a model the catalogue serves, so spelling variants
// such as case collapse into one series, and ok=false for anything else. Without it
// every denied model is reported as Unknown.
func WithKnownModel(canonical func(model string) (string, bool)) Option {
	return func(cfg *config) { cfg.knownModel = canonical }
}

// PriceLookup finds the price of a provider's model. It is consulted on every
// ObserveUsage, so it must answer from memory; PriceTable is one.
type PriceLookup interface {
	Price(provider, model string) (app.ModelPrice, bool)
}

// WithPrices sets the price list the cost estimate reads. Without it every token is
// unpriced.
func WithPrices(p PriceLookup) Option { return func(cfg *config) { cfg.prices = p } }

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// Metrics holds the gateway's metric families.
type Metrics struct {
	clock      app.Clock
	gatherer   prometheus.Gatherer
	knownModel func(model string) (string, bool)
	prices     PriceLookup

	tokens          *prometheus.CounterVec
	requests        *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
	ttft            *prometheus.HistogramVec
	policyDenied    *prometheus.CounterVec
	authFailures    *prometheus.CounterVec
	quotaUsed       *prometheus.GaugeVec
	quotaReset      *prometheus.GaugeVec
	quotaObserved   *prometheus.GaugeVec
	accountDisabled *prometheus.GaugeVec
	accountFailures *prometheus.CounterVec
	cost            *prometheus.CounterVec
	unpriced        *prometheus.CounterVec
	catalogChecked  prometheus.Gauge
	catalogModels   prometheus.Gauge
	catalogFailures prometheus.Counter
}

// Request latency runs from sub-second errors to multi-minute reasoning completions.
var durationBuckets = []float64{0.25, 0.5, 1, 2, 5, 10, 20, 30, 60, 120, 180, 300, 600}

// Time to first token is short for most models and tens of seconds for reasoning ones.
var ttftBuckets = []float64{0.1, 0.25, 0.5, 1, 2, 3, 5, 10, 20, 30, 60, 120}

// New registers every family on reg. It panics if a family is already registered
// there, as prometheus.MustRegister does.
func New(reg Registry, opts ...Option) *Metrics {
	cfg := config{clock: systemClock{}}
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.version == "" {
		cfg.version = buildVersion()
	}

	quotaLabels := []string{"account", "provider", "window"}
	accountLabels := []string{"account", "provider"}
	m := &Metrics{
		clock:      cfg.clock,
		gatherer:   reg,
		knownModel: cfg.knownModel,
		prices:     cfg.prices,
		tokens: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "tokens_total",
			Help: "Tokens consumed, by kind and service tier.",
		}, []string{"user", "provider", "model", "service_tier", "kind"}),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "requests_total",
			Help: "Proxied requests, by upstream status class (1xx..5xx), or ok/error when no status code was recorded. Per-token detail is in the usage ledger, not here.",
		}, []string{"user", "provider", "model", "stream", "status"}),
		requestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace, Name: "request_duration_seconds",
			Help:    "End-to-end duration of proxied requests.",
			Buckets: durationBuckets,
		}, []string{"provider", "model", "stream"}),
		ttft: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace, Name: "ttft_seconds",
			Help:    "Time to first token of streamed responses.",
			Buckets: ttftBuckets,
		}, []string{"provider", "model"}),
		policyDenied: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "policy_denied_total",
			Help: "Requests refused by the model access policy.",
		}, []string{"user", "model", "reason"}),
		authFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "auth_failures_total",
			Help: "Failed authentications.",
		}, []string{"reason"}),
		quotaUsed: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Name: "vendor_quota_used_ratio",
			Help: "Share of a vendor quota window used, as reported by the vendor (0..1).",
		}, quotaLabels),
		quotaReset: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Name: "vendor_quota_reset_timestamp_seconds",
			Help: "Unix time at which the vendor reports the quota window resets.",
		}, quotaLabels),
		quotaObserved: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Name: "vendor_quota_observed_timestamp_seconds",
			Help: "Unix time at which the quota figures were last observed.",
		}, quotaLabels),
		accountDisabled: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Name: "account_disabled",
			Help: "1 while a vendor account is disabled, 0 otherwise.",
		}, accountLabels),
		accountFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "account_failures_total",
			Help: "Upstream failures attributed to a vendor account.",
		}, accountLabels),
		cost: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "cost_usd_total",
			Help: "Estimated cost of consumed tokens in US dollars, at the price list in force when each request was recorded. An estimate, not a bill.",
		}, []string{"user", "provider", "model"}),
		unpriced: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "cost_unpriced_tokens_total",
			Help: "Tokens consumed by models the price list has no price for, so absent from the cost estimate.",
		}, []string{"provider", "model"}),
		catalogChecked: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Name: "price_catalog_checked_timestamp_seconds",
			Help: "Unix time of the last successful price catalog check, whether or not the catalog had changed; 0 before the first.",
		}),
		catalogModels: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Name: "price_catalog_models",
			Help: "Catalog prices in force.",
		}),
		catalogFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace, Name: "price_catalog_check_failures_total",
			Help: "Price catalog checks that failed; the prices in force were kept.",
		}),
	}

	buildInfo := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace, Name: "build_info",
		Help: "Always 1; the version label identifies the running build.",
	}, []string{"version"})
	buildInfo.WithLabelValues(cfg.version).Set(1)

	reg.MustRegister(
		m.tokens, m.requests, m.requestDuration, m.ttft,
		m.policyDenied, m.authFailures,
		m.quotaUsed, m.quotaReset, m.quotaObserved,
		m.accountDisabled, m.accountFailures,
		m.cost, m.unpriced,
		m.catalogChecked, m.catalogModels, m.catalogFailures,
		buildInfo,
	)
	return m
}

func buildVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" {
		return bi.Main.Version
	}
	return "unknown"
}

// Handler serves the registry New was given in the Prometheus exposition format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.gatherer, promhttp.HandlerOpts{})
}

// ObserveUsage records one completed request. user is the human-readable label the
// caller resolved for ev's owner (an email or a service-account name). It may not be
// an id or a secret: nothing in ev that identifies a user or a token becomes a label
// value. No family is labelled by token: a user can hold many, and their number
// would become the number of series.
//
// ev.ServiceTier must be the tier the vendor actually served
// (usage.Record.ResponseServiceTier), not the one the client requested.
func (m *Metrics) ObserveUsage(ev app.UsageEvent, user string) {
	tier := serviceTier(ev.ServiceTier)
	for _, k := range [...]struct {
		kind string
		n    int64
	}{
		{"input", ev.TokensInput},
		{"output", ev.TokensOutput},
		{"reasoning", ev.TokensReasoning},
		{"cache_read", ev.TokensCacheRead},
		{"cache_write", ev.TokensCacheWrite},
	} {
		if k.n > 0 {
			m.tokens.WithLabelValues(user, ev.Provider, ev.Model, tier, k.kind).Add(float64(k.n))
		}
	}

	stream := strconv.FormatBool(ev.Stream)
	m.requests.WithLabelValues(user, ev.Provider, ev.Model, stream, statusClass(ev)).Inc()

	if ev.LatencyMS > 0 {
		m.requestDuration.WithLabelValues(ev.Provider, ev.Model, stream).Observe(float64(ev.LatencyMS) / 1000)
	}
	// Upstream measures TTFT for non-streamed calls too, as the first body byte, which
	// arrives only after the whole generation: it is not a time to first token.
	if ev.Stream && ev.TTFTMS > 0 {
		m.ttft.WithLabelValues(ev.Provider, ev.Model).Observe(float64(ev.TTFTMS) / 1000)
	}
	m.observeCost(ev, user)
}

// observeCost prices ev's tokens at the price in force now. The kinds partition the
// request's tokens (the usage sink maps upstream's canonical breakdown that way), so
// each is priced once: reasoning tokens are output tokens and cost the output rate.
// A model without a price adds its tokens to the unpriced counter instead.
//
// Tokens upstream could not classify (an unclassified or inconsistent breakdown:
// TokensTotal above the sum of the kinds) have no rate to apply, so they are
// unpriced even for a priced model.
func (m *Metrics) observeCost(ev app.UsageEvent, user string) {
	in, out := positive(ev.TokensInput), positive(ev.TokensOutput)+positive(ev.TokensReasoning)
	cacheRead, cacheWrite := positive(ev.TokensCacheRead), positive(ev.TokensCacheWrite)
	classified := in + out + cacheRead + cacheWrite
	unclassified := max(positive(ev.TokensTotal)-classified, 0)
	if unclassified > 0 {
		m.unpriced.WithLabelValues(ev.Provider, ev.Model).Add(unclassified)
	}
	if classified == 0 {
		return
	}
	var (
		p  app.ModelPrice
		ok bool
	)
	if m.prices != nil {
		p, ok = m.prices.Price(ev.Provider, ev.Model)
	}
	if !ok {
		m.unpriced.WithLabelValues(ev.Provider, ev.Model).Add(classified)
		return
	}
	cost := (in*p.Input + out*p.Output + cacheRead*p.CacheRead + cacheWrite*p.CacheWrite) / 1e6
	if cost > 0 {
		m.cost.WithLabelValues(user, ev.Provider, ev.Model).Add(cost)
	}
}

// positive is n as a counter increment: a negative count adds nothing (a negative
// Add panics).
func positive(n int64) float64 {
	if n <= 0 {
		return 0
	}
	return float64(n)
}

// serviceTier clamps the served tier to a closed set: an empty tier is "default" and
// anything unrecognised is "other".
func serviceTier(t string) string {
	switch t {
	case "":
		return "default"
	case "standard", "priority", "flex", "batch", "default", "auto", "scale":
		return t
	default:
		return "other"
	}
}

var statusClasses = [...]string{"1xx", "2xx", "3xx", "4xx", "5xx"}

// statusClass keeps the status label to a closed set: the HTTP class of the upstream
// response, or ok/error from the failure flag when no status code was recorded.
func statusClass(ev app.UsageEvent) string {
	if ev.StatusCode >= 100 && ev.StatusCode < 600 {
		return statusClasses[ev.StatusCode/100-1]
	}
	if ev.Failed {
		return "error"
	}
	return "ok"
}

// ObserveVendorQuota records a vendor's own report of quota use. ratio is a share in
// 0..1: converting a percentage is the caller's job. A zero resetAt leaves the reset
// gauge as it was. The observed timestamp is taken from the clock.
func (m *Metrics) ObserveVendorQuota(account, provider, window string, ratio float64, resetAt time.Time) {
	m.quotaUsed.WithLabelValues(account, provider, window).Set(ratio)
	if !resetAt.IsZero() {
		m.quotaReset.WithLabelValues(account, provider, window).Set(unixSeconds(resetAt))
	}
	m.quotaObserved.WithLabelValues(account, provider, window).Set(unixSeconds(m.clock.Now()))
}

func unixSeconds(t time.Time) float64 { return float64(t.UnixNano()) / 1e9 }

// DenyReason is why the policy gate refused a request. It is a closed set so a
// client cannot mint label values through it.
type DenyReason uint8

const (
	// DenyModelNotAllowed: the model is known, but the policy does not allow the user
	// every provider that serves it.
	DenyModelNotAllowed DenyReason = iota
	// DenyUnknownModel: no provider serves the requested model; the gate fails closed.
	DenyUnknownModel
	// DenyRouteNotAllowed: the path is not on the proxied listener's allow-list.
	DenyRouteNotAllowed
)

var denyReasons = [...]string{
	DenyModelNotAllowed: "model_not_allowed",
	DenyUnknownModel:    "unknown_model",
	DenyRouteNotAllowed: "route_not_allowed",
}

// String returns the reason's label value; a value outside the declared constants
// is "other".
func (r DenyReason) String() string {
	if int(r) < len(denyReasons) {
		return denyReasons[r]
	}
	return "other"
}

// Unknown is the user label of a denial made before anyone was authenticated, and the
// model label of a denial whose model the catalogue does not serve — of every denial
// when New was given no WithKnownModel canonicaliser.
const Unknown = "unknown"

// ObservePolicyDenied counts a request the policy gate refused. user is the owner's
// label, empty when the request was refused before authentication. model may be the
// raw string the client sent: the label is the canonical name WithKnownModel returns
// for it, or Unknown when the catalogue does not serve it, so arbitrary client input
// cannot create series. Pass an empty model when the request named none.
func (m *Metrics) ObservePolicyDenied(user, model string, reason DenyReason) {
	if user == "" {
		user = Unknown
	}
	label := Unknown
	if m.knownModel != nil {
		if c, ok := m.knownModel(model); ok {
			label = c
		}
	}
	m.policyDenied.WithLabelValues(user, label, reason.String()).Inc()
}

// ObserveAuthFailure counts a failed authentication. reason must come from a closed
// set chosen by the caller, never from the presented credential.
func (m *Metrics) ObserveAuthFailure(reason string) {
	m.authFailures.WithLabelValues(reason).Inc()
}

// SetAccountDisabled records whether a vendor account is currently disabled.
func (m *Metrics) SetAccountDisabled(account, provider string, disabled bool) {
	v := 0.0
	if disabled {
		v = 1
	}
	m.accountDisabled.WithLabelValues(account, provider).Set(v)
}

// ObserveAccountFailure counts an upstream failure attributed to a vendor account.
func (m *Metrics) ObserveAccountFailure(account, provider string) {
	m.accountFailures.WithLabelValues(account, provider).Inc()
}

// ForgetAccount drops every series of a removed vendor account, so its last disabled
// state and quota figures stop being exported.
func (m *Metrics) ForgetAccount(account, provider string) {
	match := prometheus.Labels{"account": account, "provider": provider}
	m.accountDisabled.DeletePartialMatch(match)
	m.accountFailures.DeletePartialMatch(match)
	m.quotaUsed.DeletePartialMatch(match)
	m.quotaReset.DeletePartialMatch(match)
	m.quotaObserved.DeletePartialMatch(match)
}

// SetPriceCatalog reports the catalog prices in force and the last successful
// check; a zero checkedAt leaves the timestamp at 0 (never).
func (m *Metrics) SetPriceCatalog(models int, checkedAt time.Time) {
	m.catalogModels.Set(float64(models))
	if !checkedAt.IsZero() {
		m.catalogChecked.Set(unixSeconds(checkedAt))
	}
}

// ObservePriceCatalogFailure counts a failed price catalog check.
func (m *Metrics) ObservePriceCatalogFailure() { m.catalogFailures.Inc() }
