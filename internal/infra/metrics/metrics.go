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
	"sync"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// Metrics holds the gateway's metric families.
type Metrics struct {
	clock      app.Clock
	gatherer   prometheus.Gatherer
	knownModel func(model string) (string, bool)

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
	cacheSavings    *prometheus.CounterVec
	cachePremium    *prometheus.CounterVec
	unpriced        *prometheus.CounterVec
	quotaBurned     *prometheus.CounterVec
	catalogChecked  prometheus.Gauge
	catalogModels   prometheus.Gauge
	catalogFailures prometheus.Counter

	// quotaMu guards burnMarks: each quota window's high-water mark, what the next
	// reading's rise is measured from.
	quotaMu   sync.Mutex
	burnMarks map[quotaKey]burnMark
}

type quotaKey struct{ account, provider, window string }

// burnMark is the highest used ratio seen in the window that resets at resetAt
// (zero when no reading has carried a reset time yet).
type burnMark struct {
	high    float64
	resetAt time.Time
}

// resetTolerance is how far a window's reported reset time may move and still be
// the same window: codex reports it as seconds from the response, which jitters.
const resetTolerance = time.Minute

// Label names shared by several families.
const (
	labelUser     = "user"
	labelProvider = "provider"
	labelModel    = "model"
	labelAccount  = "account"
)

// Help texts too long to sit inline in New.
const (
	costHelp = "Estimated cost of consumed tokens in US dollars, by kind (input: uncached input; output: output and reasoning; " +
		"cache_read; cache_write), at the price list in force when each request was recorded. An estimate, not a bill."
	cacheSavingsHelp = "US dollars prompt caching saved, from requests where it saved: cache reads at (input - cache-read rate) " +
		"less cache writes at (cache-write - input rate), against paying the input rate for every input token. " +
		"A counter cannot go down, so a request where caching cost more adds to llmproxy_cache_write_premium_usd_total " +
		"instead; the net effect is this minus that."
	cachePremiumHelp = "US dollars prompt caching cost extra, from requests where cache writes at (cache-write - input rate) " +
		"outweighed what cache reads saved at (input - cache-read rate). " +
		"Subtract it from llmproxy_cache_savings_usd_total for the net effect of caching."
	quotaBurnedHelp = "Vendor quota burned, summed over the rises of llmproxy_vendor_quota_used_ratio above its highest reading " +
		"in the window seen by this process (a lower, late reading adds nothing; after the window resets its first " +
		"reading counts from zero; quota burned while the process was down is not counted). 1.0 = one full window; " +
		"pair with llmproxy_cost_usd_total / llmproxy_tokens_total to estimate the capacity of a window."
)

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

	quotaLabels := []string{labelAccount, labelProvider, "window"}
	accountLabels := []string{labelAccount, labelProvider}
	metricSet := &Metrics{
		clock:      cfg.clock,
		gatherer:   reg,
		knownModel: cfg.knownModel,
		burnMarks:  map[quotaKey]burnMark{},
		tokens: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "tokens_total",
			Help: "Tokens consumed, by kind and service tier.",
		}, []string{labelUser, labelProvider, labelModel, "service_tier", "kind"}),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "requests_total",
			Help: "Proxied requests, by upstream status class (1xx..5xx), or ok/error when no status code was recorded. " +
				"Per-token detail is in the usage ledger, not here.",
		}, []string{labelUser, labelProvider, labelModel, "stream", "status"}),
		requestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace, Name: "request_duration_seconds",
			Help:    "End-to-end duration of proxied requests.",
			Buckets: durationBuckets,
		}, []string{labelProvider, labelModel, "stream"}),
		ttft: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace, Name: "ttft_seconds",
			Help:    "Time to first token of streamed responses.",
			Buckets: ttftBuckets,
		}, []string{labelProvider, labelModel}),
		policyDenied: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "policy_denied_total",
			Help: "Requests refused by the model access policy.",
		}, []string{labelUser, labelModel, "reason"}),
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
			Help: costHelp,
		}, []string{labelUser, labelProvider, labelModel, "kind"}),
		cacheSavings: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "cache_savings_usd_total",
			Help: cacheSavingsHelp,
		}, []string{labelUser, labelProvider, labelModel}),
		cachePremium: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "cache_write_premium_usd_total",
			Help: cachePremiumHelp,
		}, []string{labelUser, labelProvider, labelModel}),
		unpriced: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "cost_unpriced_tokens_total",
			Help: "Tokens absent from the cost estimate: those of models the price list had no price for, and those the vendor did not classify.",
		}, []string{labelProvider, labelModel}),
		quotaBurned: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "vendor_quota_burned_ratio_total",
			Help: quotaBurnedHelp,
		}, quotaLabels),
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
		metricSet.tokens, metricSet.requests, metricSet.requestDuration, metricSet.ttft,
		metricSet.policyDenied, metricSet.authFailures,
		metricSet.quotaUsed, metricSet.quotaReset, metricSet.quotaObserved,
		metricSet.accountDisabled, metricSet.accountFailures,
		metricSet.cost, metricSet.cacheSavings, metricSet.cachePremium, metricSet.unpriced, metricSet.quotaBurned,
		metricSet.catalogChecked, metricSet.catalogModels, metricSet.catalogFailures,
		buildInfo,
	)

	return metricSet
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
	for _, part := range [...]struct {
		kind string
		n    int64
	}{
		{"input", ev.TokensInput},
		{"output", ev.TokensOutput},
		{"reasoning", ev.TokensReasoning},
		{"cache_read", ev.TokensCacheRead},
		{"cache_write", ev.TokensCacheWrite},
	} {
		if part.n > 0 {
			m.tokens.WithLabelValues(user, ev.Provider, ev.Model, tier, part.kind).Add(float64(part.n))
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
//
// It also counts the quota burned, against a high-water mark per window: a reading
// above the mark adds the difference and raises it; one at or below it adds
// nothing, for readings arrive in completion order, and a long stream reports the
// ratio of when it started. The window has rolled over only when resetAt moves
// forward by more than resetTolerance: the first reading of the new window counts
// from zero, since all of it was burned there. A reading whose resetAt is more than
// resetTolerance before the mark's is a late one from an earlier window and counts
// nothing. The first reading of a window since the process started only sets the
// mark: what was burned before is not known.
func (m *Metrics) ObserveVendorQuota(account, provider, window string, ratio float64, resetAt time.Time) {
	m.quotaUsed.WithLabelValues(account, provider, window).Set(ratio)

	if burned := m.burn(quotaKey{account, provider, window}, ratio, resetAt); burned > 0 {
		m.quotaBurned.WithLabelValues(account, provider, window).Add(burned)
	}

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
	match := prometheus.Labels{labelAccount: account, labelProvider: provider}
	m.accountDisabled.DeletePartialMatch(match)
	m.accountFailures.DeletePartialMatch(match)
	m.quotaUsed.DeletePartialMatch(match)
	m.quotaReset.DeletePartialMatch(match)
	m.quotaObserved.DeletePartialMatch(match)
	m.quotaBurned.DeletePartialMatch(match)
	m.quotaMu.Lock()
	for k := range m.burnMarks {
		if k.account == account && k.provider == provider {
			delete(m.burnMarks, k)
		}
	}
	m.quotaMu.Unlock()
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

// observeCost counts ev.Cost, the cost the usage sink priced ev at when it
// recorded it (app.PriceUsage), so the metrics and the ledger agree. A part that
// is zero adds no series.
func (m *Metrics) observeCost(ev app.UsageEvent, user string) {
	cost := ev.Cost
	if cost.UnpricedTokens > 0 {
		m.unpriced.WithLabelValues(ev.Provider, ev.Model).Add(float64(cost.UnpricedTokens))
	}

	for _, part := range [...]struct {
		kind string
		usd  float64
	}{
		{"input", cost.InputUSD},
		{"output", cost.OutputUSD},
		{"cache_read", cost.CacheReadUSD},
		{"cache_write", cost.CacheWriteUSD},
	} {
		if part.usd > 0 {
			m.cost.WithLabelValues(user, ev.Provider, ev.Model, part.kind).Add(part.usd)
		}
	}

	switch {
	case cost.CacheSavingsUSD > 0:
		m.cacheSavings.WithLabelValues(user, ev.Provider, ev.Model).Add(cost.CacheSavingsUSD)
	case cost.CacheSavingsUSD < 0:
		m.cachePremium.WithLabelValues(user, ev.Provider, ev.Model).Add(-cost.CacheSavingsUSD)
	}
}

// burn moves k's high-water mark for a reading and returns what it burned.
func (m *Metrics) burn(key quotaKey, ratio float64, resetAt time.Time) float64 {
	m.quotaMu.Lock()
	defer m.quotaMu.Unlock()

	mark, seen := m.burnMarks[key]
	switch {
	case !seen:
		m.burnMarks[key] = burnMark{high: ratio, resetAt: resetAt}

		return 0
	case resetAt.IsZero():
	case mark.resetAt.IsZero():
		mark.resetAt = resetAt
	case resetAt.After(mark.resetAt.Add(resetTolerance)):
		m.burnMarks[key] = burnMark{high: ratio, resetAt: resetAt}

		return ratio
	case resetAt.Before(mark.resetAt.Add(-resetTolerance)):
		return 0
	}

	var burned float64
	if ratio > mark.high {
		burned, mark.high = ratio-mark.high, ratio
	}

	m.burnMarks[key] = mark

	return burned
}
