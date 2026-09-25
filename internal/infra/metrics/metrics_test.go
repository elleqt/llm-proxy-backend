package metrics

import (
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

type fakeClock struct{ t time.Time }

func (c fakeClock) Now() time.Time { return c.t }

func TestObserveUsageCountsTokensByKind(t *testing.T) {
	metricSet := New(prometheus.NewRegistry())
	ev := app.UsageEvent{
		Provider: "claude", Model: "claude-sonnet-5", ServiceTier: "priority",
		TokensInput: 10, TokensOutput: 20, TokensReasoning: 4, TokensCacheRead: 5,
	}

	metricSet.ObserveUsage(ev, "alice@example.com")
	metricSet.ObserveUsage(ev, "alice@example.com")

	for kind, want := range map[string]float64{"input": 20, "output": 40, "reasoning": 8, "cache_read": 10} {
		if got := testutil.ToFloat64(metricSet.tokens.WithLabelValues("alice@example.com", "claude", "claude-sonnet-5", "priority", kind)); got != want {
			t.Errorf("%s tokens = %v, want %v", kind, got, want)
		}
	}
	// ToFloat64 above created no new series; cache_write was zero, so it must not exist.
	if n := testutil.CollectAndCount(metricSet.tokens); n != 4 {
		t.Fatalf("token series = %d, want 4 (zero-valued cache_write must not be emitted)", n)
	}
}

func TestServiceTierIsAClosedSet(t *testing.T) {
	metricSet := New(prometheus.NewRegistry())
	for _, tier := range []string{"", "flex", "auto", "scale", "priority", "turbo", "Priority"} {
		metricSet.ObserveUsage(app.UsageEvent{Provider: "codex", Model: "gpt-6", ServiceTier: tier, TokensInput: 1}, "u")
	}

	for tier, want := range map[string]float64{"default": 1, "flex": 1, "auto": 1, "scale": 1, "priority": 1, "other": 2} {
		if got := testutil.ToFloat64(metricSet.tokens.WithLabelValues("u", "codex", "gpt-6", tier, "input")); got != want {
			t.Errorf("tokens{service_tier=%q} = %v, want %v", tier, got, want)
		}
	}

	if n := testutil.CollectAndCount(metricSet.tokens); n != 6 {
		t.Fatalf("token series = %d, want 6", n)
	}
}

func TestRequestsCountedByStatusClassAndStream(t *testing.T) {
	metricSet := New(prometheus.NewRegistry())

	for _, ev := range []app.UsageEvent{
		{StatusCode: 200},
		{StatusCode: 201, Stream: true},
		{StatusCode: 429, Failed: true},
		{StatusCode: 502, Failed: true},
		{Failed: true}, // no response at all
		{},             // succeeded, status code not recorded
	} {
		ev.Provider, ev.Model = "codex", "gpt-6"
		metricSet.ObserveUsage(ev, "svc-ci")
	}

	for _, tc := range []struct {
		stream, status string
		want           float64
	}{
		{"false", "2xx", 1},
		{"true", "2xx", 1},
		{"false", "4xx", 1},
		{"false", "5xx", 1},
		{"false", "error", 1},
		{"false", "ok", 1},
	} {
		if got := testutil.ToFloat64(metricSet.requests.WithLabelValues("svc-ci", "codex", "gpt-6", tc.stream, tc.status)); got != tc.want {
			t.Errorf("requests{stream=%q,status=%q} = %v, want %v", tc.stream, tc.status, got, tc.want)
		}
	}

	if n := testutil.CollectAndCount(metricSet.requests); n != 6 {
		t.Fatalf("request series = %d, want 6", n)
	}
}

func TestDurationsInSecondsAndTTFTOnlyWhenStreamed(t *testing.T) {
	reg := prometheus.NewRegistry()
	metricSet := New(reg)

	metricSet.ObserveUsage(app.UsageEvent{Provider: "claude", Model: "m", Stream: true, LatencyMS: 90_000, TTFTMS: 1_500}, "u")
	metricSet.ObserveUsage(app.UsageEvent{Provider: "claude", Model: "m", Stream: true, LatencyMS: 2_000, TTFTMS: 500}, "u")
	// Upstream sets TTFT on non-streamed calls too (first body byte, after the whole
	// generation); it must not reach the TTFT histogram.
	metricSet.ObserveUsage(app.UsageEvent{Provider: "claude", Model: "m", LatencyMS: 500, TTFTMS: 480}, "u")

	fams := gather(t, reg)
	durations := map[string]*dto.Histogram{}

	for _, mt := range fams["llmproxy_request_duration_seconds"].GetMetric() {
		for _, l := range mt.GetLabel() {
			if l.GetName() == "stream" {
				durations[l.GetValue()] = mt.GetHistogram()
			}
		}
	}

	if h := durations["true"]; h.GetSampleCount() != 2 || h.GetSampleSum() != 92 {
		t.Fatalf("streamed duration count/sum = %d/%v, want 2/92", h.GetSampleCount(), h.GetSampleSum())
	}

	if h := durations["false"]; h.GetSampleCount() != 1 || h.GetSampleSum() != 0.5 {
		t.Fatalf("non-streamed duration count/sum = %d/%v, want 1/0.5", h.GetSampleCount(), h.GetSampleSum())
	}

	ttft := fams["llmproxy_ttft_seconds"].GetMetric()[0].GetHistogram()
	if ttft.GetSampleCount() != 2 || ttft.GetSampleSum() != 2 {
		t.Fatalf("ttft count/sum = %d/%v, want 2/2 (streamed requests only)", ttft.GetSampleCount(), ttft.GetSampleSum())
	}
}

func TestPolicyDeniedModelLabelIsTheCanonicalName(t *testing.T) {
	canonical := func(model string) (string, bool) {
		if strings.EqualFold(model, "claude-sonnet-5") {
			return "claude-sonnet-5", true
		}

		return "", false
	}
	metricSet := New(prometheus.NewRegistry(), WithKnownModel(canonical))

	metricSet.ObservePolicyDenied("u", "claude-sonnet-5", DenyModelNotAllowed)
	metricSet.ObservePolicyDenied("u", "CLAUDE-SONNET-5", DenyModelNotAllowed)

	for _, junk := range []string{"x-1", "x-2", strings.Repeat("a", 4096), ""} {
		metricSet.ObservePolicyDenied("u", junk, DenyUnknownModel)
	}

	metricSet.ObservePolicyDenied("u", "claude-sonnet-5", DenyReason(200))

	for _, tc := range []struct {
		model, reason string
		want          float64
	}{
		{"claude-sonnet-5", "model_not_allowed", 2},
		{Unknown, "unknown_model", 4},
		{"claude-sonnet-5", "other", 1},
	} {
		if got := testutil.ToFloat64(metricSet.policyDenied.WithLabelValues("u", tc.model, tc.reason)); got != tc.want {
			t.Errorf("policy_denied{model=%q,reason=%q} = %v, want %v", tc.model, tc.reason, got, tc.want)
		}
	}

	if n := testutil.CollectAndCount(metricSet.policyDenied); n != 3 {
		t.Fatalf("policy_denied series = %d, want 3: client strings must not create series", n)
	}
}

func TestPolicyDeniedWithoutPredicateNeverLabelsTheModel(t *testing.T) {
	metricSet := New(prometheus.NewRegistry())
	metricSet.ObservePolicyDenied("u", "claude-sonnet-5", DenyModelNotAllowed)

	if got := testutil.ToFloat64(metricSet.policyDenied.WithLabelValues("u", Unknown, "model_not_allowed")); got != 1 {
		t.Fatalf("policy_denied{model=%q} = %v, want 1", Unknown, got)
	}

	if n := testutil.CollectAndCount(metricSet.policyDenied); n != 1 {
		t.Fatalf("policy_denied series = %d, want 1", n)
	}
}

// A request refused before anyone was authenticated has no owner: it is counted
// under Unknown, never under an empty user label.
func TestPolicyDeniedWithoutOwnerIsUnknown(t *testing.T) {
	metricSet := New(prometheus.NewRegistry())
	metricSet.ObservePolicyDenied("", "", DenyRouteNotAllowed)

	if got := testutil.ToFloat64(metricSet.policyDenied.WithLabelValues(Unknown, Unknown, "route_not_allowed")); got != 1 {
		t.Fatalf("policy_denied{user=%q} = %v, want 1", Unknown, got)
	}

	if n := testutil.CollectAndCount(metricSet.policyDenied); n != 1 {
		t.Fatalf("policy_denied series = %d, want 1", n)
	}
}

func TestVendorQuotaGauges(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	clock := &fakeClock{t: now}
	metricSet := New(prometheus.NewRegistry(), WithClock(clock))
	reset := now.Add(3 * time.Hour)

	metricSet.ObserveVendorQuota("acct-1", "claude", "5h", 0.42, reset)

	labels := []string{"acct-1", "claude", "5h"}
	if got := testutil.ToFloat64(metricSet.quotaUsed.WithLabelValues(labels...)); got != 0.42 {
		t.Fatalf("quota ratio = %v, want 0.42 (ratio in, ratio out)", got)
	}

	if got := testutil.ToFloat64(metricSet.quotaReset.WithLabelValues(labels...)); got != float64(reset.Unix()) {
		t.Fatalf("reset timestamp = %v, want %v", got, reset.Unix())
	}

	if got := testutil.ToFloat64(metricSet.quotaObserved.WithLabelValues(labels...)); got != float64(now.Unix()) {
		t.Fatalf("observed timestamp = %v, want %v", got, now.Unix())
	}

	// A later report without a reset time updates use and observation, keeps the reset.
	clock.t = now.Add(time.Minute)

	metricSet.ObserveVendorQuota("acct-1", "claude", "5h", 0.5, time.Time{})

	if got := testutil.ToFloat64(metricSet.quotaUsed.WithLabelValues(labels...)); got != 0.5 {
		t.Fatalf("quota ratio = %v, want 0.5", got)
	}

	if got := testutil.ToFloat64(metricSet.quotaReset.WithLabelValues(labels...)); got != float64(reset.Unix()) {
		t.Fatalf("reset timestamp = %v after zero resetAt, want it kept at %v", got, reset.Unix())
	}

	if got := testutil.ToFloat64(metricSet.quotaObserved.WithLabelValues(labels...)); got != float64(clock.t.Unix()) {
		t.Fatalf("observed timestamp = %v, want %v", got, clock.t.Unix())
	}
}

func TestAccountDisabledFollowsLatestState(t *testing.T) {
	metricSet := New(prometheus.NewRegistry())
	metricSet.SetAccountDisabled("acct-1", "codex", true)

	if got := testutil.ToFloat64(metricSet.accountDisabled.WithLabelValues("acct-1", "codex")); got != 1 {
		t.Fatalf("disabled = %v, want 1", got)
	}

	metricSet.SetAccountDisabled("acct-1", "codex", false)

	if got := testutil.ToFloat64(metricSet.accountDisabled.WithLabelValues("acct-1", "codex")); got != 0 {
		t.Fatalf("disabled = %v after re-enable, want 0", got)
	}
}

func TestForgetAccountDropsOnlyThatAccountsSeries(t *testing.T) {
	metricSet := New(prometheus.NewRegistry())
	for _, acct := range []string{"gone", "kept"} {
		metricSet.SetAccountDisabled(acct, "claude", true)
		metricSet.ObserveAccountFailure(acct, "claude")
		metricSet.ObserveVendorQuota(acct, "claude", "5h", 0.9, time.Now())
		metricSet.ObserveVendorQuota(acct, "claude", "7d", 0.3, time.Now())
	}
	// Same account name under another provider is a different account.
	metricSet.SetAccountDisabled("gone", "codex", true)

	metricSet.ForgetAccount("gone", "claude")

	// Left: kept/claude and gone/codex disabled, kept's one failure, kept's 5h and 7d windows.
	for _, tc := range []struct {
		name string
		c    prometheus.Collector
		want int
	}{
		{"account_disabled", metricSet.accountDisabled, 2},
		{"account_failures_total", metricSet.accountFailures, 1},
		{"vendor_quota_used_ratio", metricSet.quotaUsed, 2},
		{"vendor_quota_reset_timestamp_seconds", metricSet.quotaReset, 2},
		{"vendor_quota_observed_timestamp_seconds", metricSet.quotaObserved, 2},
	} {
		if n := testutil.CollectAndCount(tc.c); n != tc.want {
			t.Errorf("%s series = %d after ForgetAccount, want %d", tc.name, n, tc.want)
		}
	}

	if got := testutil.ToFloat64(metricSet.quotaUsed.WithLabelValues("kept", "claude", "5h")); got != 0.9 {
		t.Fatalf("kept account's quota = %v, want 0.9", got)
	}
}

func TestHandlerServesPrefixedFamilies(t *testing.T) {
	metricSet := New(prometheus.NewRegistry(), WithVersion("v1.2.3"))
	metricSet.ObserveUsage(app.UsageEvent{
		Provider: "claude", Model: "m", Stream: true, TokensInput: 1, StatusCode: 200, LatencyMS: 10, TTFTMS: 5,
		Cost: app.UsageCost{InputUSD: 1, CacheSavingsUSD: 1, Priced: true},
	}, "u")
	metricSet.ObserveUsage(app.UsageEvent{
		Provider: "claude", Model: "unpriced", TokensInput: 1,
		Cost: app.UsageCost{UnpricedTokens: 1, CacheSavingsUSD: -1},
	}, "u")
	metricSet.ObserveVendorQuota("a", "claude", "7d", 0.05, time.Now())
	metricSet.ObservePolicyDenied("u", "m", DenyModelNotAllowed)
	metricSet.ObserveAuthFailure("unknown_token")
	metricSet.ObserveVendorQuota("a", "claude", "7d", 0.1, time.Now())
	metricSet.SetAccountDisabled("a", "claude", false)
	metricSet.ObserveAccountFailure("a", "claude")
	metricSet.SetPriceCatalog(35, time.Unix(1_790_000_000, 0))
	metricSet.ObservePriceCatalogFailure()

	body := scrape(t, metricSet)

	fams, err := parser().TextToMetricFamilies(strings.NewReader(body))
	if err != nil {
		t.Fatalf("handler output is not Prometheus text: %v\n%s", err, body)
	}

	for _, name := range []string{
		"llmproxy_tokens_total", "llmproxy_requests_total",
		"llmproxy_request_duration_seconds", "llmproxy_ttft_seconds",
		"llmproxy_policy_denied_total", "llmproxy_auth_failures_total",
		"llmproxy_vendor_quota_used_ratio", "llmproxy_vendor_quota_reset_timestamp_seconds",
		"llmproxy_vendor_quota_observed_timestamp_seconds",
		"llmproxy_account_disabled", "llmproxy_account_failures_total", "llmproxy_build_info",
		"llmproxy_cost_usd_total", "llmproxy_cost_unpriced_tokens_total",
		"llmproxy_cache_savings_usd_total", "llmproxy_cache_write_premium_usd_total",
		"llmproxy_vendor_quota_burned_ratio_total",
		"llmproxy_price_catalog_checked_timestamp_seconds", "llmproxy_price_catalog_models",
		"llmproxy_price_catalog_check_failures_total",
	} {
		if _, ok := fams[name]; !ok {
			t.Errorf("family %s missing from handler output", name)
		}
	}

	for name := range fams {
		if !strings.HasPrefix(name, "llmproxy_") {
			t.Errorf("family %s lacks the llmproxy_ prefix", name)
		}
	}

	if !strings.Contains(body, `llmproxy_build_info{version="v1.2.3"} 1`) {
		t.Errorf("build_info does not carry the configured version:\n%s", body)
	}
}

func TestLabelsNeverCarryThePrincipal(t *testing.T) {
	userID, tokenID := uuid.New(), uuid.New()
	metricSet := New(prometheus.NewRegistry())

	metricSet.ObserveUsage(app.UsageEvent{
		UserID: userID, TokenID: tokenID,
		Provider: "claude", Model: "m", TokensInput: 7, StatusCode: 200,
	}, "alice@example.com")

	body := scrape(t, metricSet)
	if !strings.Contains(body, `user="alice@example.com"`) {
		t.Fatalf("caller-supplied user label missing:\n%s", body)
	}
	// The principal upstream carries as the record's APIKey is "<userID>:<tokenID>".
	for _, id := range []string{userID.String(), tokenID.String()} {
		if strings.Contains(body, id) {
			t.Fatalf("handler output contains %q:\n%s", id, body)
		}
	}
}

func scrape(t *testing.T, m *Metrics) string {
	t.Helper()

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", http.NoBody))

	if rec.Code != 200 {
		t.Fatalf("handler status = %d", rec.Code)
	}

	b, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatal(err)
	}

	return string(b)
}

func gather(t *testing.T, reg *prometheus.Registry) map[string]*dto.MetricFamily {
	t.Helper()

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}

	out := make(map[string]*dto.MetricFamily, len(mfs))
	for _, mf := range mfs {
		out[mf.GetName()] = mf
	}

	return out
}

func parser() *expfmt.TextParser {
	p := expfmt.NewTextParser(model.UTF8Validation)

	return &p
}

// The cost counters count the cost the event carries, each part under its kind,
// and the net cache effect on the savings counter or the premium one by its sign.
func TestCostIsCountedByKind(t *testing.T) {
	metricSet := New(prometheus.NewRegistry())
	ev := app.UsageEvent{Provider: "claude", Model: "claude-sonnet-5", Cost: app.UsageCost{
		InputUSD: 1, OutputUSD: 2, CacheReadUSD: 0.25, CacheWriteUSD: 0.5, CacheSavingsUSD: 0.75,
		UnpricedTokens: 40, Priced: true,
	}}
	metricSet.ObserveUsage(ev, "u")
	ev.Cost = app.UsageCost{CacheWriteUSD: 4, CacheSavingsUSD: -1, Priced: true}
	metricSet.ObserveUsage(ev, "u")

	for kind, want := range map[string]float64{"input": 1, "output": 2, "cache_read": 0.25, "cache_write": 4.5} {
		if got := testutil.ToFloat64(metricSet.cost.WithLabelValues("u", "claude", "claude-sonnet-5", kind)); got != want {
			t.Errorf("cost{kind=%s} = %v, want %v", kind, got, want)
		}
	}

	if got := testutil.ToFloat64(metricSet.cacheSavings.WithLabelValues("u", "claude", "claude-sonnet-5")); got != 0.75 {
		t.Errorf("cache savings = %v, want 0.75 (the positive request only)", got)
	}

	if got := testutil.ToFloat64(metricSet.cachePremium.WithLabelValues("u", "claude", "claude-sonnet-5")); got != 1 {
		t.Errorf("cache write premium = %v, want 1 (the negative request, as a positive amount)", got)
	}

	if got := testutil.ToFloat64(metricSet.unpriced.WithLabelValues("claude", "claude-sonnet-5")); got != 40 {
		t.Errorf("unpriced tokens = %v, want 40", got)
	}
}

// The burned counter counts rises above each window's high-water mark.
func TestQuotaBurnedCountsRisesAboveTheHighWaterMark(t *testing.T) {
	reset := time.Date(2026, 9, 23, 15, 0, 0, 0, time.UTC)
	burned := func(m *Metrics, account, window string) float64 {
		return testutil.ToFloat64(m.quotaBurned.WithLabelValues(account, "claude", window))
	}

	t.Run("a late lower reading adds nothing and keeps the mark", func(t *testing.T) {
		metricSet := New(prometheus.NewRegistry())
		// A stream started at 0.40 finishes after shorter requests reported 0.41..0.45.
		for _, r := range []float64{0.40, 0.41, 0.42, 0.43, 0.44, 0.45, 0.40, 0.46} {
			metricSet.ObserveVendorQuota("a", "claude", "5h", r, reset)
		}

		if got := burned(metricSet, "a", "5h"); math.Abs(got-0.06) > 1e-12 {
			t.Fatalf("burned = %v, want 0.06", got)
		}
	})

	t.Run("the first reading of a new window counts from zero", func(t *testing.T) {
		metricSet := New(prometheus.NewRegistry())
		metricSet.ObserveVendorQuota("a", "claude", "5h", 0.5, reset) // the reference only
		metricSet.ObserveVendorQuota("a", "claude", "5h", 0.75, reset)
		// The window reset; its first reading is higher than the old mark.
		next := reset.Add(5 * time.Hour)
		metricSet.ObserveVendorQuota("a", "claude", "5h", 0.9, next)
		// A late reading of the old window counts nothing.
		metricSet.ObserveVendorQuota("a", "claude", "5h", 0.8, reset)
		metricSet.ObserveVendorQuota("a", "claude", "5h", 0.95, next)

		if got := burned(metricSet, "a", "5h"); math.Abs(got-(0.25+0.9+0.05)) > 1e-12 {
			t.Fatalf("burned = %v, want 0.25 + 0.9 + 0.05", got)
		}
	})

	t.Run("a late reading of the previous window counts nothing", func(t *testing.T) {
		metricSet := New(prometheus.NewRegistry())
		metricSet.ObserveVendorQuota("a", "claude", "5h", 0.7, reset)
		next := reset.Add(5 * time.Hour)
		metricSet.ObserveVendorQuota("a", "claude", "5h", 0.1, next)  // new window: +0.1
		metricSet.ObserveVendorQuota("a", "claude", "5h", 0.8, reset) // late, old window
		metricSet.ObserveVendorQuota("a", "claude", "5h", 0.15, next) // +0.05

		if got := burned(metricSet, "a", "5h"); math.Abs(got-0.15) > 1e-12 {
			t.Fatalf("burned = %v, want 0.1 + 0.05", got)
		}
	})

	t.Run("reset time jitter is the same window", func(t *testing.T) {
		m := New(prometheus.NewRegistry())
		m.ObserveVendorQuota("a", "codex", "5h", 0.3, reset)
		m.ObserveVendorQuota("a", "codex", "5h", 0.2, reset.Add(30*time.Second)) // late, not a new window
		m.ObserveVendorQuota("a", "codex", "5h", 0.35, reset.Add(-20*time.Second))

		if got := testutil.ToFloat64(m.quotaBurned.WithLabelValues("a", "codex", "5h")); math.Abs(got-0.05) > 1e-12 {
			t.Fatalf("burned = %v, want 0.05", got)
		}
	})

	t.Run("windows and accounts are apart", func(t *testing.T) {
		metricSet := New(prometheus.NewRegistry())
		metricSet.ObserveVendorQuota("a", "claude", "5h", 0.5, reset)
		metricSet.ObserveVendorQuota("a", "claude", "7d", 0.9, reset)
		metricSet.ObserveVendorQuota("b", "claude", "5h", 0.1, reset)
		metricSet.ObserveVendorQuota("b", "claude", "5h", 0.2, reset)
		metricSet.ObserveVendorQuota("a", "claude", "5h", 0.6, reset)

		if got := burned(metricSet, "a", "7d"); got != 0 {
			t.Errorf("a/7d burned = %v, want 0 (first reading of that window)", got)
		}

		if got := burned(metricSet, "b", "5h"); math.Abs(got-0.1) > 1e-12 {
			t.Errorf("b/5h burned = %v, want 0.1", got)
		}

		if got := burned(metricSet, "a", "5h"); math.Abs(got-0.1) > 1e-12 {
			t.Errorf("a/5h burned = %v, want 0.1", got)
		}
	})
}

// ForgetAccount drops the burned series and the mark: the first reading after it
// is a first reading again.
func TestForgetAccountForgetsTheBurnedMark(t *testing.T) {
	metricSet := New(prometheus.NewRegistry())
	reset := time.Now().Add(time.Hour)
	metricSet.ObserveVendorQuota("gone", "claude", "5h", 0.2, reset)
	metricSet.ObserveVendorQuota("gone", "claude", "5h", 0.5, reset)
	metricSet.ObserveVendorQuota("kept", "claude", "5h", 0.2, reset)
	metricSet.ObserveVendorQuota("kept", "claude", "5h", 0.3, reset)
	metricSet.ForgetAccount("gone", "claude")

	if n := testutil.CollectAndCount(metricSet.quotaBurned); n != 1 {
		t.Fatalf("burned series = %d after ForgetAccount, want the kept account's only", n)
	}

	metricSet.ObserveVendorQuota("gone", "claude", "5h", 0.9, reset)

	if n := testutil.CollectAndCount(metricSet.quotaBurned); n != 1 {
		t.Fatalf("a first reading after ForgetAccount burned %v, want nothing",
			testutil.ToFloat64(metricSet.quotaBurned.WithLabelValues("gone", "claude", "5h")))
	}
}
