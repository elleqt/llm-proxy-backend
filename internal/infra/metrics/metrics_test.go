package metrics

import (
	"io"
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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		got := testutil.ToFloat64(metricSet.tokens.WithLabelValues("alice@example.com", "claude", "claude-sonnet-5", "priority", kind))
		assert.Equal(t, want, got, "%s tokens", kind)
	}
	// ToFloat64 above created no new series; cache_write was zero, so it must not exist.
	require.Equal(t, 4, testutil.CollectAndCount(metricSet.tokens), "token series (zero-valued cache_write must not be emitted)")
}

func TestServiceTierIsAClosedSet(t *testing.T) {
	metricSet := New(prometheus.NewRegistry())
	for _, tier := range []string{"", "flex", "auto", "scale", "priority", "turbo", "Priority"} {
		metricSet.ObserveUsage(app.UsageEvent{Provider: "codex", Model: "gpt-6", ServiceTier: tier, TokensInput: 1}, "u")
	}

	for tier, want := range map[string]float64{"default": 1, "flex": 1, "auto": 1, "scale": 1, "priority": 1, "other": 2} {
		got := testutil.ToFloat64(metricSet.tokens.WithLabelValues("u", "codex", "gpt-6", tier, "input"))
		assert.Equal(t, want, got, "tokens{service_tier=%q}", tier)
	}

	require.Equal(t, 6, testutil.CollectAndCount(metricSet.tokens), "token series")
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
		got := testutil.ToFloat64(metricSet.requests.WithLabelValues("svc-ci", "codex", "gpt-6", tc.stream, tc.status))
		assert.Equal(t, tc.want, got, "requests{stream=%q,status=%q}", tc.stream, tc.status)
	}

	require.Equal(t, 6, testutil.CollectAndCount(metricSet.requests), "request series")
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

	streamed := durations["true"]
	require.Equal(t, uint64(2), streamed.GetSampleCount(), "streamed duration count")
	require.Equal(t, 92.0, streamed.GetSampleSum(), "streamed duration sum")

	nonStreamed := durations["false"]
	require.Equal(t, uint64(1), nonStreamed.GetSampleCount(), "non-streamed duration count")
	require.Equal(t, 0.5, nonStreamed.GetSampleSum(), "non-streamed duration sum")

	ttftMetrics := fams["llmproxy_ttft_seconds"].GetMetric()
	require.NotEmpty(t, ttftMetrics, "ttft histogram")

	ttft := ttftMetrics[0].GetHistogram()
	require.Equal(t, uint64(2), ttft.GetSampleCount(), "ttft count (streamed requests only)")
	require.Equal(t, 2.0, ttft.GetSampleSum(), "ttft sum (streamed requests only)")
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
		got := testutil.ToFloat64(metricSet.policyDenied.WithLabelValues("u", tc.model, tc.reason))
		assert.Equal(t, tc.want, got, "policy_denied{model=%q,reason=%q}", tc.model, tc.reason)
	}

	require.Equal(t, 3, testutil.CollectAndCount(metricSet.policyDenied), "policy_denied series: client strings must not create series")
}

func TestPolicyDeniedWithoutPredicateNeverLabelsTheModel(t *testing.T) {
	metricSet := New(prometheus.NewRegistry())
	metricSet.ObservePolicyDenied("u", "claude-sonnet-5", DenyModelNotAllowed)

	require.Equal(t, 1.0, testutil.ToFloat64(metricSet.policyDenied.WithLabelValues("u", Unknown, "model_not_allowed")),
		"policy_denied{model=%q}", Unknown)
	require.Equal(t, 1, testutil.CollectAndCount(metricSet.policyDenied), "policy_denied series")
}

// A request refused before anyone was authenticated has no owner: it is counted
// under Unknown, never under an empty user label.
func TestPolicyDeniedWithoutOwnerIsUnknown(t *testing.T) {
	metricSet := New(prometheus.NewRegistry())
	metricSet.ObservePolicyDenied("", "", DenyRouteNotAllowed)

	require.Equal(t, 1.0, testutil.ToFloat64(metricSet.policyDenied.WithLabelValues(Unknown, Unknown, "route_not_allowed")),
		"policy_denied{user=%q}", Unknown)
	require.Equal(t, 1, testutil.CollectAndCount(metricSet.policyDenied), "policy_denied series")
}

func TestVendorQuotaGauges(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	clock := &fakeClock{t: now}
	metricSet := New(prometheus.NewRegistry(), WithClock(clock))
	reset := now.Add(3 * time.Hour)

	metricSet.ObserveVendorQuota("acct-1", "claude", "5h", 0.42, reset)

	labels := []string{"acct-1", "claude", "5h"}
	require.Equal(t, 0.42, testutil.ToFloat64(metricSet.quotaUsed.WithLabelValues(labels...)), "quota ratio (ratio in, ratio out)")
	require.Equal(t, float64(reset.Unix()), testutil.ToFloat64(metricSet.quotaReset.WithLabelValues(labels...)), "reset timestamp")
	require.Equal(t, float64(now.Unix()), testutil.ToFloat64(metricSet.quotaObserved.WithLabelValues(labels...)), "observed timestamp")

	// A later report without a reset time updates use and observation, keeps the reset.
	clock.t = now.Add(time.Minute)

	metricSet.ObserveVendorQuota("acct-1", "claude", "5h", 0.5, time.Time{})

	require.Equal(t, 0.5, testutil.ToFloat64(metricSet.quotaUsed.WithLabelValues(labels...)), "quota ratio")
	require.Equal(t, float64(reset.Unix()), testutil.ToFloat64(metricSet.quotaReset.WithLabelValues(labels...)),
		"reset timestamp after zero resetAt must be kept")
	require.Equal(t, float64(clock.t.Unix()), testutil.ToFloat64(metricSet.quotaObserved.WithLabelValues(labels...)), "observed timestamp")
}

func TestAccountDisabledFollowsLatestState(t *testing.T) {
	metricSet := New(prometheus.NewRegistry())
	metricSet.SetAccountDisabled("acct-1", "codex", true)

	require.Equal(t, 1.0, testutil.ToFloat64(metricSet.accountDisabled.WithLabelValues("acct-1", "codex")), "disabled")

	metricSet.SetAccountDisabled("acct-1", "codex", false)

	require.Zero(t, testutil.ToFloat64(metricSet.accountDisabled.WithLabelValues("acct-1", "codex")), "disabled after re-enable")
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
		assert.Equal(t, tc.want, testutil.CollectAndCount(tc.c), "%s series after ForgetAccount", tc.name)
	}

	require.Equal(t, 0.9, testutil.ToFloat64(metricSet.quotaUsed.WithLabelValues("kept", "claude", "5h")), "kept account's quota")
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
	require.NoError(t, err, "handler output is not Prometheus text:\n%s", body)

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
		assert.Contains(t, fams, name, "family missing from handler output")
	}

	for name := range fams {
		assert.True(t, strings.HasPrefix(name, "llmproxy_"), "family %s lacks the llmproxy_ prefix", name)
	}

	assert.Contains(t, body, `llmproxy_build_info{version="v1.2.3"} 1`, "build_info does not carry the configured version")
}

func TestLabelsNeverCarryThePrincipal(t *testing.T) {
	userID, tokenID := uuid.New(), uuid.New()
	metricSet := New(prometheus.NewRegistry())

	metricSet.ObserveUsage(app.UsageEvent{
		UserID: userID, TokenID: tokenID,
		Provider: "claude", Model: "m", TokensInput: 7, StatusCode: 200,
	}, "alice@example.com")

	body := scrape(t, metricSet)
	require.Contains(t, body, `user="alice@example.com"`, "caller-supplied user label missing")
	// The principal upstream carries as the record's APIKey is "<userID>:<tokenID>".
	for _, id := range []string{userID.String(), tokenID.String()} {
		require.NotContains(t, body, id, "handler output contains the principal")
	}
}

func scrape(t *testing.T, m *Metrics) string {
	t.Helper()

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", http.NoBody))

	require.Equal(t, http.StatusOK, rec.Code, "handler status")

	b, err := io.ReadAll(rec.Body)
	require.NoError(t, err)

	return string(b)
}

func gather(t *testing.T, reg *prometheus.Registry) map[string]*dto.MetricFamily {
	t.Helper()

	mfs, err := reg.Gather()
	require.NoError(t, err)

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
		assert.Equal(t, want, testutil.ToFloat64(metricSet.cost.WithLabelValues("u", "claude", "claude-sonnet-5", kind)), "cost{kind=%s}", kind)
	}

	assert.Equal(t, 0.75, testutil.ToFloat64(metricSet.cacheSavings.WithLabelValues("u", "claude", "claude-sonnet-5")),
		"cache savings (the positive request only)")
	assert.Equal(t, 1.0, testutil.ToFloat64(metricSet.cachePremium.WithLabelValues("u", "claude", "claude-sonnet-5")),
		"cache write premium (the negative request, as a positive amount)")
	assert.Equal(t, 40.0, testutil.ToFloat64(metricSet.unpriced.WithLabelValues("claude", "claude-sonnet-5")), "unpriced tokens")
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

		require.InDelta(t, 0.06, burned(metricSet, "a", "5h"), 1e-12, "burned")
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

		require.InDelta(t, 0.25+0.9+0.05, burned(metricSet, "a", "5h"), 1e-12, "burned")
	})

	t.Run("a late reading of the previous window counts nothing", func(t *testing.T) {
		metricSet := New(prometheus.NewRegistry())
		metricSet.ObserveVendorQuota("a", "claude", "5h", 0.7, reset)
		next := reset.Add(5 * time.Hour)
		metricSet.ObserveVendorQuota("a", "claude", "5h", 0.1, next)  // new window: +0.1
		metricSet.ObserveVendorQuota("a", "claude", "5h", 0.8, reset) // late, old window
		metricSet.ObserveVendorQuota("a", "claude", "5h", 0.15, next) // +0.05

		require.InDelta(t, 0.1+0.05, burned(metricSet, "a", "5h"), 1e-12, "burned")
	})

	t.Run("reset time jitter is the same window", func(t *testing.T) {
		m := New(prometheus.NewRegistry())
		m.ObserveVendorQuota("a", "codex", "5h", 0.3, reset)
		m.ObserveVendorQuota("a", "codex", "5h", 0.2, reset.Add(30*time.Second)) // late, not a new window
		m.ObserveVendorQuota("a", "codex", "5h", 0.35, reset.Add(-20*time.Second))

		require.InDelta(t, 0.05, testutil.ToFloat64(m.quotaBurned.WithLabelValues("a", "codex", "5h")), 1e-12, "burned")
	})

	t.Run("windows and accounts are apart", func(t *testing.T) {
		metricSet := New(prometheus.NewRegistry())
		metricSet.ObserveVendorQuota("a", "claude", "5h", 0.5, reset)
		metricSet.ObserveVendorQuota("a", "claude", "7d", 0.9, reset)
		metricSet.ObserveVendorQuota("b", "claude", "5h", 0.1, reset)
		metricSet.ObserveVendorQuota("b", "claude", "5h", 0.2, reset)
		metricSet.ObserveVendorQuota("a", "claude", "5h", 0.6, reset)

		assert.Zero(t, burned(metricSet, "a", "7d"), "a/7d burned (first reading of that window)")
		assert.InDelta(t, 0.1, burned(metricSet, "b", "5h"), 1e-12, "b/5h burned")
		assert.InDelta(t, 0.1, burned(metricSet, "a", "5h"), 1e-12, "a/5h burned")
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

	require.Equal(t, 1, testutil.CollectAndCount(metricSet.quotaBurned), "burned series after ForgetAccount: want the kept account's only")

	metricSet.ObserveVendorQuota("gone", "claude", "5h", 0.9, reset)

	require.Equal(t, 1, testutil.CollectAndCount(metricSet.quotaBurned), "a first reading after ForgetAccount must burn nothing")
}
