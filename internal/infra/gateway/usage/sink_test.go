package usage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/app/mocks"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/elleqt/llm-proxy-backend/internal/infra/metrics"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	cliproxyusage "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// discardLog drops warnings, for tests that do not assert on them.
type discardLog struct{}

func (discardLog) Warn(string, ...slog.Attr) {}

// recordingLog keeps every warning, formatted.
type recordingLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *recordingLog) Warn(msg string, attrs ...slog.Attr) {
	l.mu.Lock()
	l.lines = append(l.lines, fmt.Sprintln(msg, attrs))
	l.mu.Unlock()
}

func (l *recordingLog) logged() []string {
	l.mu.Lock()
	defer l.mu.Unlock()

	return append([]string(nil), l.lines...)
}

// wallClock is the real time.
type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

// manualClock only moves when the test moves it.
type manualClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *manualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

func (c *manualClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

var (
	sinkUser  = uuid.MustParse("3f0e2d1c-4b5a-4968-8776-a5b4c3d2e1f0")
	sinkToken = uuid.MustParse("9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d")
	sinkKey   = app.Principal{UserID: sinkUser, TokenID: sinkToken}.String()
)

// ledger is a UsageRepo mock that keeps every event appended, in order.
type ledger struct {
	*mocks.UsageRepo

	mu     sync.Mutex
	events []app.UsageEvent
}

func newLedger(t *testing.T) *ledger {
	t.Helper()

	return &ledger{UsageRepo: mocks.NewUsageRepo(t)}
}

func (l *ledger) keep(evs []app.UsageEvent) {
	l.mu.Lock()
	l.events = append(l.events, evs...)
	l.mu.Unlock()
}

// accept makes every AppendBatch succeed and keeps what it was given.
func (l *ledger) accept() {
	l.EXPECT().AppendBatch(mock.Anything, mock.Anything).
		Run(func(_ context.Context, evs []app.UsageEvent) { l.keep(evs) }).Return(nil)
}

func (l *ledger) written() []app.UsageEvent {
	l.mu.Lock()
	defer l.mu.Unlock()

	return append([]app.UsageEvent(nil), l.events...)
}

// knownPrincipal makes sinkUser alice@example.com.
func knownPrincipal(users *mocks.UserRepo, tokens *mocks.TokenRepo) {
	users.EXPECT().ByID(mock.Anything, sinkUser).Return(identity.User{
		ID: sinkUser, Kind: identity.KindHuman, Email: "alice@example.com", DisplayName: "Alice",
	}, nil).Maybe()
	users.EXPECT().TouchLastSeen(mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
	tokens.EXPECT().TouchLastUsed(mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
}

// newMeteredSink builds a sink on the wall clock reporting to real metric families.
func newMeteredSink(events app.UsageRepo, tokens app.TokenRepo, users app.UserRepo, log app.Logger) (*Sink, *metrics.Metrics, *prometheus.Registry) {
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)

	return New(events, tokens, users, &app.PriceTable{}, m, wallClock{}, log), m, reg
}

// flushed waits until every record handed to sink so far has been processed.
// It is bounded: a mock refusing an unexpected call ends the worker goroutine
// (FailNow), which no recover can catch.
func flushed(t *testing.T, sink *Sink) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	require.NoError(t, sink.sync(ctx), "the sink's worker never caught up")
}

func TestSinkAttributesRecordToPrincipal(t *testing.T) {
	events, tokens, users := newLedger(t), mocks.NewTokenRepo(t), mocks.NewUserRepo(t)
	events.accept()
	users.EXPECT().ByID(mock.Anything, sinkUser).Return(identity.User{ID: sinkUser, Email: "alice@example.com"}, nil)

	at := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	// Stamped when the response completed, not when the request started.
	done := at.Add(1500 * time.Millisecond)
	tokens.EXPECT().TouchLastUsed(mock.Anything, sinkToken, done).Return(nil)
	users.EXPECT().TouchLastSeen(mock.Anything, sinkUser, done).Return(nil)

	sink, _, _ := newMeteredSink(events, tokens, users, discardLog{})
	sink.HandleUsage(context.Background(), cliproxyusage.Record{
		Provider: "claude", Model: "claude-sonnet-5", Alias: "sonnet", APIKey: sinkKey, AuthID: "claude-1.json",
		RequestedAt: at, Stream: true, Latency: 1500 * time.Millisecond, TTFT: 300 * time.Millisecond,
		// Anthropic's output count includes the thinking.
		Detail: cliproxyusage.Detail{InputTokens: 10, OutputTokens: 20, ReasoningTokens: 3, CacheReadTokens: 5, CacheCreationTokens: 2, TotalTokens: 37},
	})
	flushed(t, sink)

	want := app.UsageEvent{
		At: at, UserID: sinkUser, TokenID: sinkToken, Provider: "claude", Model: "claude-sonnet-5", Alias: "sonnet",
		Stream: true, TokensInput: 10, TokensOutput: 17, TokensReasoning: 3, TokensCacheRead: 5, TokensCacheWrite: 2,
		TokensTotal: 37, BreakdownQuality: "reconstructed", LatencyMS: 1500, TTFTMS: 300, VendorAccountID: "claude-1.json",
		// No price: every token is unpriced.
		Cost: app.UsageCost{UnpricedTokens: 37},
	}
	require.Equal(t, []app.UsageEvent{want}, events.written(), "ledger")
}

// TestSinkStoresUnattributedRecord: a record whose APIKey is not a principal
// (an upstream-internal call, a future path) is written with no user and no
// token, counted as "unknown", stamps nobody, and its APIKey is never logged.
func TestSinkStoresUnattributedRecord(t *testing.T) {
	const apiKey = "sk-upstream-internal-credential"

	events, tokens, users := newLedger(t), mocks.NewTokenRepo(t), mocks.NewUserRepo(t)
	events.accept()

	log := &recordingLog{}
	// No ByID, TouchLastUsed or TouchLastSeen expectations: any call fails the test.

	sink, meter, _ := newMeteredSink(events, tokens, users, log)
	sink.HandleUsage(context.Background(), cliproxyusage.Record{Provider: "claude", Model: "claude-sonnet-5", APIKey: apiKey})
	flushed(t, sink)

	got := events.written()
	require.Len(t, got, 1, "ledger = %+v, want one row", got)
	require.Equal(t, uuid.Nil, got[0].UserID, "user of an unattributed row")
	require.Equal(t, uuid.Nil, got[0].TokenID, "token of an unattributed row")
	require.Equal(t, "claude-sonnet-5", got[0].Model)

	require.Contains(t, scrape(t, meter),
		`llmproxy_requests_total{model="claude-sonnet-5",provider="claude",status="ok",stream="false",user="unknown"} 1`,
		"unattributed request not counted as unknown")

	logged := log.logged()
	require.Len(t, logged, 1, "warnings")
	require.NotContains(t, logged[0], apiKey, "the warning carries the APIKey")
}

func TestSinkRecordsFailures(t *testing.T) {
	events, tokens, users := newLedger(t), mocks.NewTokenRepo(t), mocks.NewUserRepo(t)
	events.accept()
	knownPrincipal(users, tokens)

	sink, meter, _ := newMeteredSink(events, tokens, users, discardLog{})
	sink.HandleUsage(context.Background(), cliproxyusage.Record{
		Provider: "claude", Model: "claude-sonnet-5", APIKey: sinkKey, AuthID: "claude-1.json",
		Failed: true, Fail: cliproxyusage.Failure{StatusCode: 429, Body: "rate limited"},
	})
	sink.HandleUsage(context.Background(), cliproxyusage.Record{
		Provider: "claude", Model: "claude-sonnet-5", APIKey: sinkKey, AuthID: "claude-1.json",
	})
	flushed(t, sink)

	got := events.written()
	require.Len(t, got, 2, "ledger = %+v, want the 429 failure then a success", got)
	require.True(t, got[0].Failed, "first row failed")
	require.Equal(t, http.StatusTooManyRequests, got[0].StatusCode)
	require.False(t, got[1].Failed, "second row failed")

	require.Contains(t, scrape(t, meter), `llmproxy_account_failures_total{account="claude-1.json",provider="claude"} 1`,
		"account failure not counted exactly once")
}

// TestSinkNamesProvidersAsPolicyDoes: a codex record is "chatgpt" in the
// ledger, every metric and the quota store, while its quota headers are still
// read as Codex's.
func TestSinkNamesProvidersAsPolicyDoes(t *testing.T) {
	events, tokens, users := newLedger(t), mocks.NewTokenRepo(t), mocks.NewUserRepo(t)
	events.accept()
	knownPrincipal(users, tokens)

	sink, meter, _ := newMeteredSink(events, tokens, users, discardLog{})
	sink.HandleUsage(context.Background(), cliproxyusage.Record{
		Provider: "codex", Model: "gpt-6", APIKey: sinkKey, AuthID: "codex-1.json",
		Failed: true, Fail: cliproxyusage.Failure{StatusCode: 429},
		Detail:          cliproxyusage.Detail{InputTokens: 4},
		ResponseHeaders: headers("X-Codex-Primary-Used-Percent", "10", "X-Codex-Primary-Window-Minutes", "300"),
	})
	flushed(t, sink)

	got := events.written()
	require.Len(t, got, 1, "ledger")
	require.Equal(t, "chatgpt", got[0].Provider, "ledger provider")

	signals := sink.QuotaSignals()
	require.Len(t, signals, 1, "QuotaSignals()")
	require.Equal(t, "chatgpt", signals[0].Provider, "quota signal provider")
	require.Equal(t, "5h", signals[0].Window, "quota signal window")

	body := scrape(t, meter)
	for _, family := range []string{
		"llmproxy_requests_total", "llmproxy_tokens_total",
		"llmproxy_account_failures_total", "llmproxy_vendor_quota_used_ratio",
	} {
		assert.Contains(t, body, family+"{", "%s has no series", family)
		assert.True(t, hasSeries(body, family, `provider="chatgpt"`), "%s has no provider=\"chatgpt\" series:\n%s", family, body)
	}

	require.NotContains(t, body, `provider="codex"`, "the upstream key reached a label")
}

// hasSeries reports whether an exposition line of family carries label.
func hasSeries(body, family, label string) bool {
	for line := range strings.SplitSeq(body, "\n") {
		if strings.HasPrefix(line, family+"{") && strings.Contains(line, label) {
			return true
		}
	}

	return false
}

// TestSinkPrefersServedTier: the ledger and the metrics carry the tier the
// vendor served; the requested one only when the vendor reported none.
func TestSinkPrefersServedTier(t *testing.T) {
	events, tokens, users := newLedger(t), mocks.NewTokenRepo(t), mocks.NewUserRepo(t)
	events.accept()
	knownPrincipal(users, tokens)

	sink, meter, _ := newMeteredSink(events, tokens, users, discardLog{})
	sink.HandleUsage(context.Background(), cliproxyusage.Record{
		Provider: "codex", Model: "gpt-6", APIKey: sinkKey, ServiceTier: "priority", ResponseServiceTier: "flex",
		Detail: cliproxyusage.Detail{InputTokens: 1},
	})
	sink.HandleUsage(context.Background(), cliproxyusage.Record{
		Provider: "codex", Model: "gpt-6", APIKey: sinkKey, ServiceTier: "priority",
		Detail: cliproxyusage.Detail{InputTokens: 1},
	})
	flushed(t, sink)

	got := events.written()
	require.Len(t, got, 2, "tiers")
	require.Equal(t, "flex", got[0].ServiceTier, "served tier")
	require.Equal(t, "priority", got[1].ServiceTier, "requested tier, none served")

	body := scrape(t, meter)
	for _, tier := range []string{"flex", "priority"} {
		require.Contains(t, body, `kind="input",model="gpt-6",provider="chatgpt",service_tier="`+tier+`",user="alice@example.com"} 1`,
			"no %s tokens series", tier)
	}
}

// TestSinkPrefersCanonicalBreakdown: upstream's breakdown partitions the total,
// so cache reads inside an OpenAI-style prompt count once, not twice.
func TestSinkPrefersCanonicalBreakdown(t *testing.T) {
	events, tokens, users := newLedger(t), mocks.NewTokenRepo(t), mocks.NewUserRepo(t)
	events.accept()
	knownPrincipal(users, tokens)

	sink, _, _ := newMeteredSink(events, tokens, users, discardLog{})
	sink.HandleUsage(context.Background(), cliproxyusage.Record{
		Provider: "codex", Model: "gpt-6", APIKey: sinkKey,
		Detail: cliproxyusage.Detail{
			InputTokens: 100, CachedTokens: 40, OutputTokens: 20, ReasoningTokens: 5, TotalTokens: 120,
			TokenBreakdown: cliproxyusage.NewSubsetTokenBreakdown(100, 40, 0, 20, 5, 120),
		},
	})
	flushed(t, sink)

	got := events.written()
	require.Len(t, got, 1, "ledger")

	event := got[0]
	require.Equal(t, int64(60), event.TokensInput, "input")
	require.Equal(t, int64(40), event.TokensCacheRead, "cache read")
	require.Equal(t, int64(15), event.TokensOutput, "output")
	require.Equal(t, int64(5), event.TokensReasoning, "reasoning")
	require.Equal(t, int64(120), event.TokensTotal, "total")
	require.Equal(t, "complete", event.BreakdownQuality, "quality")
}

// TestSinkReconstructsARawBreakdown: without a valid canonical breakdown the sink
// partitions the raw counts by the provider's protocol before pricing: OpenAI-style
// prompts include the cache and completions the reasoning; Gemini-style prompts
// include the cache and reasoning is separate; Anthropic's cache counts are
// separate and its output includes the thinking. Where upstream would not guess
// (an unknown protocol, counts above the reported total) nothing is priced.
func TestSinkReconstructsARawBreakdown(t *testing.T) {
	events, tokens, users := newLedger(t), mocks.NewTokenRepo(t), mocks.NewUserRepo(t)
	events.accept()
	knownPrincipal(users, tokens)

	prices := &app.PriceTable{}
	prices.SetPrices([]app.ModelPrice{
		{Provider: "chatgpt", Model: "gpt-6", Input: 2, Output: 10, CacheRead: 0.5},
		{Provider: "claude", Model: "claude-sonnet-5", Input: 3, Output: 15, CacheRead: 0.3, CacheWrite: 3.75},
		{Provider: "gemini", Model: "gemini-3", Input: 1, Output: 8, CacheRead: 0.25},
		{Provider: "mystery", Model: "m", Input: 1, Output: 1},
	})
	sink := New(events, tokens, users, prices, metrics.New(prometheus.NewRegistry()), wallClock{}, discardLog{})

	for _, rec := range []cliproxyusage.Record{
		{Provider: "codex", Model: "gpt-6", Detail: cliproxyusage.Detail{
			InputTokens: 100, CachedTokens: 40, OutputTokens: 20, ReasoningTokens: 5, TotalTokens: 120,
		}},
		{Provider: "claude", Model: "claude-sonnet-5", Detail: cliproxyusage.Detail{
			InputTokens: 100, CacheReadTokens: 40, CacheCreationTokens: 10, OutputTokens: 50, ReasoningTokens: 30, TotalTokens: 200,
		}},
		// No reads: upstream copies the cache creation into the cached count.
		{Provider: "claude", Model: "claude-sonnet-5", Detail: cliproxyusage.Detail{
			InputTokens: 100, CacheCreationTokens: 10, CachedTokens: 10, OutputTokens: 20,
		}},
		{Provider: "gemini", Model: "gemini-3", Detail: cliproxyusage.Detail{
			InputTokens: 100, CachedTokens: 40, OutputTokens: 20, ReasoningTokens: 5, TotalTokens: 125,
		}},
		{Provider: "mystery", Model: "m", Detail: cliproxyusage.Detail{InputTokens: 100, OutputTokens: 20, TotalTokens: 120}},
		// Claude counts adding up to more than the reported total.
		{Provider: "claude", Model: "claude-sonnet-5", Detail: cliproxyusage.Detail{InputTokens: 100, OutputTokens: 50, TotalTokens: 120}},
	} {
		rec.APIKey = sinkKey
		sink.HandleUsage(context.Background(), rec)
	}

	flushed(t, sink)

	got := events.written()
	require.Len(t, got, 6, "ledger")

	type kinds struct {
		in, out, reasoning, read, write, total int64
		quality                                string
		usd                                    float64
		unpriced                               int64
	}

	for idx, want := range []kinds{
		{60, 15, 5, 40, 0, 120, "reconstructed", (60*2 + 40*0.5 + 20*10) / 1e6, 0},
		{100, 20, 30, 40, 10, 200, "reconstructed", (100*3 + 50*15 + 40*0.3 + 10*3.75) / 1e6, 0},
		{100, 20, 0, 0, 10, 130, "reconstructed", (100*3 + 20*15 + 10*3.75) / 1e6, 0},
		{60, 20, 5, 40, 0, 125, "reconstructed", (60*1 + 25*8 + 40*0.25) / 1e6, 0},
		{0, 0, 0, 0, 0, 120, "unclassified", 0, 120},
		{0, 0, 0, 0, 0, 120, "inconsistent", 0, 120},
	} {
		event := got[idx]

		have := kinds{
			event.TokensInput, event.TokensOutput, event.TokensReasoning, event.TokensCacheRead, event.TokensCacheWrite, event.TokensTotal,
			event.BreakdownQuality, event.Cost.TotalUSD(), event.Cost.UnpricedTokens,
		}
		assert.InDelta(t, want.usd, have.usd, 1e-15, "%s record %d: cost", event.Provider, idx)

		have.usd = want.usd
		assert.Equal(t, want, have, "%s record %d", event.Provider, idx)
	}
}

// TestSinkPricesAtTheTimeOfRecording: each row carries the cost at the price in
// force when the sink recorded it, and the metrics count that same cost.
func TestSinkPricesAtTheTimeOfRecording(t *testing.T) {
	events, tokens, users := newLedger(t), mocks.NewTokenRepo(t), mocks.NewUserRepo(t)
	events.accept()
	knownPrincipal(users, tokens)

	prices := &app.PriceTable{}
	meter := metrics.New(prometheus.NewRegistry())
	sink := New(events, tokens, users, prices, meter, wallClock{}, discardLog{})
	send := func() {
		sink.HandleUsage(context.Background(), cliproxyusage.Record{
			Provider: "claude", Model: "claude-sonnet-5", APIKey: sinkKey,
			Detail: cliproxyusage.Detail{TokenBreakdown: cliproxyusage.NewIndependentTokenBreakdown(1_000_000, 0, 0, 0, 0, 1_000_000)},
		})
		flushed(t, sink)
	}

	send() // no price yet
	prices.SetPrices([]app.ModelPrice{{Provider: "claude", Model: "claude-sonnet-5", Input: 3}})
	send()
	prices.SetPrices([]app.ModelPrice{{Provider: "claude", Model: "claude-sonnet-5", Input: 5}})
	send()

	got := events.written()
	require.Len(t, got, 3, "ledger")

	assert.False(t, got[0].Cost.Priced, "row before any price is priced")
	assert.Equal(t, int64(1_000_000), got[0].Cost.UnpricedTokens, "unpriced tokens before any price")

	assert.True(t, got[1].Cost.Priced, "row after the first price is unpriced")
	assert.Equal(t, 3.0, got[1].Cost.InputUSD, "cost at the first price")
	assert.Equal(t, 5.0, got[2].Cost.InputUSD, "cost at the second price")

	require.Contains(t, scrape(t, meter),
		`llmproxy_cost_usd_total{kind="input",model="claude-sonnet-5",provider="claude",user="alice@example.com"} 8`,
		"want the metrics to count the rows' $3 + $5")
}

// TestSinkLabelsMetricsWithEmail: the user label is the owner's email (a
// service account's name), looked up once per TTL, and no id reaches a label.
func TestSinkLabelsMetricsWithEmail(t *testing.T) {
	service, serviceToken := uuid.New(), uuid.New()
	events, tokens, users := newLedger(t), mocks.NewTokenRepo(t), mocks.NewUserRepo(t)
	events.accept()
	users.EXPECT().ByID(mock.Anything, sinkUser).Return(identity.User{ID: sinkUser, Email: "alice@example.com"}, nil).Once()
	users.EXPECT().ByID(mock.Anything, service).Return(identity.NewService(service, "chat-panel", nil), nil).Once()
	users.EXPECT().TouchLastSeen(mock.Anything, mock.Anything, mock.Anything).Return(nil)
	tokens.EXPECT().TouchLastUsed(mock.Anything, mock.Anything, mock.Anything).Return(nil)

	sink, meter, _ := newMeteredSink(events, tokens, users, discardLog{})

	serviceKey := app.Principal{UserID: service, TokenID: serviceToken}.String()
	for _, key := range []string{sinkKey, sinkKey, serviceKey} {
		sink.HandleUsage(context.Background(), cliproxyusage.Record{Provider: "claude", Model: "m", APIKey: key})
		flushed(t, sink) // separate batches: the second alice record must hit the cache
	}

	body := scrape(t, meter)
	for _, series := range []string{
		`user="alice@example.com"} 2`,
		`user="chat-panel"} 1`,
	} {
		require.Contains(t, body, series, "no requests_total series ending %s", series)
	}

	for _, id := range []uuid.UUID{sinkUser, sinkToken, service, serviceToken} {
		require.NotContains(t, body, id.String(), "an id reached the metrics")
	}
}

// TestSinkLabelCacheExpires: a label is reused for a minute, then looked up
// again, so a changed email shows up after at most the TTL.
func TestSinkLabelCacheExpires(t *testing.T) {
	events, tokens, users := newLedger(t), mocks.NewTokenRepo(t), mocks.NewUserRepo(t)
	events.accept()
	users.EXPECT().ByID(mock.Anything, sinkUser).Return(identity.User{Email: "alice@example.com"}, nil).Once()
	users.EXPECT().ByID(mock.Anything, sinkUser).Return(identity.User{Email: "alice@new.example.com"}, nil).Once()
	users.EXPECT().TouchLastSeen(mock.Anything, mock.Anything, mock.Anything).Return(nil)
	tokens.EXPECT().TouchLastUsed(mock.Anything, mock.Anything, mock.Anything).Return(nil)

	clock := &manualClock{now: time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)}
	meter := metrics.New(prometheus.NewRegistry())
	sink := New(events, tokens, users, &app.PriceTable{}, meter, clock, discardLog{})
	send := func() {
		sink.HandleUsage(context.Background(), cliproxyusage.Record{Provider: "claude", Model: "m", APIKey: sinkKey})
		flushed(t, sink)
	}

	send()
	clock.advance(labelTTL - time.Second)
	send() // still cached: no lookup
	clock.advance(2 * time.Second)
	send() // expired: looked up again

	body := scrape(t, meter)
	require.Contains(t, body, `user="alice@example.com"} 2`, "want 2 requests under the old email")
	require.Contains(t, body, `user="alice@new.example.com"} 1`, "want 1 request under the new email")
}

// TestSinkDoesNotCacheFailedLookup: a failed lookup labels its record
// "unknown" but is retried on the next record, not pinned for the TTL.
func TestSinkDoesNotCacheFailedLookup(t *testing.T) {
	events, tokens, users := newLedger(t), mocks.NewTokenRepo(t), mocks.NewUserRepo(t)
	events.accept()
	users.EXPECT().ByID(mock.Anything, sinkUser).Return(identity.User{}, errors.New("connection reset")).Once()
	users.EXPECT().ByID(mock.Anything, sinkUser).Return(identity.User{Email: "alice@example.com"}, nil).Once()
	users.EXPECT().TouchLastSeen(mock.Anything, mock.Anything, mock.Anything).Return(nil)
	tokens.EXPECT().TouchLastUsed(mock.Anything, mock.Anything, mock.Anything).Return(nil)

	sink, meter, _ := newMeteredSink(events, tokens, users, discardLog{})
	for range 2 {
		sink.HandleUsage(context.Background(), cliproxyusage.Record{Provider: "claude", Model: "m", APIKey: sinkKey})
		flushed(t, sink)
	}

	body := scrape(t, meter)
	require.Contains(t, body, `user="unknown"} 1`, "want one request as unknown")
	require.Contains(t, body, `user="alice@example.com"} 1`, "want one request as alice")
}

// panickyObserver panics on every record of model "boom".
type panickyObserver struct{}

func (panickyObserver) ObserveUsage(ev app.UsageEvent, _ string) {
	if ev.Model == "boom" {
		panic("observer exploded")
	}
}
func (panickyObserver) ObserveVendorQuota(string, string, string, float64, time.Time) {}
func (panickyObserver) ObserveAccountFailure(string, string)                          {}

// TestSinkSurvivesPanic: a panic while handling one record is recovered,
// counted and logged without the principal; the worker goes on and the next
// record is written.
func TestSinkSurvivesPanic(t *testing.T) {
	events, tokens, users := newLedger(t), mocks.NewTokenRepo(t), mocks.NewUserRepo(t)
	events.accept()
	knownPrincipal(users, tokens)

	log := &recordingLog{}

	sink := New(events, tokens, users, &app.PriceTable{}, panickyObserver{}, wallClock{}, log)
	sink.HandleUsage(context.Background(), cliproxyusage.Record{Provider: "claude", Model: "boom", APIKey: sinkKey})
	flushed(t, sink)
	sink.HandleUsage(context.Background(), cliproxyusage.Record{Provider: "claude", Model: "fine", APIKey: sinkKey})
	flushed(t, sink)

	got := events.written()
	require.NotEmpty(t, got, "ledger")
	require.Equal(t, "fine", got[len(got)-1].Model, "want the record after the panic written")

	require.Equal(t, uint64(1), sink.Panics(), "Panics()")

	logged := log.logged()
	require.Len(t, logged, 1, "warnings")
	require.Contains(t, logged[0], "observer exploded", "want the recovered panic reported")

	for _, secret := range []string{sinkKey, sinkUser.String(), sinkToken.String()} {
		require.NotContains(t, logged[0], secret, "the warning carries the principal")
	}
}

// TestSinkNeverBlocksAndCountsDrops: with the worker stuck on the database,
// HandleUsage still returns at once; what does not fit the queue is dropped
// and counted, and what does fit is written once the database recovers.
func TestSinkNeverBlocksAndCountsDrops(t *testing.T) {
	events, tokens, users := newLedger(t), mocks.NewTokenRepo(t), mocks.NewUserRepo(t)
	release, entered := make(chan struct{}), make(chan struct{}, 1)

	var releaseOnce sync.Once

	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	users.EXPECT().ByID(mock.Anything, sinkUser).RunAndReturn(func(context.Context, uuid.UUID) (identity.User, error) {
		select {
		case entered <- struct{}{}:
		default:
		}

		<-release

		return identity.User{ID: sinkUser, Email: "alice@example.com"}, nil
	})
	events.EXPECT().AppendBatch(mock.Anything, mock.Anything).
		Run(func(_ context.Context, evs []app.UsageEvent) {
			<-release
			events.keep(evs)
		}).Return(nil)
	users.EXPECT().TouchLastSeen(mock.Anything, mock.Anything, mock.Anything).Return(nil)
	tokens.EXPECT().TouchLastUsed(mock.Anything, mock.Anything, mock.Anything).Return(nil)

	sink, _, _ := newMeteredSink(events, tokens, users, discardLog{})
	record := cliproxyusage.Record{Provider: "claude", Model: "m", APIKey: sinkKey}

	returnsWithin(t, time.Second, "the first HandleUsage", func() { sink.HandleUsage(context.Background(), record) })

	select {
	case <-entered: // the worker holds the first record and is stuck
	case <-time.After(5 * time.Second):
		require.Fail(t, "the worker never picked the first record up")
	}

	const overflow = 7

	returnsWithin(t, time.Second, "HandleUsage on a full queue", func() {
		for range usageQueueSize + overflow {
			sink.HandleUsage(context.Background(), record)
		}
	})

	require.Equal(t, uint64(overflow), sink.Dropped(), "Dropped()")

	unblock()
	flushed(t, sink)

	require.Len(t, events.written(), usageQueueSize+1, "want the rows that were queued")
}

// TestSinkDrainStopsIntakeAndHonoursDeadline: on shutdown Drain gives up at
// its deadline even with the database stuck, and from the moment it is called
// new records are dropped and counted, so arrivals cannot keep it busy.
func TestSinkDrainStopsIntakeAndHonoursDeadline(t *testing.T) {
	events, tokens, users := newLedger(t), mocks.NewTokenRepo(t), mocks.NewUserRepo(t)
	knownPrincipal(users, tokens)

	release, entered := make(chan struct{}), make(chan struct{}, 1)

	var releaseOnce sync.Once

	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	events.EXPECT().AppendBatch(mock.Anything, mock.Anything).
		Run(func(_ context.Context, evs []app.UsageEvent) {
			select {
			case entered <- struct{}{}:
			default:
			}

			<-release
			events.keep(evs)
		}).Return(nil)

	sink, _, _ := newMeteredSink(events, tokens, users, discardLog{})
	sink.HandleUsage(context.Background(), cliproxyusage.Record{Provider: "claude", Model: "before", APIKey: sinkKey})

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		require.Fail(t, "the worker never reached the repository")
	}

	var err error

	returnsWithin(t, 2*time.Second, "Drain with a stuck repository and a 100ms deadline", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		err = sink.Drain(ctx)
	})

	require.ErrorIs(t, err, context.DeadlineExceeded, "Drain()")

	sink.HandleUsage(context.Background(), cliproxyusage.Record{Provider: "claude", Model: "after", APIKey: sinkKey})

	require.Equal(t, uint64(1), sink.Dropped(), "want the record handed over after Drain dropped")

	unblock()
	flushed(t, sink)

	got := events.written()
	require.Len(t, got, 1, "want only the record accepted before Drain")
	require.Equal(t, "before", got[0].Model, "want only the record accepted before Drain")
}

// TestSinkStampsLatestCompletionPerID: a batch stamps each token and owner once,
// with the latest time one of its requests completed, whatever the order.
func TestSinkStampsLatestCompletionPerID(t *testing.T) {
	events, tokens, users := newLedger(t), mocks.NewTokenRepo(t), mocks.NewUserRepo(t)
	users.EXPECT().ByID(mock.Anything, sinkUser).Return(identity.User{Email: "alice@example.com"}, nil)

	release, entered := make(chan struct{}), make(chan struct{}, 1)

	var releaseOnce sync.Once

	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	events.EXPECT().AppendBatch(mock.Anything, mock.Anything).
		Run(func(_ context.Context, evs []app.UsageEvent) {
			if evs[0].Model == "blocker" {
				entered <- struct{}{}

				<-release
			}

			events.keep(evs)
		}).Return(nil)

	var mu sync.Mutex

	stamps := map[uuid.UUID][]time.Time{}
	stamp := func(_ context.Context, id uuid.UUID, at time.Time) {
		mu.Lock()

		stamps[id] = append(stamps[id], at)
		mu.Unlock()
	}
	other := app.Principal{UserID: uuid.New(), TokenID: uuid.New()}
	users.EXPECT().ByID(mock.Anything, other.UserID).Return(identity.User{Email: "bob@example.com"}, nil)
	tokens.EXPECT().TouchLastUsed(mock.Anything, mock.Anything, mock.Anything).Run(stamp).Return(nil)
	users.EXPECT().TouchLastSeen(mock.Anything, mock.Anything, mock.Anything).Run(stamp).Return(nil)

	sink, _, _ := newMeteredSink(events, tokens, users, discardLog{})
	// Hold the worker on another principal's batch so the next three queue
	// up and are written as one batch.
	sink.HandleUsage(context.Background(), cliproxyusage.Record{Provider: "claude", Model: "blocker", APIKey: other.String()})

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		require.Fail(t, "the worker never reached the repository")
	}

	start := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	for _, tc := range []struct{ started, took time.Duration }{
		{0, 2 * time.Minute},               // completes 10:02
		{time.Minute, 4 * time.Minute},     // completes 10:05: the latest
		{3 * time.Minute, 0 * time.Minute}, // completes 10:03
	} {
		sink.HandleUsage(context.Background(), cliproxyusage.Record{
			Provider: "claude", Model: "m", APIKey: sinkKey, RequestedAt: start.Add(tc.started), Latency: tc.took,
		})
	}

	unblock()
	flushed(t, sink)

	latest := start.Add(5 * time.Minute)

	mu.Lock()
	defer mu.Unlock()

	for _, id := range []uuid.UUID{sinkToken, sinkUser} {
		got := stamps[id]
		require.Len(t, got, 1, "stamps of %s", id)
		require.True(t, got[0].Equal(latest), "stamp of %s = %v, want %v", id, got[0], latest)
	}
}

// returnsWithin fails the test if fn has not returned after d.
func returnsWithin(t *testing.T, limit time.Duration, what string, fn func()) {
	t.Helper()

	done := make(chan struct{})
	go func() {
		defer close(done)

		fn()
	}()

	select {
	case <-done:
	case <-time.After(limit):
		require.Failf(t, "blocked", "%s blocked for %s", what, limit)
	}
}

// TestSinkSurvivesRepositoryError: a failed batch is logged and lost; the
// worker goes on and writes the next one.
func TestSinkSurvivesRepositoryError(t *testing.T) {
	events, tokens, users := newLedger(t), mocks.NewTokenRepo(t), mocks.NewUserRepo(t)
	knownPrincipal(users, tokens)
	events.EXPECT().AppendBatch(mock.Anything, mock.Anything).Return(errors.New("connection refused")).Once()
	events.accept()

	log := &recordingLog{}

	sink, _, _ := newMeteredSink(events, tokens, users, log)
	sink.HandleUsage(context.Background(), cliproxyusage.Record{Provider: "claude", Model: "lost", APIKey: sinkKey})
	flushed(t, sink)
	sink.HandleUsage(context.Background(), cliproxyusage.Record{Provider: "claude", Model: "kept", APIKey: sinkKey})
	flushed(t, sink)

	got := events.written()
	require.Len(t, got, 1, "want only the batch after the failure")
	require.Equal(t, "kept", got[0].Model, "want only the batch after the failure")

	logged := log.logged()
	require.Len(t, logged, 1, "warnings")
	require.Contains(t, logged[0], "connection refused", "want the failed write reported")
}

// quotaSeries names one vendor quota series.
type quotaSeries struct{ account, provider, window string }

// quotaGauge returns the values of a vendor quota gauge family by series.
func quotaGauge(t *testing.T, reg *prometheus.Registry, family string) map[quotaSeries]float64 {
	t.Helper()

	fams, err := reg.Gather()
	require.NoError(t, err, "gather")

	out := map[quotaSeries]float64{}

	for _, f := range fams {
		if f.GetName() != family {
			continue
		}

		for _, metric := range f.GetMetric() {
			var series quotaSeries

			for _, label := range metric.GetLabel() {
				switch label.GetName() {
				case "account":
					series.account = label.GetValue()
				case "provider":
					series.provider = label.GetValue()
				case "window":
					series.window = label.GetValue()
				}
			}

			out[series] = metric.GetGauge().GetValue()
		}
	}

	return out
}

func quotaSink(t *testing.T) (*Sink, *prometheus.Registry) {
	t.Helper()
	events, tokens, users := newLedger(t), mocks.NewTokenRepo(t), mocks.NewUserRepo(t)
	events.accept()
	knownPrincipal(users, tokens)
	sink, _, reg := newMeteredSink(events, tokens, users, discardLog{})

	return sink, reg
}

func headers(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i < len(kv); i += 2 {
		h.Set(kv[i], kv[i+1])
	}

	return h
}

// TestSinkReadsVendorQuotaHeaders feeds the headers upstream v7.3.15 reads
// (helps/claude_ratelimit.go, helps/codex_quota.go) and checks the gauges and
// the quota store: Anthropic reports ratios, Codex percentages; the Codex
// window comes from its length, so a weekly-only plan's primary window is 7d.
func TestSinkReadsVendorQuotaHeaders(t *testing.T) {
	sink, reg := quotaSink(t)
	at := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)

	const latency = 2 * time.Second

	arrived := at.Add(latency)

	for _, rec := range []cliproxyusage.Record{
		{Provider: "claude", AuthID: "claude-1.json", ResponseHeaders: headers(
			"Anthropic-Ratelimit-Unified-5h-Utilization", "0.42",
			"Anthropic-Ratelimit-Unified-5h-Reset", "1788256800",
			"Anthropic-Ratelimit-Unified-7d-Utilization", "0.9",
			"Anthropic-Ratelimit-Unified-7d-Reset", "2026-09-07T00:00:00Z",
		)},
		{Provider: "codex", AuthID: "codex-1.json", ResponseHeaders: headers(
			"X-Codex-Primary-Used-Percent", "37",
			"X-Codex-Primary-Window-Minutes", "300",
			"X-Codex-Primary-Reset-After-Seconds", "600",
			"X-Codex-Secondary-Used-Percent", "81.5",
			"X-Codex-Secondary-Window-Minutes", "10080",
			"X-Codex-Secondary-Reset-At", "1788800000",
		)},
		{Provider: "codex", AuthID: "codex-weekly.json", ResponseHeaders: headers(
			"X-Codex-Primary-Used-Percent", "48",
			"X-Codex-Primary-Window-Minutes", "10080",
			"X-Codex-Primary-Reset-At", "1788800000",
		)},
	} {
		rec.Model, rec.APIKey, rec.RequestedAt, rec.Latency = "m", sinkKey, at, latency
		sink.HandleUsage(context.Background(), rec)
	}

	flushed(t, sink)

	want := []app.QuotaSignal{
		{Account: "claude-1.json", Provider: "claude", Window: "5h", UsedRatio: 0.42, ResetAt: time.Unix(1788256800, 0).UTC(), ObservedAt: arrived},
		{Account: "claude-1.json", Provider: "claude", Window: "7d", UsedRatio: 0.9, ResetAt: time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC), ObservedAt: arrived},
		{Account: "codex-1.json", Provider: "chatgpt", Window: "5h", UsedRatio: 0.37, ResetAt: arrived.Add(600 * time.Second), ObservedAt: arrived},
		{Account: "codex-1.json", Provider: "chatgpt", Window: "7d", UsedRatio: 0.815, ResetAt: time.Unix(1788800000, 0).UTC(), ObservedAt: arrived},
		{Account: "codex-weekly.json", Provider: "chatgpt", Window: "7d", UsedRatio: 0.48, ResetAt: time.Unix(1788800000, 0).UTC(), ObservedAt: arrived},
	}
	require.Equal(t, want, sink.QuotaSignals(), "QuotaSignals()")

	used := quotaGauge(t, reg, "llmproxy_vendor_quota_used_ratio")

	reset := quotaGauge(t, reg, "llmproxy_vendor_quota_reset_timestamp_seconds")
	require.Len(t, used, len(want), "used ratio series")
	require.Len(t, reset, len(want), "reset series")

	for _, row := range want {
		series := quotaSeries{row.Account, row.Provider, row.Window}
		assert.Equal(t, row.UsedRatio, used[series], "used ratio %v", series)
		assert.Equal(t, float64(row.ResetAt.Unix()), reset[series], "reset %v", series)
	}
}

// TestSinkClampsQuotaRatio: an exhausted window, which vendors report as 1 or
// more, reads 1 in the store and on the gauge.
func TestSinkClampsQuotaRatio(t *testing.T) {
	sink, reg := quotaSink(t)

	for _, r := range []cliproxyusage.Record{
		{Provider: "claude", AuthID: "claude-1.json", ResponseHeaders: headers("Anthropic-Ratelimit-Unified-5h-Utilization", "1.02")},
		{Provider: "codex", AuthID: "codex-1.json", ResponseHeaders: headers("X-Codex-Primary-Used-Percent", "104", "X-Codex-Primary-Window-Minutes", "300")},
	} {
		r.Model, r.APIKey = "m", sinkKey
		sink.HandleUsage(context.Background(), r)
	}

	flushed(t, sink)

	for _, q := range sink.QuotaSignals() {
		assert.Equal(t, 1.0, q.UsedRatio, "%s %s used ratio", q.Account, q.Window)
	}

	want := map[quotaSeries]float64{{"claude-1.json", "claude", "5h"}: 1, {"codex-1.json", "chatgpt", "5h"}: 1}
	require.Equal(t, want, quotaGauge(t, reg, "llmproxy_vendor_quota_used_ratio"), "used ratio series")
}

// TestSinkQuotaSnapshotReplacesWindows: each response carrying quota signals
// replaces its account's snapshot, so a window the vendor stopped reporting
// goes; a reset the new report omits is carried over; a response without
// signals changes nothing; ForgetAccount drops the account.
func TestSinkQuotaSnapshotReplacesWindows(t *testing.T) {
	sink, _ := quotaSink(t)
	at := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	send := func(provider, account string, h http.Header) {
		sink.HandleUsage(context.Background(), cliproxyusage.Record{
			Provider: provider, Model: "m", APIKey: sinkKey, AuthID: account, RequestedAt: at, ResponseHeaders: h,
		})
	}
	send("claude", "claude-1.json", headers("Anthropic-Ratelimit-Unified-5h-Utilization", "0.2"))
	send("codex", "codex-1.json", headers(
		"X-Codex-Primary-Used-Percent", "37", "X-Codex-Primary-Window-Minutes", "300",
		"X-Codex-Secondary-Used-Percent", "50", "X-Codex-Secondary-Window-Minutes", "10080",
		"X-Codex-Secondary-Reset-At", "1788800000",
	))
	// The plan became weekly-only: one window, no reset this time.
	send("codex", "codex-1.json", headers("X-Codex-Primary-Used-Percent", "60", "X-Codex-Primary-Window-Minutes", "10080"))
	send("codex", "codex-1.json", headers("Content-Type", "application/json"))
	flushed(t, sink)

	want := []app.QuotaSignal{
		{Account: "claude-1.json", Provider: "claude", Window: "5h", UsedRatio: 0.2, ObservedAt: at},
		{Account: "codex-1.json", Provider: "chatgpt", Window: "7d", UsedRatio: 0.6, ResetAt: time.Unix(1788800000, 0).UTC(), ObservedAt: at},
	}
	require.Equal(t, want, sink.QuotaSignals(), "QuotaSignals()")

	sink.ForgetAccount("codex-1.json")

	require.Equal(t, want[:1], sink.QuotaSignals(), "after ForgetAccount, QuotaSignals()")
}

// TestSinkIgnoresMalformedQuotaHeaders: a header that does not parse leaves
// what was known alone — never a 0 in its place, never a panic.
func TestSinkIgnoresMalformedQuotaHeaders(t *testing.T) {
	sink, reg := quotaSink(t)
	send := func(provider, account string, h http.Header) {
		sink.HandleUsage(context.Background(), cliproxyusage.Record{
			Provider: provider, Model: "m", APIKey: sinkKey, AuthID: account, ResponseHeaders: h,
		})
	}
	send("claude", "claude-1.json", headers("Anthropic-Ratelimit-Unified-5h-Utilization", "0.42"))
	send("claude", "claude-1.json", headers(
		"Anthropic-Ratelimit-Unified-5h-Utilization", "forty-two",
		"Anthropic-Ratelimit-Unified-7d-Utilization", "NaN",
	))
	send("claude", "claude-2.json", headers(
		"Anthropic-Ratelimit-Unified-5h-Utilization", "",
		"Anthropic-Ratelimit-Unified-7d-Utilization", "-0.1",
	))
	send("codex", "codex-1.json", headers(
		"X-Codex-Primary-Used-Percent", "Inf",
		"X-Codex-Secondary-Used-Percent", "50",
		"X-Codex-Secondary-Window-Minutes", "a week",
		"X-Codex-Secondary-Reset-At", "soon",
		"X-Codex-Secondary-Reset-After-Seconds", "-5",
	))
	// Quota headers on a record with no account describe nobody.
	send("claude", "", headers("Anthropic-Ratelimit-Unified-5h-Utilization", "0.99"))
	flushed(t, sink)

	want := map[quotaSeries]float64{
		{"claude-1.json", "claude", "5h"}: 0.42,
		// Window-Minutes unreadable: the secondary window falls back to 7d.
		{"codex-1.json", "chatgpt", "7d"}: 0.5,
	}
	require.Equal(t, want, quotaGauge(t, reg, "llmproxy_vendor_quota_used_ratio"), "used ratio series")

	require.Empty(t, quotaGauge(t, reg, "llmproxy_vendor_quota_reset_timestamp_seconds"), "reset series: no reset header parsed")

	got := sink.QuotaSignals()
	require.Len(t, got, 2, "want the two readable signals")
	require.Equal(t, 0.42, got[0].UsedRatio, "first signal's ratio")
	require.True(t, got[0].ResetAt.IsZero(), "first signal's reset = %v, want none", got[0].ResetAt)
	require.True(t, got[1].ResetAt.IsZero(), "second signal's reset = %v, want none", got[1].ResetAt)
}

func scrape(t *testing.T, m *metrics.Metrics) string {
	t.Helper()

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", http.NoBody))

	b, err := io.ReadAll(rec.Body)
	require.NoError(t, err, "read the exposition")

	return string(b)
}
