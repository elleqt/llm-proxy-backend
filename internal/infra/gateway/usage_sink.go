package gateway

import (
	"context"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	cliproxyusage "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"

	"github.com/elleqt/llm-proxy-backend/internal/app"
)

// UsageObserver is what the sink reports to besides the ledger: the metric
// families of internal/infra/metrics. *metrics.Metrics implements it.
type UsageObserver interface {
	// ObserveUsage records one request. user is the owner's human-readable
	// label, never an id.
	ObserveUsage(ev app.UsageEvent, user string)
	// ObserveVendorQuota records a vendor's report of quota use; ratio is 0..1.
	ObserveVendorQuota(account, provider, window string, ratio float64, resetAt time.Time)
	// ObserveAccountFailure counts a failed request served by a vendor account.
	ObserveAccountFailure(account, provider string)
}

const (
	// usageQueueSize bounds the records waiting for the worker. A full queue
	// drops the record rather than stall upstream's usage dispatcher, which
	// delivers to every plugin from one goroutine.
	usageQueueSize = 4096
	// usageBatchMax bounds the events written in one round trip.
	usageBatchMax = 256
	// usageWriteTimeout bounds one batch write, and usageLookupTimeout one
	// label lookup, so a stalled database cannot wedge the worker for good.
	usageWriteTimeout  = 10 * time.Second
	usageLookupTimeout = 2 * time.Second
	// labelTTL is how long a resolved user label is reused: a user whose email
	// changed shows the old label for up to this long.
	labelTTL = time.Minute
	// labelCacheMax bounds the label cache; a full cache is emptied.
	labelCacheMax = 10_000
	// unknownLabel labels a request whose owner cannot be resolved.
	unknownLabel = "unknown"
)

// UsageSink turns upstream usage records into ledger rows, metrics and vendor
// quota signals. It implements upstream's usage.Plugin. Each row is priced as it
// is mapped, at the price in force then (app.PriceUsage), and the metrics count
// that same cost, so the ledger and the metrics never price a request apart.
//
// HandleUsage only enqueues: every lookup, write and metric happens on the
// sink's worker goroutine, with a context of its own rather than the request's.
// A panic there is recovered per record (or per batch write), logged and
// counted (Panics); upstream's own recover around plugins does not reach this
// goroutine.
//
// Every provider the sink records — ledger rows, metric labels, quota signals —
// is the policy-facing name (policyProvider), never the upstream key.
type UsageSink struct {
	events   app.UsageRepo
	tokens   app.TokenRepo
	users    app.UserRepo
	prices   app.PriceLookup
	observer UsageObserver
	clock    app.Clock
	log      app.Logger

	queue   chan cliproxyusage.Record
	flush   chan chan struct{}
	closed  atomic.Bool
	dropped atomic.Uint64
	panics  atomic.Uint64

	// Owned by the worker goroutine.
	userLabels labelCache

	quotaMu sync.Mutex
	// quota holds each account's latest snapshot: window -> signal.
	quota map[string]map[string]app.QuotaSignal
}

var (
	_ cliproxyusage.Plugin = (*UsageSink)(nil)
	_ app.QuotaReader      = (*UsageSink)(nil)
)

// NewUsageSink starts the sink's worker; it runs for the life of the process.
// prices must answer from memory: it is read for every record.
func NewUsageSink(events app.UsageRepo, tokens app.TokenRepo, users app.UserRepo, prices app.PriceLookup,
	observer UsageObserver, clock app.Clock, log app.Logger) *UsageSink {
	s := &UsageSink{
		events:     events,
		tokens:     tokens,
		users:      users,
		prices:     prices,
		observer:   observer,
		clock:      clock,
		log:        log,
		queue:      make(chan cliproxyusage.Record, usageQueueSize),
		flush:      make(chan chan struct{}),
		userLabels: labelCache{},
		quota:      map[string]map[string]app.QuotaSignal{},
	}
	go s.run()
	return s
}

// HandleUsage enqueues record and returns at once. When the queue is full, or
// Drain has been called, the record is dropped and counted (Dropped): the
// ledger may lose a row under overload, the proxy never waits for it.
func (s *UsageSink) HandleUsage(_ context.Context, record cliproxyusage.Record) {
	if s.closed.Load() {
		s.dropped.Add(1)
		return
	}
	select {
	case s.queue <- record:
	default:
		s.dropped.Add(1)
	}
}

// Dropped is how many records HandleUsage has dropped: on a full queue, or
// after Drain.
func (s *UsageSink) Dropped() uint64 { return s.dropped.Load() }

// Panics is how many panics the worker has recovered from.
func (s *UsageSink) Panics() uint64 { return s.panics.Load() }

// Drain is for shutdown. It stops accepting records — HandleUsage drops and
// counts them from then on — and returns once every record accepted before
// has been processed: written (or failed and logged), observed and touched.
// If ctx ends first it returns ctx.Err(); the worker finishes on its own.
func (s *UsageSink) Drain(ctx context.Context) error {
	s.closed.Store(true)
	return s.sync(ctx)
}

// sync returns once every record enqueued before the call has been processed,
// or ctx.Err(). It does not stop intake: the worker processes only as many
// records as were queued when it took the request, so arrivals cannot keep it
// from answering.
func (s *UsageSink) sync(ctx context.Context) error {
	done := make(chan struct{})
	select {
	case s.flush <- done:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *UsageSink) run() {
	batch := make([]cliproxyusage.Record, 0, usageBatchMax)
	for {
		select {
		case r := <-s.queue:
			batch = s.fill(append(batch, r), usageBatchMax-1)
			s.process(batch)
			batch = batch[:0]
		case done := <-s.flush:
			// Only this goroutine receives, so at least n records are queued.
			for n := len(s.queue); n > 0; n -= len(batch) {
				batch = s.take(batch[:0], min(n, usageBatchMax))
				s.process(batch)
			}
			batch = batch[:0]
			close(done)
		}
	}
}

// fill tops batch up with at most n more queued records, without waiting.
func (s *UsageSink) fill(batch []cliproxyusage.Record, n int) []cliproxyusage.Record {
	for ; n > 0; n-- {
		select {
		case r := <-s.queue:
			batch = append(batch, r)
		default:
			return batch
		}
	}
	return batch
}

// take appends exactly n queued records to batch.
func (s *UsageSink) take(batch []cliproxyusage.Record, n int) []cliproxyusage.Record {
	for ; n > 0; n-- {
		batch = append(batch, <-s.queue)
	}
	return batch
}

// process handles one batch: map and observe every record, write the ledger
// rows, then stamp the tokens and owners the batch used.
func (s *UsageSink) process(records []cliproxyusage.Record) {
	events := make([]app.UsageEvent, 0, len(records))
	for _, r := range records {
		s.guard(func(p any) {
			s.log.Warnf("usage: recovered a panic handling a %s/%s record: %v", policyProvider(r.Provider), r.Model, p)
		}, func() {
			ev := s.eventOf(r)
			events = append(events, ev)
			s.observe(r, ev)
		})
	}
	s.guard(func(p any) {
		s.log.Warnf("usage: recovered a panic writing %d ledger rows: %v", len(events), p)
	}, func() {
		ctx, cancel := context.WithTimeout(context.Background(), usageWriteTimeout)
		defer cancel()
		if err := s.events.AppendBatch(ctx, events); err != nil {
			s.log.Warnf("usage: %d ledger rows lost: %v", len(events), err)
		}
		s.touch(ctx, events)
	})
}

// guard runs fn, and on a panic counts it and hands the value to report.
func (s *UsageSink) guard(report func(any), fn func()) {
	defer func() {
		if p := recover(); p != nil {
			s.panics.Add(1)
			report(p)
		}
	}()
	fn()
}

// observe feeds the metrics and the quota store from one record.
func (s *UsageSink) observe(r cliproxyusage.Record, ev app.UsageEvent) {
	s.observer.ObserveUsage(ev, s.userLabel(ev.UserID))
	if r.AuthID == "" {
		return
	}
	if r.Failed {
		s.observer.ObserveAccountFailure(r.AuthID, ev.Provider)
	}
	s.observeQuota(r, ev.Provider, completedAt(ev))
}

// completedAt is when the response of ev finished arriving.
func completedAt(ev app.UsageEvent) time.Time {
	return ev.At.Add(time.Duration(ev.LatencyMS) * time.Millisecond)
}

// eventOf maps a record onto a ledger row. Record.APIKey carries the principal
// (app.Principal.String); a record without one is kept unattributed.
func (s *UsageSink) eventOf(r cliproxyusage.Record) app.UsageEvent {
	ev := app.UsageEvent{
		At:              r.RequestedAt,
		Provider:        policyProvider(r.Provider),
		Model:           r.Model,
		Alias:           r.Alias,
		Stream:          r.Stream,
		ServiceTier:     r.ResponseServiceTier,
		LatencyMS:       int(r.Latency.Milliseconds()),
		TTFTMS:          int(r.TTFT.Milliseconds()),
		Failed:          r.Failed,
		StatusCode:      r.Fail.StatusCode,
		VendorAccountID: r.AuthID,
	}
	if ev.At.IsZero() {
		ev.At = s.clock.Now().Add(-r.Latency)
	}
	// The tier the vendor served, not the one the client asked for.
	if ev.ServiceTier == "" {
		ev.ServiceTier = r.ServiceTier
	}
	if p, err := app.ParsePrincipal(r.APIKey); err == nil {
		ev.UserID, ev.TokenID = p.UserID, p.TokenID
	} else {
		// The value is not logged: it may be a credential upstream recorded.
		s.log.Warnf("usage: %s/%s record carries no principal; stored unattributed", ev.Provider, r.Model)
	}

	// Upstream's canonical breakdown partitions the total without double
	// counting cache or reasoning tokens; the raw detail is the fallback.
	if b := r.Detail.TokenBreakdown; b.Valid() {
		ev.TokensInput = b.Input.UncachedTokens
		ev.TokensCacheRead = b.Input.CacheReadTokens
		ev.TokensCacheWrite = b.Input.CacheWriteTokens
		ev.TokensOutput = b.Output.NonReasoningTokens
		ev.TokensReasoning = b.Output.ReasoningTokens
		ev.TokensTotal = b.TotalTokens
		ev.BreakdownQuality = string(b.Quality)
	} else {
		partitionDetail(&ev, r.Provider, r.Detail)
	}
	price, ok := s.prices.Price(ev.Provider, ev.Model)
	ev.Cost = app.PriceUsage(ev, price, ok)
	return ev
}

// BreakdownQuality of a row whose token kinds the sink derived from the raw
// detail, upstream having sent no valid breakdown: reconstructed when the kinds
// partition the request, else unclassified (a protocol not recognised) or
// inconsistent (counts that contradict each other), with every token unpriced.
const (
	qualityReconstructed = "reconstructed"
	qualityUnclassified  = "unclassified"
	qualityInconsistent  = "inconsistent"
)

// partitionDetail maps a raw usage detail onto ev's token kinds, which partition
// the request, by how the upstream provider key's protocol reports usage (as
// upstream's own accounting.go tokenAccountingSemanticsFor tells them apart):
//
//   - OpenAI-style (codex, OpenAI-compatible and the like): the prompt count
//     includes the cached and cache-written tokens, and the completion count
//     the reasoning tokens, so both are taken out.
//   - Gemini-style: the prompt count includes the cache; reasoning is separate.
//   - Anthropic: the cache counts are separate from the input; the output count
//     includes thinking, so reasoning is taken out.
//
// Where upstream would not guess, neither does the sink: a protocol it does not
// recognise, a cache larger than the prompt that includes it, reasoning larger
// than the output that includes it, or kinds adding up to more than a reported
// total leave every token unclassified, so none is priced. A zero reported total
// is taken from the kinds.
func partitionDetail(ev *app.UsageEvent, providerKey string, d cliproxyusage.Detail) {
	in, out, reasoning := max(d.InputTokens, 0), max(d.OutputTokens, 0), max(d.ReasoningTokens, 0)
	cacheRead, cacheWrite := max(d.CacheReadTokens, 0), max(d.CacheCreationTokens, 0)
	// A legacy cached count stands for the cache reads only when neither cache
	// count is set: upstream copies cache creation into it when there are no reads.
	if cacheRead == 0 && cacheWrite == 0 {
		cacheRead = max(d.CachedTokens, 0)
	}
	total := max(d.TotalTokens, 0)

	quality := qualityReconstructed
	cacheInInput, reasoningInOutput, known := detailSemantics(providerKey)
	switch {
	case !known:
		quality = qualityUnclassified
	case cacheInInput && cacheRead+cacheWrite > in, reasoningInOutput && reasoning > out:
		quality = qualityInconsistent
	default:
		if cacheInInput {
			in -= cacheRead + cacheWrite
		}
		if reasoningInOutput {
			out -= reasoning
		}
		if classified := in + out + reasoning + cacheRead + cacheWrite; total == 0 {
			total = classified
		} else if classified > total {
			quality = qualityInconsistent
		}
	}
	ev.BreakdownQuality = quality
	if quality != qualityReconstructed {
		// Every token unclassified: the total, or the least the counts imply.
		if total == 0 {
			total = max(in, cacheRead+cacheWrite, max(d.CachedTokens, 0)) + max(out, reasoning)
		}
		ev.TokensTotal = total
		return
	}
	ev.TokensInput, ev.TokensOutput, ev.TokensReasoning = in, out, reasoning
	ev.TokensCacheRead, ev.TokensCacheWrite = cacheRead, cacheWrite
	ev.TokensTotal = total
}

// detailSemantics says whether an upstream provider key's raw usage counts cache
// tokens inside the prompt count and reasoning inside the completion count; known
// is false for a protocol it does not recognise.
func detailSemantics(providerKey string) (cacheInInput, reasoningInOutput, known bool) {
	key := strings.ToLower(strings.TrimSpace(providerKey))
	if key == "openai-compatibility" || strings.HasPrefix(key, openAICompatiblePrefix) {
		return true, true, true
	}
	if strings.Contains(key, "claude") || strings.Contains(key, "anthropic") {
		return false, true, true
	}
	for _, marker := range [...]string{"gemini", "aistudio", "antigravity", "vertex", "interaction"} {
		if strings.Contains(key, marker) {
			return true, false, true
		}
	}
	for _, marker := range [...]string{"openai", "codex", "xai", "grok", "kimi", "qwen", "deepseek", "openrouter"} {
		if strings.Contains(key, marker) {
			return true, true, true
		}
	}
	return false, false, false
}

// touch stamps each token and owner in events once, with the latest time one
// of its requests completed. Records arrive in completion order, and the
// repositories never move a stamp backwards.
func (s *UsageSink) touch(ctx context.Context, events []app.UsageEvent) {
	tokens, users := map[uuid.UUID]time.Time{}, map[uuid.UUID]time.Time{}
	for _, ev := range events {
		at := completedAt(ev)
		if ev.TokenID != uuid.Nil && at.After(tokens[ev.TokenID]) {
			tokens[ev.TokenID] = at
		}
		if ev.UserID != uuid.Nil && at.After(users[ev.UserID]) {
			users[ev.UserID] = at
		}
	}
	for id, at := range tokens {
		if err := s.tokens.TouchLastUsed(ctx, id, at); err != nil {
			s.log.Warnf("usage: stamp token last use: %v", err)
		}
	}
	for id, at := range users {
		if err := s.users.TouchLastSeen(ctx, id, at); err != nil {
			s.log.Warnf("usage: stamp user last seen: %v", err)
		}
	}
}

// userLabel is the owner's label (identity.User.Label).
func (s *UsageSink) userLabel(id uuid.UUID) string {
	return s.userLabels.get(s.clock.Now(), id, func(ctx context.Context) (string, error) {
		u, err := s.users.ByID(ctx, id)
		return u.Label(), err
	})
}

// labelCache remembers resolved labels for labelTTL. A failed lookup is not
// remembered, so a database hiccup does not pin "unknown" for a minute.
type labelCache map[uuid.UUID]cachedLabel

type cachedLabel struct {
	label   string
	expires time.Time
}

func (c labelCache) get(now time.Time, id uuid.UUID, lookup func(context.Context) (string, error)) string {
	if id == uuid.Nil {
		return unknownLabel
	}
	if l, ok := c[id]; ok && now.Before(l.expires) {
		return l.label
	}
	ctx, cancel := context.WithTimeout(context.Background(), usageLookupTimeout)
	defer cancel()
	label, err := lookup(ctx)
	if err != nil {
		return unknownLabel
	}
	if label == "" {
		label = unknownLabel
	}
	if len(c) >= labelCacheMax {
		clear(c)
	}
	c[id] = cachedLabel{label: label, expires: now.Add(labelTTL)}
	return label
}

// QuotaSignals returns every account's latest snapshot, ordered by account and
// window.
func (s *UsageSink) QuotaSignals() []app.QuotaSignal {
	s.quotaMu.Lock()
	var out []app.QuotaSignal
	for _, windows := range s.quota {
		for _, q := range windows {
			out = append(out, q)
		}
	}
	s.quotaMu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Account != out[j].Account {
			return out[i].Account < out[j].Account
		}
		return out[i].Window < out[j].Window
	})
	return out
}

// ForgetAccount drops a removed account's quota snapshot; call it with
// metrics.ForgetAccount. A record of the account still queued brings it back.
func (s *UsageSink) ForgetAccount(account string) {
	s.quotaMu.Lock()
	delete(s.quota, account)
	s.quotaMu.Unlock()
}

// observeQuota reads the vendor's quota headers off r, whose response arrived
// at observedAt, into the metrics and the quota store, under the policy-facing
// provider name. The headers are chosen by r's upstream provider key. A header
// that does not parse is ignored. Names and formats as upstream v7.3.12 reads
// them:
//
//   - claude: Anthropic-Ratelimit-Unified-{5h,7d}-Utilization, a ratio, and
//     -Reset, epoch seconds (internal/runtime/executor/helps/claude_ratelimit.go
//     parseUnixOrTimestamp, which also accepts RFC 3339).
//   - codex: X-Codex-{Primary,Secondary}-Used-Percent, a percentage;
//     -Window-Minutes; -Reset-At, epoch seconds, or -Reset-After-Seconds,
//     seconds from the response (helps/codex_quota.go). The window comes from
//     Window-Minutes: primary is 5 h on plans with a 5-hour limit and 7 d on
//     weekly-only ones, so the primary/secondary position does not name it.
//
// Like upstream's own snapshot (sdk/cliproxy/auth/quota_signals.go), a
// response carrying any signal replaces the account's whole snapshot, so a
// window the vendor stopped reporting disappears; one carrying none leaves it.
func (s *UsageSink) observeQuota(r cliproxyusage.Record, provider string, observedAt time.Time) {
	h := r.ResponseHeaders
	if h == nil {
		return
	}
	var snapshot []app.QuotaSignal
	add := func(window string, ratio float64, reset time.Time) {
		snapshot = append(snapshot, app.QuotaSignal{
			Account: r.AuthID, Provider: provider, Window: window,
			UsedRatio: ratio, ResetAt: reset, ObservedAt: observedAt,
		})
	}
	switch r.Provider {
	case "claude":
		for _, w := range [...]string{"5h", "7d"} {
			prefix := "Anthropic-Ratelimit-Unified-" + w + "-"
			ratio, ok := parseShare(h.Get(prefix+"Utilization"), 1)
			if !ok {
				continue
			}
			reset, _ := parseEpochOrRFC3339(h.Get(prefix + "Reset"))
			add(w, ratio, reset)
		}
	case "codex":
		for _, pos := range [...]struct{ name, fallback string }{{"Primary", "5h"}, {"Secondary", "7d"}} {
			prefix := "X-Codex-" + pos.name + "-"
			ratio, ok := parseShare(h.Get(prefix+"Used-Percent"), 100)
			if !ok {
				continue
			}
			window := windowOf(h.Get(prefix+"Window-Minutes"), pos.fallback)
			reset, ok := parseEpochOrRFC3339(h.Get(prefix + "Reset-At"))
			if !ok {
				reset = afterSeconds(h.Get(prefix+"Reset-After-Seconds"), observedAt)
			}
			add(window, ratio, reset)
		}
	}
	if len(snapshot) == 0 {
		return
	}
	for _, q := range snapshot {
		s.observer.ObserveVendorQuota(q.Account, q.Provider, q.Window, q.UsedRatio, q.ResetAt)
	}

	s.quotaMu.Lock()
	defer s.quotaMu.Unlock()
	previous := s.quota[r.AuthID]
	windows := make(map[string]app.QuotaSignal, len(snapshot))
	for _, q := range snapshot {
		// Like the reset gauge, a report without a reset keeps the last one known.
		if q.ResetAt.IsZero() {
			q.ResetAt = previous[q.Window].ResetAt
		}
		windows[q.Window] = q
	}
	s.quota[r.AuthID] = windows
}

// parseShare reads a non-negative finite number, divides it by scale and caps
// the result at 1: a vendor reports an exhausted window as 1 or more.
func parseShare(raw string, scale float64) (float64, bool) {
	v, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
		return 0, false
	}
	return min(v/scale, 1), true
}

// parseEpochOrRFC3339 reads a positive epoch-seconds value or an RFC 3339 time.
func parseEpochOrRFC3339(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	if sec, err := strconv.ParseInt(raw, 10, 64); err == nil {
		if sec <= 0 {
			return time.Time{}, false
		}
		return time.Unix(sec, 0).UTC(), true
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t.UTC(), true
	}
	return time.Time{}, false
}

// afterSeconds is from plus a non-negative whole number of seconds, or zero.
func afterSeconds(raw string, from time.Time) time.Time {
	sec, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || sec < 0 {
		return time.Time{}
	}
	return from.Add(time.Duration(sec) * time.Second).UTC()
}

// windowOf names a Codex window from its length in minutes: whole days as
// "<n>d", whole hours as "<n>h", else "<n>m"; fallback when absent or invalid.
func windowOf(raw, fallback string) string {
	m, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	switch {
	case err != nil || m <= 0:
		return fallback
	case m%(24*60) == 0:
		return strconv.FormatInt(m/(24*60), 10) + "d"
	case m%60 == 0:
		return strconv.FormatInt(m/60, 10) + "h"
	default:
		return strconv.FormatInt(m, 10) + "m"
	}
}
