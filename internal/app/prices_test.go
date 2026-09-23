package app_test

import (
	"context"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/app/mocks"
)

// pricesFixture is a Prices whose stores are mocks backed by the fields below, so a
// test reads what was stored, what the sink holds and what was reported.
type pricesFixture struct {
	repo    *mocks.PriceRepo
	catalog *mocks.PriceCatalogRepo
	source  *mocks.PriceCatalogSource
	sink    *mocks.PriceSink
	metrics *mocks.PriceCatalogMetrics
	audit   *mocks.AuditSink
	svc     *app.Prices

	mu            sync.Mutex
	storedCatalog []app.ModelPrice
	state         app.CatalogState
	sunk          [][]app.ModelPrice
	models        int
	checkedAt     time.Time
	failures      int
	events        []app.AuditEvent
}

// newPricesFixture builds the service with a catalog source unless disabled. The
// manual store is left to each test; the catalog store starts as given.
func newPricesFixture(t *testing.T, disabled bool, catalog []app.ModelPrice, state app.CatalogState) *pricesFixture {
	t.Helper()
	f := &pricesFixture{
		repo: mocks.NewPriceRepo(t), catalog: mocks.NewPriceCatalogRepo(t), source: mocks.NewPriceCatalogSource(t),
		sink: mocks.NewPriceSink(t), metrics: mocks.NewPriceCatalogMetrics(t), audit: mocks.NewAuditSink(t),
		storedCatalog: catalog, state: state,
	}
	f.catalog.EXPECT().List(mock.Anything).RunAndReturn(func(context.Context) ([]app.ModelPrice, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.storedCatalog, nil
	}).Maybe()
	f.catalog.EXPECT().State(mock.Anything).RunAndReturn(func(context.Context) (app.CatalogState, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.state, nil
	}).Maybe()
	f.catalog.EXPECT().Replace(mock.Anything, mock.Anything, mock.Anything, mock.Anything).RunAndReturn(
		func(_ context.Context, prices []app.ModelPrice, s app.CatalogState, at time.Time) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.storedCatalog = make([]app.ModelPrice, len(prices))
			for i, p := range prices {
				p.UpdatedAt = at
				f.storedCatalog[i] = p
			}
			f.state = s
			return nil
		}).Maybe()
	f.catalog.EXPECT().SetState(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, s app.CatalogState) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.state = s
		return nil
	}).Maybe()
	f.sink.EXPECT().SetPrices(mock.Anything).Run(func(p []app.ModelPrice) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.sunk = append(f.sunk, p)
	}).Maybe()
	f.metrics.EXPECT().SetPriceCatalog(mock.Anything, mock.Anything).Run(func(n int, at time.Time) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.models, f.checkedAt = n, at
	}).Maybe()
	f.metrics.EXPECT().ObservePriceCatalogFailure().Run(func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.failures++
	}).Maybe()
	f.audit.EXPECT().Record(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, e app.AuditEvent) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.events = append(f.events, e)
		return nil
	}).Maybe()

	var source app.PriceCatalogSource = f.source
	if disabled {
		source = nil
	}
	f.svc = app.NewPrices(f.repo, f.catalog, source, f.sink, f.metrics, f.audit, fixedClock{now: settingsNow}, discardLogger{})
	return f
}

// load runs Load with manual as the stored overrides.
func (f *pricesFixture) load(t *testing.T, manual ...app.ModelPrice) {
	t.Helper()
	f.repo.EXPECT().List(mock.Anything).Return(manual, nil).Once()
	if err := f.svc.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}
}

// priced is the sink's latest list as provider/model -> input rate.
func (f *pricesFixture) priced(t *testing.T) map[string]float64 {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sunk) == 0 {
		t.Fatal("the sink was never given a list")
	}
	out := map[string]float64{}
	for _, p := range f.sunk[len(f.sunk)-1] {
		out[p.Provider+"/"+p.Model] = p.Input
	}
	return out
}

func (f *pricesFixture) get(t *testing.T) app.PriceList {
	t.Helper()
	list, err := f.svc.Get(context.Background(), newAdmin())
	if err != nil {
		t.Errorf("Get: %v", err)
	}
	return list
}

func sonnet() app.ModelPrice {
	return app.ModelPrice{Provider: "claude", Model: "claude-sonnet-5", Input: 3, Output: 15, CacheRead: 0.3, CacheWrite: 3.75}
}

func gpt() app.ModelPrice {
	return app.ModelPrice{Provider: "chatgpt", Model: "gpt-6", Input: 1.25, Output: 10}
}

var earlier = settingsNow.Add(-6 * time.Hour)

func TestPricesReplaceRefusesInvalidLists(t *testing.T) {
	with := func(edit func(*app.ModelPrice)) []app.ModelPrice {
		p := sonnet()
		edit(&p)
		return []app.ModelPrice{sonnet(), p}
	}
	for name, c := range map[string]struct {
		list  []app.ModelPrice
		field string
	}{
		"negative input":       {with(func(p *app.ModelPrice) { p.Model, p.Input = "m2", -0.01 }), "[1].input"},
		"NaN output":           {with(func(p *app.ModelPrice) { p.Model, p.Output = "m2", math.NaN() }), "[1].output"},
		"infinite cache read":  {with(func(p *app.ModelPrice) { p.Model, p.CacheRead = "m2", math.Inf(1) }), "[1].cacheRead"},
		"negative cache write": {with(func(p *app.ModelPrice) { p.Model, p.CacheWrite = "m2", -1 }), "[1].cacheWrite"},
		"blank provider":       {with(func(p *app.ModelPrice) { p.Provider = " " }), "[1].provider"},
		"blank model":          {with(func(p *app.ModelPrice) { p.Model = "" }), "[1].model"},
		"duplicate model":      {with(func(p *app.ModelPrice) { p.Input = 1 }), "[1]"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newPricesFixture(t, false, nil, app.CatalogState{})
			// No manual store expectation: nothing may be written.
			_, err := f.svc.Replace(context.Background(), newAdmin(), c.list)
			var ie *app.InvalidInputError
			if !errors.As(err, &ie) || ie.Field != c.field {
				t.Fatalf("err = %v, want InvalidInputError{%q}", err, c.field)
			}
		})
	}
}

// A manual price wins over the catalog's for its model and shows what removing it
// restores; the catalog prices the rest; an override the catalog lacks stands
// alone. Omitting an override from the next list restores the catalog's price and
// drops a model only the override priced.
func TestManualPricesOverrideTheCatalogUntilOmitted(t *testing.T) {
	catalogSonnet := sonnet()
	catalogSonnet.UpdatedAt = earlier
	catalogGPT := gpt()
	catalogGPT.UpdatedAt = earlier
	f := newPricesFixture(t, false, []app.ModelPrice{catalogSonnet, catalogGPT}, app.CatalogState{CheckedAt: earlier})

	override := sonnet()
	override.Input = 2
	custom := app.ModelPrice{Provider: "claude", Model: "claude-private", Input: 7}
	f.load(t, override, custom)

	if got := f.priced(t); got["claude/claude-sonnet-5"] != 2 || got["chatgpt/gpt-6"] != 1.25 || got["claude/claude-private"] != 7 || len(got) != 3 {
		t.Fatalf("sink = %v, want the override for sonnet, the catalog for gpt-6, the private model", got)
	}
	list := f.get(t)
	if len(list.Prices) != 3 {
		t.Fatalf("Get = %+v, want 3 entries", list.Prices)
	}
	byModel := map[string]app.PriceEntry{}
	for _, e := range list.Prices {
		byModel[e.Model] = e
	}
	if e := byModel["claude-sonnet-5"]; e.Source != app.PriceSourceManual || e.Input != 2 || e.Catalog == nil || e.Catalog.Input != 3 {
		t.Fatalf("sonnet = %+v, want manual at 2 with the catalog's 3 behind it", e)
	}
	if e := byModel["gpt-6"]; e.Source != app.PriceSourceCatalog || e.Catalog != nil || !e.UpdatedAt.Equal(earlier) {
		t.Fatalf("gpt-6 = %+v, want the catalog's row", e)
	}
	if e := byModel["claude-private"]; e.Source != app.PriceSourceManual || e.Catalog != nil {
		t.Fatalf("private = %+v, want manual with no catalog rates", e)
	}
	if list.Catalog.Models != 2 || !list.Catalog.Enabled {
		t.Fatalf("catalog status = %+v, want enabled with 2 models", list.Catalog)
	}

	f.repo.EXPECT().Replace(mock.Anything, []app.ModelPrice{}, settingsNow).Return(nil).Once()
	f.repo.EXPECT().List(mock.Anything).Return(nil, nil).Once()
	got, err := f.svc.Replace(context.Background(), newAdmin(), []app.ModelPrice{})
	if err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if len(got.Prices) != 2 || got.Prices[0].Source != app.PriceSourceCatalog || got.Prices[1].Source != app.PriceSourceCatalog {
		t.Fatalf("after omitting the overrides = %+v, want the catalog's two rows", got.Prices)
	}
	if priced := f.priced(t); priced["claude/claude-sonnet-5"] != 3 || len(priced) != 2 {
		t.Fatalf("sink = %v, want sonnet back at the catalog's 3 and the private model gone", priced)
	}
	if len(f.events) != 1 || f.events[0].Action != "prices.replace" {
		t.Fatalf("audit = %+v, want one prices.replace", f.events)
	}
}

func TestPricesReplaceStoreFailureLeavesTheSinkAlone(t *testing.T) {
	f := newPricesFixture(t, false, nil, app.CatalogState{})
	f.load(t, sonnet())
	f.repo.EXPECT().Replace(mock.Anything, mock.Anything, mock.Anything).Return(errors.New("db down"))

	if _, err := f.svc.Replace(context.Background(), newAdmin(), []app.ModelPrice{gpt()}); err == nil {
		t.Fatal("Replace succeeded with the store failing")
	}
	if got := f.priced(t); len(f.sunk) != 1 || got["claude/claude-sonnet-5"] != 3 {
		t.Fatalf("sink = %v after %d lists, want the stored list alone", got, len(f.sunk))
	}
}

// A check that finds a new catalog stores it with its validators, prices it and
// reports it; the refresh is audited.
func TestRefreshAppliesAChangedCatalog(t *testing.T) {
	f := newPricesFixture(t, false, nil, app.CatalogState{})
	f.load(t)
	v := app.CatalogValidators{ETag: `"v1"`, LastModified: "Tue, 22 Sep 2026 10:00:00 GMT"}
	f.source.EXPECT().Fetch(mock.Anything, app.CatalogValidators{}).
		Return(app.CatalogFetch{Prices: []app.ModelPrice{sonnet(), gpt()}, Validators: v}, nil).Once()

	list, err := f.svc.Refresh(context.Background(), newAdmin())
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if got := f.priced(t); got["claude/claude-sonnet-5"] != 3 || got["chatgpt/gpt-6"] != 1.25 {
		t.Fatalf("sink = %v, want the catalog's prices", got)
	}
	if f.state.Validators != v || !f.state.CheckedAt.Equal(settingsNow) || !f.state.ChangedAt.Equal(settingsNow) {
		t.Fatalf("stored state = %+v, want the validators, checked and changed now", f.state)
	}
	if c := list.Catalog; c.Models != 2 || !c.CheckedAt.Equal(settingsNow) || !c.ChangedAt.Equal(settingsNow) || c.LastError != "" {
		t.Fatalf("status = %+v", c)
	}
	if f.models != 2 || !f.checkedAt.Equal(settingsNow) {
		t.Fatalf("metrics = %d models checked at %v", f.models, f.checkedAt)
	}
	if len(f.events) != 1 || f.events[0].Action != "prices.refresh" || f.events[0].Detail["outcome"] != "changed" || f.events[0].Detail["models"] != 2 {
		t.Fatalf("audit = %+v, want prices.refresh changed with 2 models", f.events)
	}
}

// A 304 is a successful check: the prices and the validators stay, the check time
// moves and an earlier failure is cleared.
func TestNotModifiedKeepsPricesAndValidatorsAndClearsTheError(t *testing.T) {
	v := app.CatalogValidators{ETag: `"v1"`, LastModified: "Tue, 22 Sep 2026 10:00:00 GMT"}
	stored := sonnet()
	stored.UpdatedAt = earlier
	f := newPricesFixture(t, false, []app.ModelPrice{stored},
		app.CatalogState{Validators: v, CheckedAt: earlier, ChangedAt: earlier, LastError: "the catalog answered 503"})
	f.load(t)
	f.source.EXPECT().Fetch(mock.Anything, v).Return(app.CatalogFetch{Unchanged: true}, nil).Once()

	list, err := f.svc.Refresh(context.Background(), newAdmin())
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if f.state.Validators != v || !f.state.CheckedAt.Equal(settingsNow) || !f.state.ChangedAt.Equal(earlier) || f.state.LastError != "" {
		t.Fatalf("stored state = %+v, want the same validators and change time, checked now, no error", f.state)
	}
	if list.Catalog.LastError != "" || list.Catalog.Models != 1 || len(list.Prices) != 1 || !list.Prices[0].UpdatedAt.Equal(earlier) {
		t.Fatalf("list = %+v, want the stored price and no error", list)
	}
	if got := f.priced(t); got["claude/claude-sonnet-5"] != 3 {
		t.Fatalf("sink = %v, want the stored price", got)
	}
	if f.events[0].Detail["outcome"] != "unchanged" {
		t.Fatalf("audit = %+v, want outcome unchanged", f.events)
	}
}

// A failed check, including one whose catalog prices none of our models, keeps
// every price in force and the validators, records why and counts the failure.
func TestFailedChecksKeepThePricesInForce(t *testing.T) {
	for name, answer := range map[string]struct {
		fetch app.CatalogFetch
		err   error
		want  string
	}{
		"unreachable": {err: errors.New("the catalog answered 503 Service Unavailable"), want: "the catalog answered 503 Service Unavailable"},
		"no prices": {fetch: app.CatalogFetch{Validators: app.CatalogValidators{ETag: `"empty"`}},
			want: "the catalog has no price for any of our providers"},
	} {
		t.Run(name, func(t *testing.T) {
			v := app.CatalogValidators{ETag: `"v1"`}
			f := newPricesFixture(t, false, []app.ModelPrice{sonnet()}, app.CatalogState{Validators: v, CheckedAt: earlier})
			f.load(t)
			f.source.EXPECT().Fetch(mock.Anything, v).Return(answer.fetch, answer.err).Once()

			list, err := f.svc.Refresh(context.Background(), newAdmin())
			if err != nil {
				t.Fatalf("Refresh: %v, want the failure in the status", err)
			}
			if list.Catalog.LastError != answer.want || list.Catalog.Models != 1 || !list.Catalog.CheckedAt.Equal(earlier) {
				t.Fatalf("status = %+v, want lastError %q, the price kept, the last success unchanged", list.Catalog, answer.want)
			}
			if len(f.storedCatalog) != 1 || f.state.Validators != v || f.state.LastError != answer.want {
				t.Fatalf("stored %v / %+v, want the catalog and validators kept and the error recorded", f.storedCatalog, f.state)
			}
			if got := f.priced(t); len(f.sunk) != 1 || got["claude/claude-sonnet-5"] != 3 {
				t.Fatalf("sink = %v after %d lists, want the price in force untouched", got, len(f.sunk))
			}
			if f.failures != 1 {
				t.Fatalf("failures = %d, want 1", f.failures)
			}
			if e := f.events[0]; e.Detail["outcome"] != "failed" || e.Detail["error"] != answer.want {
				t.Fatalf("audit = %+v, want outcome failed with the reason", e)
			}
		})
	}
}

// With no catalog configured a refresh is refused, and catalog rows stored while
// one was are not in force.
func TestDisabledCatalog(t *testing.T) {
	f := newPricesFixture(t, true, []app.ModelPrice{gpt()}, app.CatalogState{CheckedAt: earlier})
	f.load(t, sonnet())
	if _, err := f.svc.Refresh(context.Background(), newAdmin()); !errors.Is(err, app.ErrCatalogDisabled) {
		t.Fatalf("Refresh = %v, want ErrCatalogDisabled", err)
	}
	list := f.get(t)
	if list.Catalog != (app.CatalogStatus{}) || len(list.Prices) != 1 || list.Prices[0].Model != "claude-sonnet-5" {
		t.Fatalf("list = %+v, want the manual price alone and a disabled catalog", list)
	}
	if got := f.priced(t); len(got) != 1 {
		t.Fatalf("sink = %v, want the manual price alone", got)
	}
}

// Checks run one at a time, and reading the list never waits on one.
func TestChecksAreSerialisedAndReadsDoNotWait(t *testing.T) {
	f := newPricesFixture(t, false, nil, app.CatalogState{})
	f.load(t)
	var inFlight, most atomic.Int32
	release, entered := make(chan struct{}), make(chan struct{}, 2)
	f.source.EXPECT().Fetch(mock.Anything, mock.Anything).RunAndReturn(
		func(context.Context, app.CatalogValidators) (app.CatalogFetch, error) {
			n := inFlight.Add(1)
			defer inFlight.Add(-1)
			for m := most.Load(); n > m && !most.CompareAndSwap(m, n); m = most.Load() {
			}
			entered <- struct{}{}
			<-release
			return app.CatalogFetch{Unchanged: true}, nil
		}).Times(2)

	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			if _, err := f.svc.Refresh(context.Background(), newAdmin()); err != nil {
				t.Errorf("Refresh: %v", err)
			}
		})
	}
	<-entered
	read := make(chan struct{})
	go func() { f.get(t); close(read) }()
	select {
	case <-read:
	case <-time.After(5 * time.Second):
		t.Fatal("Get waited on a catalog fetch")
	}
	select {
	case <-entered:
		t.Fatal("a second fetch started while the first ran")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	wg.Wait()
	if most.Load() != 1 {
		t.Fatalf("%d fetches ran at once, want 1", most.Load())
	}
}

// The scheduled loop checks at once, not an interval later, and returns when
// told to stop.
func TestRunCatalogChecksAtOnceAndStops(t *testing.T) {
	f := newPricesFixture(t, false, nil, app.CatalogState{})
	f.load(t)
	fetched := make(chan struct{}, 1)
	f.source.EXPECT().Fetch(mock.Anything, mock.Anything).RunAndReturn(
		func(context.Context, app.CatalogValidators) (app.CatalogFetch, error) {
			fetched <- struct{}{}
			return app.CatalogFetch{Unchanged: true}, nil
		}).Once()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.svc.RunCatalog(ctx, time.Hour); close(done) }()
	select {
	case <-fetched:
	case <-time.After(5 * time.Second):
		t.Fatal("no check at start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunCatalog did not return after its context ended")
	}
}

func TestPricesAreAdminOnly(t *testing.T) {
	f := newPricesFixture(t, false, nil, app.CatalogState{})
	if _, err := f.svc.Get(context.Background(), newPerson()); !errors.Is(err, app.ErrForbidden) {
		t.Fatalf("Get by a user: err = %v, want ErrForbidden", err)
	}
	if _, err := f.svc.Replace(context.Background(), newPerson(), nil); !errors.Is(err, app.ErrForbidden) {
		t.Fatalf("Replace by a user: err = %v, want ErrForbidden", err)
	}
	if _, err := f.svc.Refresh(context.Background(), newPerson()); !errors.Is(err, app.ErrForbidden) {
		t.Fatalf("Refresh by a user: err = %v, want ErrForbidden", err)
	}
}
