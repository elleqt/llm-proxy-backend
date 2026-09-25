package app_test

import (
	"context"
	"errors"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/app/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
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
	// storeErr is what the catalog store's writes return; replaces and
	// setStates count them.
	storeErr  error
	onStore   func()
	replaces  int
	setStates int
}

// fingerprint is the fixture source's Fingerprint.
const fingerprint = "2 https://catalog.example.com/models.json"

// newPricesFixture builds the service with a catalog source unless disabled. The
// manual store is left to each test; the catalog store starts as given.
func newPricesFixture(t *testing.T, disabled bool, catalog []app.ModelPrice, state app.CatalogState) *pricesFixture {
	t.Helper()
	fixture := &pricesFixture{
		repo: mocks.NewPriceRepo(t), catalog: mocks.NewPriceCatalogRepo(t), source: mocks.NewPriceCatalogSource(t),
		sink: mocks.NewPriceSink(t), metrics: mocks.NewPriceCatalogMetrics(t), audit: mocks.NewAuditSink(t),
		storedCatalog: catalog, state: state,
	}
	fixture.catalog.EXPECT().List(mock.Anything).RunAndReturn(func(context.Context) ([]app.ModelPrice, error) {
		fixture.mu.Lock()
		defer fixture.mu.Unlock()

		return fixture.storedCatalog, nil
	}).Maybe()
	fixture.catalog.EXPECT().State(mock.Anything).RunAndReturn(func(context.Context) (app.CatalogState, error) {
		fixture.mu.Lock()
		defer fixture.mu.Unlock()

		return fixture.state, nil
	}).Maybe()
	fixture.catalog.EXPECT().Replace(mock.Anything, mock.Anything, mock.Anything, mock.Anything).RunAndReturn(
		func(_ context.Context, prices []app.ModelPrice, state app.CatalogState, at time.Time) error {
			fixture.mu.Lock()
			defer fixture.mu.Unlock()

			fixture.replaces++
			if fixture.onStore != nil {
				fixture.onStore()
			}

			if fixture.storeErr != nil {
				return fixture.storeErr
			}

			fixture.storedCatalog = make([]app.ModelPrice, len(prices))
			for i, p := range prices {
				p.UpdatedAt = at
				fixture.storedCatalog[i] = p
			}

			fixture.state = state

			return nil
		}).Maybe()
	fixture.catalog.EXPECT().SetState(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, state app.CatalogState) error {
		fixture.mu.Lock()
		defer fixture.mu.Unlock()

		fixture.setStates++
		if fixture.storeErr != nil && state.LastError == "" {
			return fixture.storeErr
		}

		fixture.state = state

		return nil
	}).Maybe()
	fixture.sink.EXPECT().SetPrices(mock.Anything).Run(func(p []app.ModelPrice) {
		fixture.mu.Lock()
		defer fixture.mu.Unlock()

		fixture.sunk = append(fixture.sunk, p)
	}).Maybe()
	fixture.metrics.EXPECT().SetPriceCatalog(mock.Anything, mock.Anything).Run(func(n int, at time.Time) {
		fixture.mu.Lock()
		defer fixture.mu.Unlock()

		fixture.models, fixture.checkedAt = n, at
	}).Maybe()
	fixture.metrics.EXPECT().ObservePriceCatalogFailure().Run(func() {
		fixture.mu.Lock()
		defer fixture.mu.Unlock()

		fixture.failures++
	}).Maybe()
	fixture.audit.EXPECT().Record(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, e app.AuditEvent) error {
		fixture.mu.Lock()
		defer fixture.mu.Unlock()

		fixture.events = append(fixture.events, e)

		return nil
	}).Maybe()

	fixture.source.EXPECT().Fingerprint().Return(fingerprint).Maybe()

	var source app.PriceCatalogSource = fixture.source
	if disabled {
		source = nil
	}

	fixture.svc = app.NewPrices(fixture.repo, fixture.catalog, source, fixture.sink, fixture.metrics, fixture.audit, fixedClock{now: settingsNow}, discardLogger{})

	return fixture
}

// load runs Load with manual as the stored overrides.
func (f *pricesFixture) load(t *testing.T, manual ...app.ModelPrice) {
	t.Helper()
	f.repo.EXPECT().List(mock.Anything).Return(manual, nil).Once()

	err := f.svc.Load(context.Background())
	require.NoError(t, err, "Load")
}

// priced is the sink's latest list as provider/model -> input rate.
func (f *pricesFixture) priced(t *testing.T) map[string]float64 {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()

	require.NotEmpty(t, f.sunk, "the sink was never given a list")

	out := map[string]float64{}
	for _, p := range f.sunk[len(f.sunk)-1] {
		out[p.Provider+"/"+p.Model] = p.Input
	}

	return out
}

func (f *pricesFixture) get(t *testing.T) app.PriceList {
	t.Helper()

	list, err := f.svc.Get(context.Background(), newAdmin())
	assert.NoError(t, err, "Get")

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
	for name, tc := range map[string]struct {
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
			_, err := f.svc.Replace(context.Background(), newAdmin(), tc.list)

			var ie *app.InvalidInputError
			require.ErrorAs(t, err, &ie)
			require.Equal(t, tc.field, ie.Field, "InvalidInputError field")
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
	fixture := newPricesFixture(t, false, []app.ModelPrice{catalogSonnet, catalogGPT}, app.CatalogState{CheckedAt: earlier})

	override := sonnet()
	override.Input = 2
	custom := app.ModelPrice{Provider: "claude", Model: "claude-private", Input: 7}
	fixture.load(t, override, custom)

	require.Equal(t, map[string]float64{"claude/claude-sonnet-5": 2, "chatgpt/gpt-6": 1.25, "claude/claude-private": 7}, fixture.priced(t),
		"sink: want the override for sonnet, the catalog for gpt-6, the private model")

	assertOverriddenList(t, fixture.get(t))

	fixture.repo.EXPECT().Replace(mock.Anything, []app.ModelPrice{}, settingsNow).Return(nil).Once()
	fixture.repo.EXPECT().List(mock.Anything).Return(nil, nil).Once()

	got, err := fixture.svc.Replace(context.Background(), newAdmin(), []app.ModelPrice{})
	require.NoError(t, err, "Replace")
	require.Len(t, got.Prices, 2, "after omitting the overrides: want the catalog's two rows")
	require.Equal(t, app.PriceSourceCatalog, got.Prices[0].Source, "after omitting the overrides")
	require.Equal(t, app.PriceSourceCatalog, got.Prices[1].Source, "after omitting the overrides")

	priced := fixture.priced(t)
	require.Equal(t, 3.0, priced["claude/claude-sonnet-5"], "sink: want sonnet back at the catalog's 3")
	require.Len(t, priced, 2, "sink: want the private model gone")

	require.Len(t, fixture.events, 1, "audit: want one prices.replace")
	require.Equal(t, "prices.replace", fixture.events[0].Action, "audit action")
}

// assertOverriddenList checks the admin view while a manual sonnet price and a
// private model override a two-row catalog: each entry names its source, and a
// manual entry shadowing a catalog row carries that row's rates behind it.
func assertOverriddenList(t *testing.T, list app.PriceList) {
	t.Helper()

	require.Len(t, list.Prices, 3, "Get: want 3 entries")

	byModel := map[string]app.PriceEntry{}
	for _, e := range list.Prices {
		byModel[e.Model] = e
	}

	sonnetEntry := byModel["claude-sonnet-5"]
	require.Equal(t, app.PriceSourceManual, sonnetEntry.Source, "sonnet source")
	require.Equal(t, 2.0, sonnetEntry.Input, "sonnet input")
	require.NotNil(t, sonnetEntry.Catalog, "sonnet: want the catalog's rates behind it")
	require.Equal(t, 3.0, sonnetEntry.Catalog.Input, "sonnet catalog input")

	gptEntry := byModel["gpt-6"]
	require.Equal(t, app.PriceSourceCatalog, gptEntry.Source, "gpt-6 source")
	require.Nil(t, gptEntry.Catalog, "gpt-6: the catalog's own row has no catalog rates behind it")
	require.True(t, gptEntry.UpdatedAt.Equal(earlier), "gpt-6 updated at %v, want %v", gptEntry.UpdatedAt, earlier)

	privateEntry := byModel["claude-private"]
	require.Equal(t, app.PriceSourceManual, privateEntry.Source, "private source")
	require.Nil(t, privateEntry.Catalog, "private: want no catalog rates")

	require.Equal(t, 2, list.Catalog.Models, "catalog status models")
	require.True(t, list.Catalog.Enabled, "catalog status: want enabled")
}

func TestPricesReplaceStoreFailureLeavesTheSinkAlone(t *testing.T) {
	fixture := newPricesFixture(t, false, nil, app.CatalogState{})
	fixture.load(t, sonnet())
	fixture.repo.EXPECT().Replace(mock.Anything, mock.Anything, mock.Anything).Return(errors.New("db down"))

	_, err := fixture.svc.Replace(context.Background(), newAdmin(), []app.ModelPrice{gpt()})
	require.Error(t, err, "Replace succeeded with the store failing")

	got := fixture.priced(t)
	require.Len(t, fixture.sunk, 1, "sink: want the stored list alone")
	require.Equal(t, 3.0, got["claude/claude-sonnet-5"], "sink: want the stored list alone")
}

// A check that finds a new catalog stores it with its validators, prices it and
// reports it; the refresh is audited.
func TestRefreshAppliesAChangedCatalog(t *testing.T) {
	fixture := newPricesFixture(t, false, nil, app.CatalogState{})
	fixture.load(t)

	validators := app.CatalogValidators{ETag: `"v1"`, LastModified: "Tue, 22 Sep 2026 10:00:00 GMT"}
	fixture.source.EXPECT().Fetch(mock.Anything, app.CatalogValidators{}).
		Return(app.CatalogFetch{Prices: []app.ModelPrice{sonnet(), gpt()}, Validators: validators}, nil).Once()

	list, err := fixture.svc.Refresh(context.Background(), newAdmin())
	require.NoError(t, err, "Refresh")

	got := fixture.priced(t)
	require.Equal(t, 3.0, got["claude/claude-sonnet-5"], "sink: want the catalog's prices")
	require.Equal(t, 1.25, got["chatgpt/gpt-6"], "sink: want the catalog's prices")

	require.Equal(t, validators, fixture.state.Validators, "stored validators")
	require.True(t, fixture.state.CheckedAt.Equal(settingsNow), "stored state = %+v, want checked now", fixture.state)
	require.True(t, fixture.state.ChangedAt.Equal(settingsNow), "stored state = %+v, want changed now", fixture.state)

	status := list.Catalog
	require.Equal(t, 2, status.Models, "status models")
	require.True(t, status.CheckedAt.Equal(settingsNow), "status = %+v, want checked now", status)
	require.True(t, status.ChangedAt.Equal(settingsNow), "status = %+v, want changed now", status)
	require.Empty(t, status.LastError, "status last error")

	require.Equal(t, 2, fixture.models, "metrics models")
	require.True(t, fixture.checkedAt.Equal(settingsNow), "metrics checked at %v, want now", fixture.checkedAt)

	require.Len(t, fixture.events, 1, "audit: want one prices.refresh")
	require.Equal(t, "prices.refresh", fixture.events[0].Action, "audit action")
	require.Equal(t, "changed", fixture.events[0].Detail["outcome"], "audit outcome")
	require.Equal(t, 2, fixture.events[0].Detail["models"], "audit models")
}

// A 304 is a successful check: the prices and the validators stay, the check time
// moves and an earlier failure is cleared.
func TestNotModifiedKeepsPricesAndValidatorsAndClearsTheError(t *testing.T) {
	validators := app.CatalogValidators{ETag: `"v1"`, LastModified: "Tue, 22 Sep 2026 10:00:00 GMT"}
	stored := sonnet()
	stored.UpdatedAt = earlier
	fixture := newPricesFixture(t, false, []app.ModelPrice{stored},
		app.CatalogState{Validators: validators, Fingerprint: fingerprint, CheckedAt: earlier, ChangedAt: earlier, LastError: "the catalog answered 503"})
	fixture.load(t)
	fixture.source.EXPECT().Fetch(mock.Anything, validators).Return(app.CatalogFetch{Unchanged: true}, nil).Once()

	list, err := fixture.svc.Refresh(context.Background(), newAdmin())
	require.NoError(t, err, "Refresh")

	require.Equal(t, validators, fixture.state.Validators, "stored validators")
	require.True(t, fixture.state.CheckedAt.Equal(settingsNow), "stored state = %+v, want checked now", fixture.state)
	require.True(t, fixture.state.ChangedAt.Equal(earlier), "stored state = %+v, want the same change time", fixture.state)
	require.Empty(t, fixture.state.LastError, "stored state: want no error")

	require.Empty(t, list.Catalog.LastError, "list: want no error")
	require.Equal(t, 1, list.Catalog.Models, "list catalog models")
	require.Len(t, list.Prices, 1, "list: want the stored price")
	require.True(t, list.Prices[0].UpdatedAt.Equal(earlier), "list = %+v, want the stored price", list)

	require.Equal(t, 3.0, fixture.priced(t)["claude/claude-sonnet-5"], "sink: want the stored price")

	require.NotEmpty(t, fixture.events, "audit")
	require.Equal(t, "unchanged", fixture.events[0].Detail["outcome"], "audit outcome")
}

// A failed check, including one whose catalog prices none of our models, keeps
// every price in force and the validators, records why and counts the failure.
func TestFailedChecksKeepThePricesInForce(t *testing.T) {
	for name, answer := range map[string]struct {
		fetch app.CatalogFetch
		err   error
		want  string
	}{
		"unreachable": {err: errors.New("the catalog answered 503"), want: "the catalog answered 503"},
		"no prices": {
			fetch: app.CatalogFetch{Validators: app.CatalogValidators{ETag: `"empty"`}},
			want:  "the catalog has no price for any of our providers",
		},
		"every price zero": {
			fetch: app.CatalogFetch{Prices: []app.ModelPrice{
				{Provider: "claude", Model: "claude-sonnet-5"},
				{Provider: "chatgpt", Model: "gpt-6", CacheRead: 1},
			}, Validators: app.CatalogValidators{ETag: `"zero"`}},
			want: "the catalog prices every model at zero",
		},
		"too long": {err: errors.New(strings.Repeat("é", 300)), want: strings.Repeat("é", 100)},
	} {
		t.Run(name, func(t *testing.T) {
			validators := app.CatalogValidators{ETag: `"v1"`}
			fixture := newPricesFixture(t, false, []app.ModelPrice{sonnet()}, app.CatalogState{Validators: validators, Fingerprint: fingerprint, CheckedAt: earlier})
			fixture.load(t)
			fixture.source.EXPECT().Fetch(mock.Anything, validators).Return(answer.fetch, answer.err).Once()

			list, err := fixture.svc.Refresh(context.Background(), newAdmin())
			require.NoError(t, err, "Refresh: want the failure in the status")

			require.Equal(t, answer.want, list.Catalog.LastError, "status last error")
			require.Equal(t, 1, list.Catalog.Models, "status: want the price kept")
			require.True(t, list.Catalog.CheckedAt.Equal(earlier), "status = %+v, want the last success unchanged", list.Catalog)

			require.Len(t, fixture.storedCatalog, 1, "stored: want the catalog kept")
			require.Equal(t, validators, fixture.state.Validators, "stored: want the validators kept")
			require.Equal(t, answer.want, fixture.state.LastError, "stored: want the error recorded")

			got := fixture.priced(t)
			require.Len(t, fixture.sunk, 1, "sink: want the price in force untouched")
			require.Equal(t, 3.0, got["claude/claude-sonnet-5"], "sink: want the price in force untouched")

			require.Equal(t, 1, fixture.failures, "failures")

			require.NotEmpty(t, fixture.events, "audit")
			e := fixture.events[0]
			require.Equal(t, "failed", e.Detail["outcome"], "audit outcome")
			require.Equal(t, answer.want, e.Detail["error"], "audit reason")
		})
	}
}

// With no catalog configured a refresh is refused, and catalog rows stored while
// one was are not in force.
func TestDisabledCatalog(t *testing.T) {
	fixture := newPricesFixture(t, true, []app.ModelPrice{gpt()}, app.CatalogState{CheckedAt: earlier})
	fixture.load(t, sonnet())

	_, err := fixture.svc.Refresh(context.Background(), newAdmin())
	require.ErrorIs(t, err, app.ErrCatalogDisabled, "Refresh")

	list := fixture.get(t)
	require.Zero(t, list.Catalog, "list: want a disabled catalog")
	require.Len(t, list.Prices, 1, "list: want the manual price alone")
	require.Equal(t, "claude-sonnet-5", list.Prices[0].Model, "list: want the manual price alone")

	require.Len(t, fixture.priced(t), 1, "sink: want the manual price alone")
}

// Checks run one at a time, and reading the list never waits on one.
func TestChecksAreSerialisedAndReadsDoNotWait(t *testing.T) {
	fixture := newPricesFixture(t, false, nil, app.CatalogState{})
	fixture.load(t)

	var inFlight, most atomic.Int32

	release, entered := make(chan struct{}), make(chan struct{}, 2)

	fixture.source.EXPECT().Fetch(mock.Anything, mock.Anything).RunAndReturn(
		func(context.Context, app.CatalogValidators) (app.CatalogFetch, error) {
			current := inFlight.Add(1)
			defer inFlight.Add(-1)

			// Raise the recorded peak to n unless a concurrent fetch already set it higher.
			for {
				peak := most.Load()
				if current <= peak || most.CompareAndSwap(peak, current) {
					break
				}
			}

			entered <- struct{}{}

			<-release

			return app.CatalogFetch{Unchanged: true}, nil
		}).Times(2)

	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			_, err := fixture.svc.Refresh(context.Background(), newAdmin())
			assert.NoError(t, err, "Refresh")
		})
	}

	<-entered

	read := make(chan struct{})

	go func() { fixture.get(t); close(read) }()

	select {
	case <-read:
	case <-time.After(5 * time.Second):
		require.Fail(t, "Get waited on a catalog fetch")
	}

	select {
	case <-entered:
		require.Fail(t, "a second fetch started while the first ran")
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	wg.Wait()

	require.Equal(t, int32(1), most.Load(), "fetches that ran at once")
}

// The scheduled loop checks at once, not an interval later, and returns when
// told to stop.
func TestRunCatalogChecksAtOnceAndStops(t *testing.T) {
	fixture := newPricesFixture(t, false, nil, app.CatalogState{})
	fixture.load(t)

	fetched := make(chan struct{}, 1)

	fixture.source.EXPECT().Fetch(mock.Anything, mock.Anything).RunAndReturn(
		func(context.Context, app.CatalogValidators) (app.CatalogFetch, error) {
			fetched <- struct{}{}

			return app.CatalogFetch{Unchanged: true}, nil
		}).Once()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() { fixture.svc.RunCatalog(ctx, time.Hour); close(done) }()

	select {
	case <-fetched:
	case <-time.After(5 * time.Second):
		require.Fail(t, "no check at start")
	}

	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		require.Fail(t, "RunCatalog did not return after its context ended")
	}
}

func TestPricesAreAdminOnly(t *testing.T) {
	fixture := newPricesFixture(t, false, nil, app.CatalogState{})
	_, err := fixture.svc.Get(context.Background(), newPerson())
	require.ErrorIs(t, err, app.ErrForbidden, "Get by a user")

	_, err = fixture.svc.Replace(context.Background(), newPerson(), nil)
	require.ErrorIs(t, err, app.ErrForbidden, "Replace by a user")

	_, err = fixture.svc.Refresh(context.Background(), newPerson())
	require.ErrorIs(t, err, app.ErrForbidden, "Refresh by a user")
}

// A catalog whose rates match the stored ones under new validators is not a
// change: the validators move, the prices and their change time stay.
func TestNewValidatorsWithTheSameRatesAreNoChange(t *testing.T) {
	v1, v2 := app.CatalogValidators{ETag: `"v1"`}, app.CatalogValidators{ETag: `"v2"`}
	stored := sonnet()
	stored.UpdatedAt = earlier
	fixture := newPricesFixture(t, false, []app.ModelPrice{stored}, app.CatalogState{Validators: v1, Fingerprint: fingerprint, CheckedAt: earlier, ChangedAt: earlier})
	fixture.load(t)
	fixture.source.EXPECT().Fetch(mock.Anything, v1).Return(app.CatalogFetch{Prices: []app.ModelPrice{sonnet()}, Validators: v2}, nil).Once()

	list, err := fixture.svc.Refresh(context.Background(), newAdmin())
	require.NoError(t, err, "Refresh")

	require.Zero(t, fixture.replaces, "replaces")
	require.Equal(t, v2, fixture.state.Validators, "state: want the new validators")
	require.True(t, fixture.state.ChangedAt.Equal(earlier), "state = %+v, want changed at the earlier time", fixture.state)
	require.True(t, fixture.state.CheckedAt.Equal(settingsNow), "state = %+v, want checked now", fixture.state)

	require.True(t, list.Catalog.ChangedAt.Equal(earlier), "status = %+v, want unchanged", list.Catalog)
	require.NotEmpty(t, fixture.events, "audit")
	require.Equal(t, "unchanged", fixture.events[0].Detail["outcome"], "audit outcome")
}

// Validators stored under another URL or parser are not sent: the new source
// reads the whole catalog, and stores its own fingerprint with what it finds.
func TestValidatorsFromAnotherSourceAreNotSent(t *testing.T) {
	validators := app.CatalogValidators{ETag: `"v1"`, LastModified: "Tue, 22 Sep 2026 10:00:00 GMT"}
	fixture := newPricesFixture(t, false, []app.ModelPrice{sonnet()},
		app.CatalogState{Validators: validators, Fingerprint: "1 https://catalog.example.com/models.json", CheckedAt: earlier})
	fixture.load(t)
	fixture.source.EXPECT().Fetch(mock.Anything, app.CatalogValidators{}).
		Return(app.CatalogFetch{Prices: []app.ModelPrice{sonnet()}, Validators: validators}, nil).Once()

	_, err := fixture.svc.Refresh(context.Background(), newAdmin())
	require.NoError(t, err, "Refresh")

	require.Equal(t, fingerprint, fixture.state.Fingerprint, "state: want this source's fingerprint")
	require.Equal(t, validators, fixture.state.Validators, "state: want the validators")
}

// A store that refuses the catalog makes a failed check, reported like any other.
func TestAStoreFailureIsAFailedCheck(t *testing.T) {
	fixture := newPricesFixture(t, false, []app.ModelPrice{sonnet()}, app.CatalogState{CheckedAt: earlier})
	fixture.load(t)
	fixture.storeErr = errors.New("invalid byte sequence for encoding UTF8: 0x00")
	fixture.source.EXPECT().Fetch(mock.Anything, mock.Anything).
		Return(app.CatalogFetch{Prices: []app.ModelPrice{gpt()}, Validators: app.CatalogValidators{ETag: `"v1"`}}, nil).Once()

	list, err := fixture.svc.Refresh(context.Background(), newAdmin())
	require.NoError(t, err, "Refresh")

	require.Equal(t, "the catalog could not be stored", list.Catalog.LastError, "status last error")
	require.True(t, list.Catalog.CheckedAt.Equal(earlier), "status = %+v, want the last success unchanged", list.Catalog)
	require.Equal(t, 1, fixture.failures, "failures: want a failed check counted")

	got := fixture.priced(t)
	require.Len(t, fixture.sunk, 1, "sink: want the price in force untouched")
	require.Equal(t, 3.0, got["claude/claude-sonnet-5"], "sink: want the price in force untouched")

	require.NotEmpty(t, fixture.events, "audit")
	require.Equal(t, "failed", fixture.events[0].Detail["outcome"], "audit outcome")
}

// A check cut short by the shutdown is not a failed check: nothing is counted or
// recorded.
func TestACancelledCheckIsNotAFailure(t *testing.T) {
	fixture := newPricesFixture(t, false, []app.ModelPrice{sonnet()}, app.CatalogState{CheckedAt: earlier})
	fixture.load(t)

	fetching := make(chan struct{})

	fixture.source.EXPECT().Fetch(mock.Anything, mock.Anything).RunAndReturn(
		func(ctx context.Context, _ app.CatalogValidators) (app.CatalogFetch, error) {
			close(fetching)
			<-ctx.Done()

			return app.CatalogFetch{}, errors.New("the catalog could not be fetched: context canceled")
		}).Once()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() { fixture.svc.RunCatalog(ctx, time.Hour); close(done) }()

	<-fetching
	cancel()
	<-done

	require.Zero(t, fixture.failures, "failures")
	require.Zero(t, fixture.setStates, "state writes")
	require.Empty(t, fixture.get(t).Catalog.LastError, "status last error")
}

// A check stopped while its catalog is being stored is not a failed check either.
func TestACheckCancelledWhileStoringIsNotAFailure(t *testing.T) {
	fixture := newPricesFixture(t, false, []app.ModelPrice{sonnet()}, app.CatalogState{CheckedAt: earlier})
	fixture.load(t)

	ctx, cancel := context.WithCancel(context.Background())
	fixture.onStore, fixture.storeErr = cancel, context.Canceled
	fixture.source.EXPECT().Fetch(mock.Anything, mock.Anything).
		Return(app.CatalogFetch{Prices: []app.ModelPrice{gpt()}, Validators: app.CatalogValidators{ETag: `"v1"`}}, nil).Once()

	done := make(chan struct{})

	go func() { fixture.svc.RunCatalog(ctx, time.Hour); close(done) }()

	<-done

	require.Equal(t, 1, fixture.replaces, "replaces")
	require.Zero(t, fixture.failures, "failures")
	require.Zero(t, fixture.setStates, "state writes")
	require.Empty(t, fixture.get(t).Catalog.LastError, "status last error")
}
