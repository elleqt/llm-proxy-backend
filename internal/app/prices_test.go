package app_test

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/app/mocks"
)

type pricesFixture struct {
	repo  *mocks.PriceRepo
	sink  *mocks.PriceSink
	audit *mocks.AuditSink
	svc   *app.Prices
}

func newPricesFixture(t *testing.T) *pricesFixture {
	t.Helper()
	f := &pricesFixture{repo: mocks.NewPriceRepo(t), sink: mocks.NewPriceSink(t), audit: mocks.NewAuditSink(t)}
	f.svc = app.NewPrices(f.repo, f.sink, f.audit, fixedClock{now: settingsNow})
	return f
}

func sonnet() app.ModelPrice {
	return app.ModelPrice{Provider: "claude", Model: "claude-sonnet-5", Input: 3, Output: 15, CacheRead: 0.3, CacheWrite: 3.75}
}

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
			f := newPricesFixture(t)
			// No repo, sink or audit expectation: nothing may be written.
			_, err := f.svc.Replace(context.Background(), newAdmin(), c.list)
			var ie *app.InvalidInputError
			if !errors.As(err, &ie) || ie.Field != c.field {
				t.Fatalf("err = %v, want InvalidInputError{%q}", err, c.field)
			}
		})
	}
}

func TestPricesReplaceStoresThenUpdatesTheSink(t *testing.T) {
	f := newPricesFixture(t)
	admin := newAdmin()
	list := []app.ModelPrice{sonnet(), {Provider: "chatgpt", Model: "gpt-6", Input: 1.25, Output: 10}}
	stored := []app.ModelPrice{list[1], list[0]}
	var steps []string

	f.repo.EXPECT().Replace(mock.Anything, list, settingsNow).RunAndReturn(
		func(context.Context, []app.ModelPrice, time.Time) error { steps = append(steps, "store"); return nil }).Once()
	f.sink.EXPECT().SetPrices(list).Run(func([]app.ModelPrice) { steps = append(steps, "sink") }).Once()
	f.repo.EXPECT().List(mock.Anything).Return(stored, nil).Once()
	f.audit.EXPECT().Record(mock.Anything, mock.MatchedBy(func(e app.AuditEvent) bool {
		return e.Action == "prices.replace" && e.ActorID == admin.ID
	})).Return(nil).Once()

	got, err := f.svc.Replace(context.Background(), admin, list)
	if err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if len(got) != 2 || got[0] != stored[0] {
		t.Fatalf("Replace returned %v, want the stored list", got)
	}
	if len(steps) != 2 || steps[0] != "store" || steps[1] != "sink" {
		t.Fatalf("steps = %v, want store then sink", steps)
	}
}

func TestPricesReplaceStoreFailureLeavesTheSinkAlone(t *testing.T) {
	f := newPricesFixture(t)
	f.repo.EXPECT().Replace(mock.Anything, mock.Anything, mock.Anything).Return(errors.New("db down"))
	// No SetPrices expectation: the metrics must keep pricing with the stored list.

	if _, err := f.svc.Replace(context.Background(), newAdmin(), []app.ModelPrice{sonnet()}); err == nil {
		t.Fatal("Replace succeeded with the store failing")
	}
}

func TestPricesLoadFillsTheSink(t *testing.T) {
	f := newPricesFixture(t)
	stored := []app.ModelPrice{sonnet()}
	f.repo.EXPECT().List(mock.Anything).Return(stored, nil)
	f.sink.EXPECT().SetPrices(stored).Once()

	if err := f.svc.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}
}

func TestPricesAreAdminOnly(t *testing.T) {
	f := newPricesFixture(t)
	if _, err := f.svc.Get(context.Background(), newPerson()); !errors.Is(err, app.ErrForbidden) {
		t.Fatalf("Get by a user: err = %v, want ErrForbidden", err)
	}
	if _, err := f.svc.Replace(context.Background(), newPerson(), nil); !errors.Is(err, app.ErrForbidden) {
		t.Fatalf("Replace by a user: err = %v, want ErrForbidden", err)
	}
}
