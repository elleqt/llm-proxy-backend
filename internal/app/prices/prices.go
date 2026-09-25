// Package prices maintains the price list the cost estimates use: the price
// catalog's prices with the administrator's manual overrides on top.
package prices

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
)

// Source says where a price in force comes from.
type Source string

const (
	// SourceCatalog is a price the price catalog set.
	SourceCatalog Source = "catalog"
	// SourceManual is an administrator's override; it wins over the catalog.
	SourceManual Source = "manual"
)

// Entry is one price in force. Catalog is set on a manual entry whose model
// the catalog also prices: the catalog's price, which removing the override
// restores.
type Entry struct {
	app.ModelPrice

	Source  Source
	Catalog *app.ModelPrice
}

// CatalogStatus is the price catalog as the administrator sees it. A zero time
// means never.
type CatalogStatus struct {
	Enabled   bool
	CheckedAt time.Time
	ChangedAt time.Time
	// Models is how many catalog prices are in force.
	Models    int
	LastError string
}

// List is the effective price list, ordered by provider then model, and
// the catalog's status.
type List struct {
	Prices  []Entry
	Catalog CatalogStatus
}

// Catalog check outcomes, as audited.
const (
	catalogChanged   = "changed"
	catalogUnchanged = "unchanged"
	catalogFailed    = "failed"
)

// Service maintains the price list the metrics cost estimate uses: the price
// catalog's prices with the administrator's manual overrides on top. Both lists
// live in the database and in memory here; sink holds the effective list the
// metrics read, set at boot (Load), on every Replace and on every catalog change,
// so a price change applies to usage recorded from then on and no request reads
// the database for a price.
//
// Catalog checks (RunCatalog on a schedule, Refresh on demand) run one at a time.
// A failed check records why and keeps the prices in force; a catalog that prices
// nothing of ours is a failed check, so it can never wipe them.
type Service struct {
	repo    app.PriceRepo
	catalog app.PriceCatalogRepo
	// source is nil when the catalog is disabled: then the stored catalog
	// prices are not in force, and only manual prices are.
	source  app.PriceCatalogSource
	sink    app.PriceSink
	metrics app.PriceCatalogMetrics
	audit   app.AuditSink
	clock   app.Clock
	log     app.InfoLogger

	// checking holds a token while a catalog check runs. It is never taken
	// under mu, and mu is never held across a fetch: reading the list does not
	// wait on the catalog.
	checking chan struct{}

	// mu guards the fields below and serialises every write, so the sink ends up
	// holding the effective list of the last one.
	mu            sync.Mutex
	manual        []app.ModelPrice
	catalogPrices []app.ModelPrice
	state         app.CatalogState
}

// New builds the service. source is nil when no catalog is configured.
func New(repo app.PriceRepo, catalog app.PriceCatalogRepo, source app.PriceCatalogSource, sink app.PriceSink,
	metrics app.PriceCatalogMetrics, audit app.AuditSink, clock app.Clock, log app.InfoLogger,
) *Service {
	return &Service{
		repo: repo, catalog: catalog, source: source, sink: sink, metrics: metrics,
		audit: audit, clock: clock, log: log, checking: make(chan struct{}, 1),
	}
}

// Load reads the stored lists and hands the effective one to the sink. The
// composition root calls it at boot, before RunCatalog.
func (p *Service) Load(ctx context.Context) error {
	manual, err := p.repo.List(ctx)
	if err != nil {
		return fmt.Errorf("app: load prices: %w", err)
	}

	var (
		catalog []app.ModelPrice
		state   app.CatalogState
	)
	if p.source != nil {
		if catalog, err = p.catalog.List(ctx); err != nil {
			return fmt.Errorf("app: load catalog prices: %w", err)
		}

		if state, err = p.catalog.State(ctx); err != nil {
			return fmt.Errorf("app: load catalog state: %w", err)
		}

		p.metrics.SetPriceCatalog(len(catalog), state.CheckedAt)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.manual, p.catalogPrices, p.state = manual, catalog, state
	p.publish()

	return nil
}

// Get returns the effective list and the catalog's status.
func (p *Service) Get(_ context.Context, actor identity.User) (List, error) {
	if err := app.RequireAdmin(actor); err != nil {
		return List{}, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	return p.listLocked(), nil
}

// Replace makes list the whole manual override list: a model it omits falls back
// to the catalog's price, or has none. Every rate must be a finite, non-negative
// number and every (provider, model) must be named once; the first entry that is
// not is an *InvalidInputError naming it as "[index].field".
func (p *Service) Replace(ctx context.Context, actor identity.User, list []app.ModelPrice) (List, error) {
	if err := app.RequireAdmin(actor); err != nil {
		return List{}, err
	}

	if err := validatePrices(list); err != nil {
		return List{}, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	now := p.clock.Now()
	if err := p.repo.Replace(ctx, list, now); err != nil {
		return List{}, fmt.Errorf("app: replace prices: %w", err)
	}
	// The sink gets the list as submitted: it is what was stored, and a failed
	// read-back below must not leave the metrics pricing with the old list.
	p.manual = slices.Clone(list)
	p.publish()

	stored, err := p.repo.List(ctx)
	if err != nil {
		return List{}, fmt.Errorf("app: prices replaced; read back: %w", err)
	}

	p.manual = stored
	if err := p.audit.Record(ctx, app.AuditEvent{
		At:      now,
		ActorID: actor.ID,
		Action:  "prices.replace",
		Target:  "model_prices",
		Detail:  map[string]any{"count": len(list)},
	}); err != nil {
		return List{}, fmt.Errorf("app: prices.replace applied but not audited: %w", err)
	}

	return p.listLocked(), nil
}

// Refresh checks the catalog now. A failed check is not an error: it shows in the
// returned status and the prices in force are kept. ErrCatalogDisabled when no
// catalog is configured.
func (p *Service) Refresh(ctx context.Context, actor identity.User) (List, error) {
	if err := app.RequireAdmin(actor); err != nil {
		return List{}, err
	}

	if p.source == nil {
		return List{}, app.ErrCatalogDisabled
	}

	res, err := p.check(ctx)
	if err != nil {
		return List{}, err
	}

	detail := map[string]any{"outcome": res.outcome, "models": res.models}
	if res.failure != "" {
		detail["error"] = res.failure
	}

	if err := p.audit.Record(ctx, app.AuditEvent{
		At:      p.clock.Now(),
		ActorID: actor.ID,
		Action:  "prices.refresh",
		Target:  "price_catalog",
		Detail:  detail,
	}); err != nil {
		return List{}, fmt.Errorf("app: prices.refresh done but not audited: %w", err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	return p.listLocked(), nil
}

// RunCatalog checks the catalog at once and then every interval until ctx ends.
// The composition root runs it after Load; it returns at once when no catalog is
// configured.
func (p *Service) RunCatalog(ctx context.Context, interval time.Duration) {
	if p.source == nil {
		return
	}

	tick := time.NewTicker(interval)
	defer tick.Stop()

	for {
		if _, err := p.check(ctx); err != nil && ctx.Err() == nil {
			p.log.Warn("price catalog check failed", slog.Any("err", err))
		}

		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

type checkResult struct {
	outcome string
	// models is the number of catalog prices in force after the check.
	models int
	// failure is why the check failed, when it did.
	failure string
}

// check fetches the catalog and applies what it says. A catalog that cannot be
// read or priced is a failed check, recorded and returned as a result; the error
// is for a failure to store the outcome, or ctx ending first.
func (p *Service) check(ctx context.Context) (checkResult, error) {
	select {
	case p.checking <- struct{}{}:
	case <-ctx.Done():
		return checkResult{}, fmt.Errorf("app: price catalog check: %w", ctx.Err())
	}

	defer func() { <-p.checking }()

	p.mu.Lock()

	since := p.state.Validators
	if p.state.Fingerprint != p.source.Fingerprint() {
		// Stored by another URL or parser: this one must read the whole catalog.
		since = app.CatalogValidators{}
	}
	p.mu.Unlock()

	fetched, err := p.source.Fetch(ctx, since)
	if err == nil && !fetched.Unchanged {
		err = acceptCatalog(fetched.Prices)
	}

	if err != nil {
		if ctx.Err() != nil {
			// Stopped, not failed: a shutdown is not the catalog's fault.
			return checkResult{}, fmt.Errorf("app: price catalog check: %w", ctx.Err())
		}

		return p.recordFailure(ctx, err.Error())
	}

	return p.recordSuccess(ctx, fetched)
}

// The reasons acceptCatalog refuses a fetched list. Their text is the failure the
// check records, audits, logs and shows.
var (
	errCatalogEmpty        = errors.New("the catalog has no price for any of our providers")
	errCatalogZero         = errors.New("the catalog prices every model at zero")
	errCatalogInvalidPrice = errors.New("the catalog carries an invalid price")
)

// acceptCatalog refuses a fetched list the prices in force must not be replaced
// with: an empty one, which would unprice every model, one that prices every
// model at zero, which would zero the cost estimate, or an invalid one.
func acceptCatalog(prices []app.ModelPrice) error {
	if len(prices) == 0 {
		return errCatalogEmpty
	}

	if !slices.ContainsFunc(prices, func(p app.ModelPrice) bool { return p.Input > 0 || p.Output > 0 }) {
		return errCatalogZero
	}

	if err := validatePrices(prices); err != nil {
		if ie, ok := errors.AsType[*app.InvalidInputError](err); ok {
			return fmt.Errorf("%w (%s)", errCatalogInvalidPrice, ie.Field)
		}

		return err
	}

	return nil
}

// maxCatalogError bounds the failure text stored, audited, logged and shown.
const maxCatalogError = 200

// clip cuts text to at most maxCatalogError bytes, on a rune boundary.
func clip(text string) string {
	if len(text) <= maxCatalogError {
		return text
	}

	cut := maxCatalogError
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}

	return text[:cut]
}

func (p *Service) recordFailure(ctx context.Context, why string) (checkResult, error) {
	why = clip(why)

	p.metrics.ObservePriceCatalogFailure()
	p.mu.Lock()
	defer p.mu.Unlock()

	p.state.LastError = why
	res := checkResult{outcome: catalogFailed, models: len(p.catalogPrices), failure: why}
	p.log.Warn("price catalog check failed; catalog prices in force are kept",
		slog.String("reason", why), slog.Int("prices", res.models))

	if err := p.catalog.SetState(ctx, p.state); err != nil {
		return res, fmt.Errorf("app: record the price catalog failure: %w", err)
	}

	return res, nil
}

// recordSuccess stores what a successful fetch found. A store that refuses it
// makes the check a failed one: the prices and the state in force stay.
func (p *Service) recordSuccess(ctx context.Context, fetched app.CatalogFetch) (checkResult, error) {
	now := p.clock.Now()
	p.mu.Lock()
	state := p.state

	state.CheckedAt, state.LastError = now, ""
	if !fetched.Unchanged {
		state.Validators, state.Fingerprint = fetched.Validators, p.source.Fingerprint()
	}

	changed := !fetched.Unchanged && !sameRates(p.catalogPrices, fetched.Prices)

	var err error

	if changed {
		state.ChangedAt = now
		err = p.catalog.Replace(ctx, fetched.Prices, state, now)
	} else {
		err = p.catalog.SetState(ctx, state)
	}

	if err != nil {
		p.mu.Unlock()

		if ctx.Err() != nil {
			// Stopped while storing, not failed: nothing was stored.
			return checkResult{}, fmt.Errorf("app: price catalog check: %w", ctx.Err())
		}

		p.log.Warn("price catalog: storing the check failed", slog.Any("err", err))

		return p.recordFailure(ctx, "the catalog could not be stored")
	}

	defer p.mu.Unlock()

	p.state = state

	if !changed {
		p.metrics.SetPriceCatalog(len(p.catalogPrices), now)
		p.log.Info("price catalog checked: unchanged", slog.Int("prices", len(p.catalogPrices)))

		return checkResult{outcome: catalogUnchanged, models: len(p.catalogPrices)}, nil
	}
	// As in Replace: what was stored goes to the sink before the read-back.
	p.catalogPrices = fetched.Prices
	p.publish()
	p.metrics.SetPriceCatalog(len(fetched.Prices), now)
	p.log.Info("price catalog updated", slog.Int("prices", len(fetched.Prices)))
	res := checkResult{outcome: catalogChanged, models: len(fetched.Prices)}

	stored, err := p.catalog.List(ctx)
	if err != nil {
		return res, fmt.Errorf("app: price catalog stored; read back: %w", err)
	}

	p.catalogPrices = stored

	return res, nil
}

// sameRates reports whether two price lists price the same models at the same
// rates, whatever their order and UpdatedAt.
func sameRates(left, right []app.ModelPrice) bool {
	if len(left) != len(right) {
		return false
	}

	byKey := make(map[priceKey]app.ModelPrice, len(left))
	for _, mp := range left {
		mp.UpdatedAt = time.Time{}
		byKey[priceKey{mp.Provider, mp.Model}] = mp
	}

	for _, mp := range right {
		mp.UpdatedAt = time.Time{}
		if old, ok := byKey[priceKey{mp.Provider, mp.Model}]; !ok || old != mp {
			return false
		}
	}

	return true
}

// priceKey identifies a price: one model of one provider.
type priceKey struct{ provider, model string }

// entriesLocked is the effective list: the catalog's prices, each manual price
// replacing the catalog's for its model. p.mu must be held.
func (p *Service) entriesLocked() []Entry {
	out := make([]Entry, 0, len(p.catalogPrices)+len(p.manual))

	at := make(map[priceKey]int, len(p.catalogPrices))
	for _, c := range p.catalogPrices {
		at[priceKey{c.Provider, c.Model}] = len(out)
		out = append(out, Entry{ModelPrice: c, Source: SourceCatalog})
	}

	for _, m := range p.manual {
		entry := Entry{ModelPrice: m, Source: SourceManual}
		if i, ok := at[priceKey{m.Provider, m.Model}]; ok {
			c := out[i].ModelPrice
			entry.Catalog = &c
			out[i] = entry

			continue
		}

		out = append(out, entry)
	}

	slices.SortFunc(out, func(a, b Entry) int {
		return cmp.Or(strings.Compare(a.Provider, b.Provider), strings.Compare(a.Model, b.Model))
	})

	return out
}

// publish hands the effective list to the sink. p.mu must be held.
func (p *Service) publish() {
	entries := p.entriesLocked()

	prices := make([]app.ModelPrice, len(entries))
	for i, e := range entries {
		prices[i] = e.ModelPrice
	}

	p.sink.SetPrices(prices)
}

// listLocked is the list Get answers. p.mu must be held.
func (p *Service) listLocked() List {
	status := CatalogStatus{Enabled: p.source != nil}
	if status.Enabled {
		status.CheckedAt, status.ChangedAt = p.state.CheckedAt, p.state.ChangedAt
		status.Models, status.LastError = len(p.catalogPrices), p.state.LastError
	}

	return List{Prices: p.entriesLocked(), Catalog: status}
}

func validatePrices(list []app.ModelPrice) error {
	seen := make(map[priceKey]struct{}, len(list))
	for index, mp := range list {
		field := func(name string) error { return &app.InvalidInputError{Field: fmt.Sprintf("[%d].%s", index, name)} }
		if strings.TrimSpace(mp.Provider) == "" {
			return field("provider")
		}

		if strings.TrimSpace(mp.Model) == "" {
			return field("model")
		}

		for _, r := range [...]struct {
			name string
			v    float64
		}{{"input", mp.Input}, {"output", mp.Output}, {"cacheRead", mp.CacheRead}, {"cacheWrite", mp.CacheWrite}} {
			if r.v < 0 || math.IsNaN(r.v) || math.IsInf(r.v, 0) {
				return field(r.name)
			}
		}

		k := priceKey{mp.Provider, mp.Model}
		if _, dup := seen[k]; dup {
			return &app.InvalidInputError{Field: fmt.Sprintf("[%d]", index)}
		}

		seen[k] = struct{}{}
	}

	return nil
}
