package app

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
)

// PriceSource says where a price in force comes from.
type PriceSource string

const (
	// PriceSourceCatalog is a price the price catalog set.
	PriceSourceCatalog PriceSource = "catalog"
	// PriceSourceManual is an administrator's override; it wins over the catalog.
	PriceSourceManual PriceSource = "manual"
)

// PriceEntry is one price in force. Catalog is set on a manual entry whose model
// the catalog also prices: the catalog's price, which removing the override
// restores.
type PriceEntry struct {
	ModelPrice
	Source  PriceSource
	Catalog *ModelPrice
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

// PriceList is the effective price list, ordered by provider then model, and
// the catalog's status.
type PriceList struct {
	Prices  []PriceEntry
	Catalog CatalogStatus
}

// Catalog check outcomes, as audited.
const (
	catalogChanged   = "changed"
	catalogUnchanged = "unchanged"
	catalogFailed    = "failed"
)

// Prices maintains the price list the metrics cost estimate uses: the price
// catalog's prices with the administrator's manual overrides on top. Both lists
// live in the database and in memory here; sink holds the effective list the
// metrics read, set at boot (Load), on every Replace and on every catalog change,
// so a price change applies to usage recorded from then on and no request reads
// the database for a price.
//
// Catalog checks (RunCatalog on a schedule, Refresh on demand) run one at a time.
// A failed check records why and keeps the prices in force; a catalog that prices
// nothing of ours is a failed check, so it can never wipe them.
type Prices struct {
	repo    PriceRepo
	catalog PriceCatalogRepo
	// source is nil when the catalog is disabled: then the stored catalog
	// prices are not in force, and only manual prices are.
	source  PriceCatalogSource
	sink    PriceSink
	metrics PriceCatalogMetrics
	audit   AuditSink
	clock   Clock
	log     InfoLogger

	// checking holds a token while a catalog check runs. It is never taken
	// under mu, and mu is never held across a fetch: reading the list does not
	// wait on the catalog.
	checking chan struct{}

	// mu guards the fields below and serialises every write, so the sink ends up
	// holding the effective list of the last one.
	mu            sync.Mutex
	manual        []ModelPrice
	catalogPrices []ModelPrice
	state         CatalogState
}

// NewPrices builds the service. source is nil when no catalog is configured.
func NewPrices(repo PriceRepo, catalog PriceCatalogRepo, source PriceCatalogSource, sink PriceSink,
	metrics PriceCatalogMetrics, audit AuditSink, clock Clock, log InfoLogger) *Prices {
	return &Prices{
		repo: repo, catalog: catalog, source: source, sink: sink, metrics: metrics,
		audit: audit, clock: clock, log: log, checking: make(chan struct{}, 1),
	}
}

// Load reads the stored lists and hands the effective one to the sink. The
// composition root calls it at boot, before RunCatalog.
func (p *Prices) Load(ctx context.Context) error {
	manual, err := p.repo.List(ctx)
	if err != nil {
		return fmt.Errorf("app: load prices: %w", err)
	}
	var (
		catalog []ModelPrice
		state   CatalogState
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
func (p *Prices) Get(_ context.Context, actor identity.User) (PriceList, error) {
	if err := requireAdmin(actor); err != nil {
		return PriceList{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.listLocked(), nil
}

// Replace makes list the whole manual override list: a model it omits falls back
// to the catalog's price, or has none. Every rate must be a finite, non-negative
// number and every (provider, model) must be named once; the first entry that is
// not is an *InvalidInputError naming it as "[index].field".
func (p *Prices) Replace(ctx context.Context, actor identity.User, list []ModelPrice) (PriceList, error) {
	if err := requireAdmin(actor); err != nil {
		return PriceList{}, err
	}
	if err := validatePrices(list); err != nil {
		return PriceList{}, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.clock.Now()
	if err := p.repo.Replace(ctx, list, now); err != nil {
		return PriceList{}, fmt.Errorf("app: replace prices: %w", err)
	}
	// The sink gets the list as submitted: it is what was stored, and a failed
	// read-back below must not leave the metrics pricing with the old list.
	p.manual = slices.Clone(list)
	p.publish()
	stored, err := p.repo.List(ctx)
	if err != nil {
		return PriceList{}, fmt.Errorf("app: prices replaced; read back: %w", err)
	}
	p.manual = stored
	if err := p.audit.Record(ctx, AuditEvent{
		At:      now,
		ActorID: actor.ID,
		Action:  "prices.replace",
		Target:  "model_prices",
		Detail:  map[string]any{"count": len(list)},
	}); err != nil {
		return PriceList{}, fmt.Errorf("app: prices.replace applied but not audited: %w", err)
	}
	return p.listLocked(), nil
}

// Refresh checks the catalog now. A failed check is not an error: it shows in the
// returned status and the prices in force are kept. ErrCatalogDisabled when no
// catalog is configured.
func (p *Prices) Refresh(ctx context.Context, actor identity.User) (PriceList, error) {
	if err := requireAdmin(actor); err != nil {
		return PriceList{}, err
	}
	if p.source == nil {
		return PriceList{}, ErrCatalogDisabled
	}
	res, err := p.check(ctx)
	if err != nil {
		return PriceList{}, err
	}
	detail := map[string]any{"outcome": res.outcome, "models": res.models}
	if res.failure != "" {
		detail["error"] = res.failure
	}
	if err := p.audit.Record(ctx, AuditEvent{
		At:      p.clock.Now(),
		ActorID: actor.ID,
		Action:  "prices.refresh",
		Target:  "price_catalog",
		Detail:  detail,
	}); err != nil {
		return PriceList{}, fmt.Errorf("app: prices.refresh done but not audited: %w", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.listLocked(), nil
}

// RunCatalog checks the catalog at once and then every interval until ctx ends.
// The composition root runs it after Load; it returns at once when no catalog is
// configured.
func (p *Prices) RunCatalog(ctx context.Context, interval time.Duration) {
	if p.source == nil {
		return
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		if _, err := p.check(ctx); err != nil && ctx.Err() == nil {
			p.log.Warnf("price catalog: %v", err)
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
func (p *Prices) check(ctx context.Context) (checkResult, error) {
	select {
	case p.checking <- struct{}{}:
	case <-ctx.Done():
		return checkResult{}, ctx.Err()
	}
	defer func() { <-p.checking }()

	p.mu.Lock()
	since := p.state.Validators
	if p.state.Fingerprint != p.source.Fingerprint() {
		// Stored by another URL or parser: this one must read the whole catalog.
		since = CatalogValidators{}
	}
	p.mu.Unlock()

	fetched, err := p.source.Fetch(ctx, since)
	if err == nil && !fetched.Unchanged {
		err = acceptCatalog(fetched.Prices)
	}
	if err != nil {
		if ctx.Err() != nil {
			// Stopped, not failed: a shutdown is not the catalog's fault.
			return checkResult{}, ctx.Err()
		}
		return p.recordFailure(ctx, err.Error())
	}
	return p.recordSuccess(ctx, fetched)
}

// acceptCatalog refuses a fetched list the prices in force must not be replaced
// with: an empty one, which would unprice every model, one that prices every
// model at zero, which would zero the cost estimate, or an invalid one.
func acceptCatalog(prices []ModelPrice) error {
	if len(prices) == 0 {
		return errors.New("the catalog has no price for any of our providers")
	}
	if !slices.ContainsFunc(prices, func(p ModelPrice) bool { return p.Input > 0 || p.Output > 0 }) {
		return errors.New("the catalog prices every model at zero")
	}
	if err := validatePrices(prices); err != nil {
		var ie *InvalidInputError
		if errors.As(err, &ie) {
			return fmt.Errorf("the catalog carries an invalid price (%s)", ie.Field)
		}
		return err
	}
	return nil
}

// maxCatalogError bounds the failure text stored, audited, logged and shown.
const maxCatalogError = 200

// clip cuts s to at most maxCatalogError bytes, on a rune boundary.
func clip(s string) string {
	if len(s) <= maxCatalogError {
		return s
	}
	cut := maxCatalogError
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func (p *Prices) recordFailure(ctx context.Context, why string) (checkResult, error) {
	why = clip(why)
	p.metrics.ObservePriceCatalogFailure()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.state.LastError = why
	res := checkResult{outcome: catalogFailed, models: len(p.catalogPrices), failure: why}
	p.log.Warnf("price catalog check failed: %s; the %d catalog prices in force are kept", why, res.models)
	if err := p.catalog.SetState(ctx, p.state); err != nil {
		return res, fmt.Errorf("app: record the price catalog failure: %w", err)
	}
	return res, nil
}

// recordSuccess stores what a successful fetch found. A store that refuses it
// makes the check a failed one: the prices and the state in force stay.
func (p *Prices) recordSuccess(ctx context.Context, fetched CatalogFetch) (checkResult, error) {
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
			return checkResult{}, ctx.Err()
		}
		p.log.Warnf("price catalog: store the check: %v", err)
		return p.recordFailure(ctx, "the catalog could not be stored")
	}
	defer p.mu.Unlock()
	p.state = state

	if !changed {
		p.metrics.SetPriceCatalog(len(p.catalogPrices), now)
		p.log.Infof("price catalog checked: unchanged, %d prices", len(p.catalogPrices))
		return checkResult{outcome: catalogUnchanged, models: len(p.catalogPrices)}, nil
	}
	// As in Replace: what was stored goes to the sink before the read-back.
	p.catalogPrices = fetched.Prices
	p.publish()
	p.metrics.SetPriceCatalog(len(fetched.Prices), now)
	p.log.Infof("price catalog updated: %d prices", len(fetched.Prices))
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
func sameRates(a, b []ModelPrice) bool {
	if len(a) != len(b) {
		return false
	}
	byKey := make(map[priceKey]ModelPrice, len(a))
	for _, mp := range a {
		mp.UpdatedAt = time.Time{}
		byKey[priceKey{mp.Provider, mp.Model}] = mp
	}
	for _, mp := range b {
		mp.UpdatedAt = time.Time{}
		if old, ok := byKey[priceKey{mp.Provider, mp.Model}]; !ok || old != mp {
			return false
		}
	}
	return true
}

type priceKey struct{ provider, model string }

// entriesLocked is the effective list: the catalog's prices, each manual price
// replacing the catalog's for its model. p.mu must be held.
func (p *Prices) entriesLocked() []PriceEntry {
	out := make([]PriceEntry, 0, len(p.catalogPrices)+len(p.manual))
	at := make(map[priceKey]int, len(p.catalogPrices))
	for _, c := range p.catalogPrices {
		at[priceKey{c.Provider, c.Model}] = len(out)
		out = append(out, PriceEntry{ModelPrice: c, Source: PriceSourceCatalog})
	}
	for _, m := range p.manual {
		e := PriceEntry{ModelPrice: m, Source: PriceSourceManual}
		if i, ok := at[priceKey{m.Provider, m.Model}]; ok {
			c := out[i].ModelPrice
			e.Catalog = &c
			out[i] = e
			continue
		}
		out = append(out, e)
	}
	slices.SortFunc(out, func(a, b PriceEntry) int {
		return cmp.Or(strings.Compare(a.Provider, b.Provider), strings.Compare(a.Model, b.Model))
	})
	return out
}

// publish hands the effective list to the sink. p.mu must be held.
func (p *Prices) publish() {
	entries := p.entriesLocked()
	prices := make([]ModelPrice, len(entries))
	for i, e := range entries {
		prices[i] = e.ModelPrice
	}
	p.sink.SetPrices(prices)
}

// listLocked is the list Get answers. p.mu must be held.
func (p *Prices) listLocked() PriceList {
	status := CatalogStatus{Enabled: p.source != nil}
	if status.Enabled {
		status.CheckedAt, status.ChangedAt = p.state.CheckedAt, p.state.ChangedAt
		status.Models, status.LastError = len(p.catalogPrices), p.state.LastError
	}
	return PriceList{Prices: p.entriesLocked(), Catalog: status}
}

func validatePrices(list []ModelPrice) error {
	seen := make(map[priceKey]struct{}, len(list))
	for i, mp := range list {
		field := func(name string) error { return &InvalidInputError{Field: fmt.Sprintf("[%d].%s", i, name)} }
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
			return &InvalidInputError{Field: fmt.Sprintf("[%d]", i)}
		}
		seen[k] = struct{}{}
	}
	return nil
}
