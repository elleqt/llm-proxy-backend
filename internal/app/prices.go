package app

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync"

	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
)

// Prices maintains the model price list the metrics cost estimate uses. The list
// lives in the database; sink holds the in-memory copy the metrics read, filled at
// boot (Load) and on every Replace, so a price change applies to usage recorded
// from then on and no request reads the database for a price.
type Prices struct {
	repo  PriceRepo
	sink  PriceSink
	audit AuditSink
	clock Clock

	// mu serialises Replace, so the sink ends up holding the list stored last.
	mu sync.Mutex
}

func NewPrices(repo PriceRepo, sink PriceSink, audit AuditSink, clock Clock) *Prices {
	return &Prices{repo: repo, sink: sink, audit: audit, clock: clock}
}

// Load hands the stored list to the sink. The composition root calls it at boot.
func (p *Prices) Load(ctx context.Context) error {
	list, err := p.repo.List(ctx)
	if err != nil {
		return fmt.Errorf("app: load prices: %w", err)
	}
	p.sink.SetPrices(list)
	return nil
}

func (p *Prices) Get(ctx context.Context, actor identity.User) ([]ModelPrice, error) {
	if err := requireAdmin(actor); err != nil {
		return nil, err
	}
	return p.repo.List(ctx)
}

// Replace makes list the whole price list. Every rate must be a finite,
// non-negative number and every (provider, model) must be named once; the first
// entry that is not is an *InvalidInputError naming it as "[index].field".
func (p *Prices) Replace(ctx context.Context, actor identity.User, list []ModelPrice) ([]ModelPrice, error) {
	if err := requireAdmin(actor); err != nil {
		return nil, err
	}
	if err := validatePrices(list); err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.clock.Now()
	if err := p.repo.Replace(ctx, list, now); err != nil {
		return nil, fmt.Errorf("app: replace prices: %w", err)
	}
	// The sink gets the list as submitted: it is what was stored, and a failed
	// read-back below must not leave the metrics pricing with the old list.
	p.sink.SetPrices(list)
	stored, err := p.repo.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("app: prices replaced; read back: %w", err)
	}
	if err := p.audit.Record(ctx, AuditEvent{
		At:      now,
		ActorID: actor.ID,
		Action:  "prices.replace",
		Target:  "model_prices",
		Detail:  map[string]any{"count": len(list)},
	}); err != nil {
		return nil, fmt.Errorf("app: prices.replace applied but not audited: %w", err)
	}
	return stored, nil
}

func validatePrices(list []ModelPrice) error {
	type key struct{ provider, model string }
	seen := make(map[key]struct{}, len(list))
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
		k := key{mp.Provider, mp.Model}
		if _, dup := seen[k]; dup {
			return &InvalidInputError{Field: fmt.Sprintf("[%d]", i)}
		}
		seen[k] = struct{}{}
	}
	return nil
}
