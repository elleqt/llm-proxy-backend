package metrics

import (
	"sync/atomic"

	"github.com/elleqt/llm-proxy-backend/internal/app"
)

type priceKey struct{ provider, model string }

// PriceTable is the in-memory price list: app.Prices fills it with the effective
// list (catalog prices under the manual overrides) at boot, on every replacement
// and on every catalog change (it is an app.PriceSink), and ObserveUsage reads it
// (it is a PriceLookup). A replacement swaps the whole table at once, so a request
// is priced entirely at the old list or entirely at the new one, and reads take
// no lock.
type PriceTable struct {
	table atomic.Pointer[map[priceKey]app.ModelPrice]
}

var (
	_ app.PriceSink = (*PriceTable)(nil)
	_ PriceLookup   = (*PriceTable)(nil)
)

// SetPrices replaces the table with prices.
func (t *PriceTable) SetPrices(prices []app.ModelPrice) {
	m := make(map[priceKey]app.ModelPrice, len(prices))
	for _, p := range prices {
		m[priceKey{p.Provider, p.Model}] = p
	}
	t.table.Store(&m)
}

// Price returns the price of provider's model; ok is false when there is none, or
// before the first SetPrices.
func (t *PriceTable) Price(provider, model string) (app.ModelPrice, bool) {
	m := t.table.Load()
	if m == nil {
		return app.ModelPrice{}, false
	}
	p, ok := (*m)[priceKey{provider, model}]
	return p, ok
}
