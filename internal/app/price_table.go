package app

import "sync/atomic"

// PriceTable is the in-memory price list: Prices fills it with the effective list
// (catalog prices under the manual overrides) at boot, on every replacement and on
// every catalog change (it is a PriceSink), and the usage sink prices every
// recorded request from it (it is a PriceLookup). A replacement swaps the whole
// table at once, so a request is priced entirely at the old list or entirely at the
// new one, and reads take no lock.
type PriceTable struct {
	table atomic.Pointer[map[priceKey]ModelPrice]
}

var (
	_ PriceSink   = (*PriceTable)(nil)
	_ PriceLookup = (*PriceTable)(nil)
)

// SetPrices replaces the table with prices.
func (t *PriceTable) SetPrices(prices []ModelPrice) {
	m := make(map[priceKey]ModelPrice, len(prices))
	for _, p := range prices {
		m[priceKey{p.Provider, p.Model}] = p
	}

	t.table.Store(&m)
}

// Price returns the price of provider's model; ok is false when there is none, or
// before the first SetPrices.
func (t *PriceTable) Price(provider, model string) (ModelPrice, bool) {
	m := t.table.Load()
	if m == nil {
		return ModelPrice{}, false
	}

	p, ok := (*m)[priceKey{provider, model}]

	return p, ok
}
