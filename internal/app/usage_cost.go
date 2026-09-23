package app

// UsageCost is what a request's tokens cost at list prices, in US dollars: an
// estimate of work done, not a bill. Summed over requests it is the cost of all of
// them.
type UsageCost struct {
	// InputUSD prices the input tokens neither read from nor written to the prompt
	// cache at the input rate; OutputUSD the output tokens, reasoning included, at
	// the output rate; CacheReadUSD and CacheWriteUSD the cache reads and writes at
	// their own rates.
	InputUSD, OutputUSD, CacheReadUSD, CacheWriteUSD float64
	// CacheSavingsUSD is the net effect of prompt caching against paying the input
	// rate for every input token: cache reads at (input - cache-read rate) less
	// cache writes at (cache-write - input rate). Negative when writes cost more
	// than reads saved.
	CacheSavingsUSD float64
	// UnpricedTokens are the tokens no rate applied to: all of them for a model
	// without a price, and those the vendor did not classify for one with a price.
	// They are in no USD figure.
	UnpricedTokens int64
	// Priced is whether any token was priced: false for a model without a price and
	// for a request with no classified token.
	Priced bool
}

// TotalUSD is the sum of the four priced parts.
func (c UsageCost) TotalUSD() float64 {
	return c.InputUSD + c.OutputUSD + c.CacheReadUSD + c.CacheWriteUSD
}

// Add adds o to c; the sum is priced when either is.
func (c *UsageCost) Add(o UsageCost) {
	c.InputUSD += o.InputUSD
	c.OutputUSD += o.OutputUSD
	c.CacheReadUSD += o.CacheReadUSD
	c.CacheWriteUSD += o.CacheWriteUSD
	c.CacheSavingsUSD += o.CacheSavingsUSD
	c.UnpricedTokens += o.UnpricedTokens
	c.Priced = c.Priced || o.Priced
}

// PriceUsage prices ev's tokens at p; ok is false when the model has no price. The
// token kinds partition the request (the usage sink maps upstream's canonical
// breakdown that way), so each token is priced once: reasoning tokens are output
// tokens and cost the output rate. Tokens the vendor could not classify
// (TokensTotal above the sum of the kinds) have no rate and are unpriced even for a
// priced model; without a price every token is. A negative count counts as zero.
//
// The migration that added the ledger's cost columns backfilled them with the same
// arithmetic in SQL (0003_usage_cost.sql): a change here must change it there.
func PriceUsage(ev UsageEvent, p ModelPrice, ok bool) UsageCost {
	in := positive(ev.TokensInput)
	out := positive(ev.TokensOutput) + positive(ev.TokensReasoning)
	cacheRead, cacheWrite := positive(ev.TokensCacheRead), positive(ev.TokensCacheWrite)
	classified := in + out + cacheRead + cacheWrite
	unclassified := max(positive(ev.TokensTotal)-classified, 0)
	if !ok || classified == 0 {
		if !ok {
			unclassified += classified
		}
		return UsageCost{UnpricedTokens: unclassified}
	}
	fin, fout, fread, fwrite := float64(in), float64(out), float64(cacheRead), float64(cacheWrite)
	return UsageCost{
		InputUSD:        fin * p.Input / 1e6,
		OutputUSD:       fout * p.Output / 1e6,
		CacheReadUSD:    fread * p.CacheRead / 1e6,
		CacheWriteUSD:   fwrite * p.CacheWrite / 1e6,
		CacheSavingsUSD: (fread*(p.Input-p.CacheRead) - fwrite*(p.CacheWrite-p.Input)) / 1e6,
		UnpricedTokens:  unclassified,
		Priced:          true,
	}
}

func positive(n int64) int64 { return max(n, 0) }
