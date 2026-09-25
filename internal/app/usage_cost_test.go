package app_test

import (
	"testing"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/stretchr/testify/require"
)

var sonnetPrice = app.ModelPrice{Provider: "claude", Model: "claude-sonnetPrice-5", Input: 3, Output: 15, CacheRead: 0.3, CacheWrite: 3.75}

// costEpsilon absorbs float rounding in the per-million arithmetic.
const costEpsilon = 1e-12

func TestPriceUsagePricesEachKindAtItsRate(t *testing.T) {
	cost := app.PriceUsage(app.UsageEvent{
		TokensInput: 1000, TokensOutput: 200, TokensReasoning: 100, TokensCacheRead: 2000, TokensCacheWrite: 400,
		TokensTotal: 3700,
	}, sonnetPrice, true)

	// Reasoning tokens are output tokens: they cost the output rate.
	require.InDelta(t, 1000*3/1e6, cost.InputUSD, costEpsilon, "input part")
	require.InDelta(t, 300*15/1e6, cost.OutputUSD, costEpsilon, "output part")
	require.InDelta(t, 2000*0.3/1e6, cost.CacheReadUSD, costEpsilon, "cache read part")
	require.InDelta(t, 400*3.75/1e6, cost.CacheWriteUSD, costEpsilon, "cache write part")

	require.InDelta(t, (1000*3+300*15+2000*0.3+400*3.75)/1e6, cost.TotalUSD(), costEpsilon, "total")
	// Reads saved 2000 × (3 - 0.3); writes cost 400 × (3.75 - 3) extra.
	require.InDelta(t, (2000*(3-0.3)-400*(3.75-3))/1e6, cost.CacheSavingsUSD, costEpsilon, "savings")

	require.True(t, cost.Priced, "priced")
	require.Zero(t, cost.UnpricedTokens, "unpriced tokens")
}

func TestPriceUsageSavingsNegativeWhenWritesDominate(t *testing.T) {
	c := app.PriceUsage(app.UsageEvent{TokensInput: 10, TokensCacheRead: 100, TokensCacheWrite: 10_000, TokensTotal: 10_110}, sonnetPrice, true)
	require.InDelta(t, (100*(3-0.3)-10_000*(3.75-3))/1e6, c.CacheSavingsUSD, costEpsilon, "savings")
	require.Negative(t, c.CacheSavingsUSD, "savings")
}

func TestPriceUsageLeavesUnclassifiedTokensUnpriced(t *testing.T) {
	// The kinds cover 110 of 150 tokens: 40 have no rate.
	cost := app.PriceUsage(app.UsageEvent{TokensInput: 100, TokensOutput: 10, TokensTotal: 150}, sonnetPrice, true)
	require.Equal(t, int64(40), cost.UnpricedTokens, "unpriced tokens")
	require.InDelta(t, (100*3+10*15)/1e6, cost.TotalUSD(), costEpsilon, "total of the 110 classified tokens")
	require.True(t, cost.Priced, "priced")
	// Only a total: nothing to price.
	cost = app.PriceUsage(app.UsageEvent{TokensTotal: 500}, sonnetPrice, true)
	require.Equal(t, int64(500), cost.UnpricedTokens, "unpriced tokens")
	require.Zero(t, cost.TotalUSD(), "total")
	require.False(t, cost.Priced, "priced")
}

func TestPriceUsageWithoutAPriceLeavesEveryTokenUnpriced(t *testing.T) {
	c := app.PriceUsage(app.UsageEvent{
		TokensInput: 10, TokensOutput: 5, TokensReasoning: 2, TokensCacheRead: 3, TokensCacheWrite: 1, TokensTotal: 30,
	}, app.ModelPrice{}, false)
	// 21 classified plus 9 unclassified.
	require.Equal(t, app.UsageCost{UnpricedTokens: 30}, c, "all 30 tokens unpriced and nothing else")
}

// A price without a cache-write rate (OpenAI bills written tokens as input) prices
// cache writes at the input rate, and writing is neither a premium nor a saving.
func TestPriceUsageZeroCacheWriteRateMeansInputRate(t *testing.T) {
	gpt := app.ModelPrice{Provider: "chatgpt", Model: "gpt-6", Input: 1.25, Output: 10, CacheRead: 0.125}

	cost := app.PriceUsage(app.UsageEvent{TokensInput: 100, TokensCacheRead: 400, TokensCacheWrite: 1000, TokensTotal: 1500}, gpt, true)
	require.InDelta(t, 1000*1.25/1e6, cost.CacheWriteUSD, costEpsilon, "cache write at the input rate")
	require.InDelta(t, 400*(1.25-0.125)/1e6, cost.CacheSavingsUSD, costEpsilon, "savings from the reads only")
}
