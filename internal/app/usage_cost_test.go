package app_test

import (
	"math"
	"testing"

	"github.com/elleqt/llm-proxy-backend/internal/app"
)

var sonnetPrice = app.ModelPrice{Provider: "claude", Model: "claude-sonnetPrice-5", Input: 3, Output: 15, CacheRead: 0.3, CacheWrite: 3.75}

func near(a, b float64) bool { return math.Abs(a-b) <= 1e-12 }

func TestPriceUsagePricesEachKindAtItsRate(t *testing.T) {
	cost := app.PriceUsage(app.UsageEvent{
		TokensInput: 1000, TokensOutput: 200, TokensReasoning: 100, TokensCacheRead: 2000, TokensCacheWrite: 400,
		TokensTotal: 3700,
	}, sonnetPrice, true)

	// Reasoning tokens are output tokens: they cost the output rate.
	if !near(cost.InputUSD, 1000*3/1e6) || !near(cost.OutputUSD, 300*15/1e6) ||
		!near(cost.CacheReadUSD, 2000*0.3/1e6) || !near(cost.CacheWriteUSD, 400*3.75/1e6) {
		t.Fatalf("parts = %+v", cost)
	}

	if want := (1000*3 + 300*15 + 2000*0.3 + 400*3.75) / 1e6; !near(cost.TotalUSD(), want) {
		t.Fatalf("total = %v, want %v", cost.TotalUSD(), want)
	}
	// Reads saved 2000 × (3 - 0.3); writes cost 400 × (3.75 - 3) extra.
	if want := (2000*(3-0.3) - 400*(3.75-3)) / 1e6; !near(cost.CacheSavingsUSD, want) {
		t.Fatalf("savings = %v, want %v", cost.CacheSavingsUSD, want)
	}

	if !cost.Priced || cost.UnpricedTokens != 0 {
		t.Fatalf("priced = %v, unpriced = %d; want priced, none unpriced", cost.Priced, cost.UnpricedTokens)
	}
}

func TestPriceUsageSavingsNegativeWhenWritesDominate(t *testing.T) {
	c := app.PriceUsage(app.UsageEvent{TokensInput: 10, TokensCacheRead: 100, TokensCacheWrite: 10_000, TokensTotal: 10_110}, sonnetPrice, true)
	if want := (100*(3-0.3) - 10_000*(3.75-3)) / 1e6; !near(c.CacheSavingsUSD, want) || c.CacheSavingsUSD >= 0 {
		t.Fatalf("savings = %v, want %v (negative)", c.CacheSavingsUSD, want)
	}
}

func TestPriceUsageLeavesUnclassifiedTokensUnpriced(t *testing.T) {
	// The kinds cover 110 of 150 tokens: 40 have no rate.
	cost := app.PriceUsage(app.UsageEvent{TokensInput: 100, TokensOutput: 10, TokensTotal: 150}, sonnetPrice, true)
	if cost.UnpricedTokens != 40 || !near(cost.TotalUSD(), (100*3+10*15)/1e6) || !cost.Priced {
		t.Fatalf("cost = %+v, want the 110 classified tokens priced and 40 unpriced", cost)
	}
	// Only a total: nothing to price.
	cost = app.PriceUsage(app.UsageEvent{TokensTotal: 500}, sonnetPrice, true)
	if cost.UnpricedTokens != 500 || cost.TotalUSD() != 0 || cost.Priced {
		t.Fatalf("cost = %+v, want 500 unpriced and not priced", cost)
	}
}

func TestPriceUsageWithoutAPriceLeavesEveryTokenUnpriced(t *testing.T) {
	c := app.PriceUsage(app.UsageEvent{
		TokensInput: 10, TokensOutput: 5, TokensReasoning: 2, TokensCacheRead: 3, TokensCacheWrite: 1, TokensTotal: 30,
	}, app.ModelPrice{}, false)
	// 21 classified plus 9 unclassified.
	if c.UnpricedTokens != 30 || c.Priced || c != (app.UsageCost{UnpricedTokens: 30}) {
		t.Fatalf("cost = %+v, want all 30 tokens unpriced and nothing else", c)
	}
}

// A price without a cache-write rate (OpenAI bills written tokens as input) prices
// cache writes at the input rate, and writing is neither a premium nor a saving.
func TestPriceUsageZeroCacheWriteRateMeansInputRate(t *testing.T) {
	gpt := app.ModelPrice{Provider: "chatgpt", Model: "gpt-6", Input: 1.25, Output: 10, CacheRead: 0.125}

	cost := app.PriceUsage(app.UsageEvent{TokensInput: 100, TokensCacheRead: 400, TokensCacheWrite: 1000, TokensTotal: 1500}, gpt, true)
	if !near(cost.CacheWriteUSD, 1000*1.25/1e6) {
		t.Fatalf("cache write = %v, want %v (the input rate)", cost.CacheWriteUSD, 1000*1.25/1e6)
	}

	if want := 400 * (1.25 - 0.125) / 1e6; !near(cost.CacheSavingsUSD, want) {
		t.Fatalf("savings = %v, want %v (the reads only)", cost.CacheSavingsUSD, want)
	}
}
