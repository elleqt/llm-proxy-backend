package app_test

import (
	"math"
	"testing"

	"github.com/elleqt/llm-proxy-backend/internal/app"
)

var sonnetPrice = app.ModelPrice{Provider: "claude", Model: "claude-sonnetPrice-5", Input: 3, Output: 15, CacheRead: 0.3, CacheWrite: 3.75}

func near(a, b float64) bool { return math.Abs(a-b) <= 1e-12 }

func TestPriceUsagePricesEachKindAtItsRate(t *testing.T) {
	c := app.PriceUsage(app.UsageEvent{
		TokensInput: 1000, TokensOutput: 200, TokensReasoning: 100, TokensCacheRead: 2000, TokensCacheWrite: 400,
		TokensTotal: 3700,
	}, sonnetPrice, true)

	// Reasoning tokens are output tokens: they cost the output rate.
	if !near(c.InputUSD, 1000*3/1e6) || !near(c.OutputUSD, 300*15/1e6) ||
		!near(c.CacheReadUSD, 2000*0.3/1e6) || !near(c.CacheWriteUSD, 400*3.75/1e6) {
		t.Fatalf("parts = %+v", c)
	}
	if want := (1000*3 + 300*15 + 2000*0.3 + 400*3.75) / 1e6; !near(c.TotalUSD(), want) {
		t.Fatalf("total = %v, want %v", c.TotalUSD(), want)
	}
	// Reads saved 2000 × (3 - 0.3); writes cost 400 × (3.75 - 3) extra.
	if want := (2000*(3-0.3) - 400*(3.75-3)) / 1e6; !near(c.CacheSavingsUSD, want) {
		t.Fatalf("savings = %v, want %v", c.CacheSavingsUSD, want)
	}
	if !c.Priced || c.UnpricedTokens != 0 {
		t.Fatalf("priced = %v, unpriced = %d; want priced, none unpriced", c.Priced, c.UnpricedTokens)
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
	c := app.PriceUsage(app.UsageEvent{TokensInput: 100, TokensOutput: 10, TokensTotal: 150}, sonnetPrice, true)
	if c.UnpricedTokens != 40 || !near(c.TotalUSD(), (100*3+10*15)/1e6) || !c.Priced {
		t.Fatalf("cost = %+v, want the 110 classified tokens priced and 40 unpriced", c)
	}
	// Only a total: nothing to price.
	c = app.PriceUsage(app.UsageEvent{TokensTotal: 500}, sonnetPrice, true)
	if c.UnpricedTokens != 500 || c.TotalUSD() != 0 || c.Priced {
		t.Fatalf("cost = %+v, want 500 unpriced and not priced", c)
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
