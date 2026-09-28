package app_test

import (
	"testing"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/app/mocks"
	"github.com/stretchr/testify/require"
)

func priceTable(prices ...app.ModelPrice) *app.PriceTable {
	table := &app.PriceTable{}
	table.SetPrices(prices)

	return table
}

// A request is priced under the name the registry serves its routed model by:
// the thinking suffix goes (access.Routed) and the case is the registry's, so a
// price keyed by that name covers the request as the client spelled it.
func TestPricedNameResolvesAsTheGateRoutes(t *testing.T) {
	catalog := mocks.NewModelCatalog(t)
	catalog.EXPECT().ProvidersFor("Claude-X").Return([]string{"claude"})
	catalog.EXPECT().KnownModel("Claude-X").Return("claude-x", true)

	name, providers, ok := app.PricedName(catalog, "Claude-X(high)")
	require.True(t, ok, "served")
	require.Equal(t, "claude-x", name, "registry name")
	require.Equal(t, []string{"claude"}, providers, "providers")

	prices := priceTable(app.ModelPrice{Provider: "claude", Model: "claude-x", Input: 1, Output: 2})
	require.True(t, app.PricedEverywhere(catalog, prices, "Claude-X(high)"), "priced on its one provider")
}

// Upstream may route a model to any provider serving it, so a price on one of two
// leaves it unpriced.
func TestPricedEverywhereNeedsAPriceOnEveryProvider(t *testing.T) {
	catalog := mocks.NewModelCatalog(t)
	catalog.EXPECT().ProvidersFor("shared").Return([]string{"a", "b"})
	catalog.EXPECT().KnownModel("shared").Return("shared", true)

	prices := priceTable(app.ModelPrice{Provider: "a", Model: "shared", Input: 1, Output: 2})
	require.False(t, app.PricedEverywhere(catalog, prices, "shared"), "priced on a only")
}

// A model no provider serves has no price, and its name is never canonicalised:
// the strict mock fails the test on a KnownModel call.
func TestPricedEverywhereRefusesAnUnservedModel(t *testing.T) {
	catalog := mocks.NewModelCatalog(t)
	catalog.EXPECT().ProvidersFor("ghost").Return(nil)
	catalog.EXPECT().ProvidersFor("ghost(high)").Return(nil)

	_, _, ok := app.PricedName(catalog, "ghost(high)")
	require.False(t, ok, "served")
	require.False(t, app.PricedEverywhere(catalog, priceTable(), "ghost(high)"), "priced")
}
