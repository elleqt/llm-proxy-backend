package models_test

import (
	"slices"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/app/mocks"
	appmodels "github.com/elleqt/llm-proxy-backend/internal/app/models"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/elleqt/llm-proxy-backend/internal/domain/limits"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// fakeCatalog is a fixed catalogue: each provider and the models it serves.
type fakeCatalog map[string][]string

func (c fakeCatalog) Models() map[string][]string { return c }

func (c fakeCatalog) ProvidersFor(model string) []string {
	var out []string

	for provider, models := range c {
		if slices.Contains(models, model) {
			out = append(out, provider)
		}
	}

	slices.Sort(out)

	return out
}

func (c fakeCatalog) KnownModel(model string) (string, bool) {
	return model, len(c.ProvidersFor(model)) > 0
}

var _ app.ModelCatalog = fakeCatalog(nil)

var twoProviders = fakeCatalog{
	"claude":  {"sonnet", "shared", "opus"},
	"chatgpt": {"o3", "gpt-5-mini", "shared", "gpt-5"},
	"gemini":  {"pro"},
}

// unlimited is a spend gate under which no account has limits in force.
func unlimited(t *testing.T) *mocks.SpendGate {
	t.Helper()

	gate := mocks.NewSpendGate(t)
	gate.EXPECT().Effective(mock.Anything).Return(limits.Set{}).Maybe()

	return gate
}

// A user sees each model their policy admits under every provider serving it,
// providers in name order and models sorted; a model two providers serve is listed
// only when both are allowed, as GET /v1/models does, and a provider left with
// nothing is absent.
func TestAllowedModelsFollowThePolicy(t *testing.T) {
	svc := appmodels.New(twoProviders, &app.PriceTable{}, unlimited(t))
	for _, tc := range []struct {
		rules []string
		want  []app.CatalogProvider
	}{
		{[]string{"claude:*", "chatgpt:gpt-5*"}, []app.CatalogProvider{
			{Name: "chatgpt", Models: []string{"gpt-5", "gpt-5-mini"}},
			{Name: "claude", Models: []string{"opus", "sonnet"}},
		}},
		{[]string{"claude:*", "chatgpt:shared"}, []app.CatalogProvider{
			{Name: "chatgpt", Models: []string{"shared"}},
			{Name: "claude", Models: []string{"opus", "shared", "sonnet"}},
		}},
		{nil, []app.CatalogProvider{}},
	} {
		got := svc.Allowed(identity.User{Policy: mustPolicy(t, tc.rules...)})
		assert.Equal(t, tc.want, got, "policy %v", tc.rules)
	}
}

// Under spend limits, a model the policy admits but that lacks a price on a
// provider serving it is listed as unpriced, not allowed: the gate would refuse
// it. A provider left with only unpriced models still appears. Without limits in
// force the same model is allowed like any other.
func TestAllowedModelsSplitsOutUnpricedUnderLimits(t *testing.T) {
	catalog := fakeCatalog{"vendora": {"unpriced", "priced"}, "vendorb": {"lonely"}}
	prices := &app.PriceTable{}
	prices.SetPrices([]app.ModelPrice{{Provider: "vendora", Model: "priced", Input: 1, Output: 1}})

	own := &limits.Set{{Window: 2 * time.Hour, AmountUSD: 10}}
	user := identity.User{Policy: mustPolicy(t, "*:*"), SpendLimits: own}

	limited := mocks.NewSpendGate(t)
	limited.EXPECT().Effective(own).Return(*own)
	assert.Equal(t, []app.CatalogProvider{
		{Name: "vendora", Models: []string{"priced"}, Unpriced: []string{"unpriced"}},
		{Name: "vendorb", Unpriced: []string{"lonely"}},
	}, appmodels.New(catalog, prices, limited).Allowed(user), "limited")

	free := mocks.NewSpendGate(t)
	free.EXPECT().Effective(own).Return(limits.Set{})
	assert.Equal(t, []app.CatalogProvider{
		{Name: "vendora", Models: []string{"priced", "unpriced"}},
		{Name: "vendorb", Models: []string{"lonely"}},
	}, appmodels.New(catalog, prices, free).Allowed(user), "unlimited")
}
