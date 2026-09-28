package app

import "github.com/elleqt/llm-proxy-backend/internal/domain/access"

// PricingCatalog is what pricing reads of the model catalogue: which providers
// serve a model, and the name the registry serves it under.
type PricingCatalog interface {
	// ProvidersFor returns every provider serving model now, under the names
	// prices are keyed by; nil if none does.
	ProvidersFor(model string) []string
	// KnownModel is the name the registry serves model under, which prices are
	// keyed by: as given, else in lower case; false when no provider serves it.
	KnownModel(model string) (string, bool)
}

// PricedName resolves requested as the policy gate routes it (access.Routed) to
// the name the registry serves it under, which prices are keyed by, with the
// providers serving it; ok is false when no provider serves it. The gate checks
// a limited account's request by this name and the usage sink prices an alias
// by it, so whatever the gate admits the sink can price.
func PricedName(catalog PricingCatalog, requested string) (string, []string, bool) {
	model, providers := access.Routed(catalog, requested)
	if len(providers) == 0 {
		return "", nil, false
	}

	name, ok := catalog.KnownModel(model)
	if !ok {
		return "", nil, false
	}

	return name, providers, true
}

// PricedEverywhere reports whether requested has a price on every provider
// serving it. Upstream may route to any of them, so one unpriced provider fails
// the model, as Policy.Covers fails it.
func PricedEverywhere(catalog PricingCatalog, prices PriceLookup, requested string) bool {
	name, providers, ok := PricedName(catalog, requested)
	if !ok {
		return false
	}

	for _, provider := range providers {
		if _, priced := prices.Price(provider, name); !priced {
			return false
		}
	}

	return true
}
