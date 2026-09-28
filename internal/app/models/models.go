// Package models shows the cabinet which models a user's keys may use.
package models

import (
	"slices"
	"strings"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
)

// Service shows the cabinet which models a user's keys may use.
type Service struct {
	catalog app.ModelCatalog
	prices  app.PriceLookup
	limits  app.SpendGate
}

// New returns the service over the live catalogue, the price list in force and
// the spend gate the proxied API applies, so it judges a model as the gate does.
func New(catalog app.ModelCatalog, prices app.PriceLookup, limits app.SpendGate) *Service {
	return &Service{catalog: catalog, prices: prices, limits: limits}
}

// verdict is what Allowed makes of one model for one user.
type verdict uint8

const (
	denied verdict = iota
	allowed
	// unpriced: the policy admits it, but the user's spend limits are in force and
	// the model lacks a price on a provider serving it, so the gate refuses it.
	unpriced
)

// Allowed is today's catalogue as u's keys see it: every model u's policy admits
// by access.Policy.Admits — the rule the gateway filters GET /v1/models by, so a
// model two providers serve is admitted on both or on neither — under each
// provider serving it. While u has spend limits in force, an admitted model
// without a price on every provider serving it (app.PricedEverywhere, the gate's
// rule) is listed in Unpriced instead of Models. Providers come in name order
// with both lists sorted, and a provider with neither is left out.
//
// The policy and spend limits are the ones user carries: the session middleware
// loads the user on every request, as the gate loads a key's owner, so an
// administrator's edit shows on the next call.
func (s *Service) Allowed(user identity.User) []app.CatalogProvider {
	out := []app.CatalogProvider{}
	if len(user.Policy) == 0 {
		return out
	}

	limited := len(s.limits.Effective(user.SpendLimits)) > 0
	verdicts := map[string]verdict{}

	for name, models := range s.catalog.Models() {
		var ok, blocked []string

		for _, model := range models {
			judged, seen := verdicts[model]
			if !seen {
				judged = s.judge(user, limited, model)
				verdicts[model] = judged
			}

			switch judged {
			case allowed:
				ok = append(ok, model)
			case unpriced:
				blocked = append(blocked, model)
			case denied:
			}
		}

		if len(ok) == 0 && len(blocked) == 0 {
			continue
		}

		slices.Sort(ok)
		slices.Sort(blocked)
		out = append(out, app.CatalogProvider{Name: name, Models: ok, Unpriced: blocked})
	}

	slices.SortFunc(out, func(a, b app.CatalogProvider) int { return strings.Compare(a.Name, b.Name) })

	return out
}

// judge decides one model for user, limited or not.
func (s *Service) judge(user identity.User, limited bool, model string) verdict {
	switch {
	case !user.Policy.Admits(s.catalog, model):
		return denied
	case limited && !app.PricedEverywhere(s.catalog, s.prices, model):
		return unpriced
	default:
		return allowed
	}
}
