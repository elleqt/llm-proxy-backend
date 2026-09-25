package app

import (
	"slices"
	"strings"

	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
)

// ModelsService shows the cabinet which models a user's keys may use.
type ModelsService struct {
	catalog ModelCatalog
}

func NewModelsService(catalog ModelCatalog) *ModelsService { return &ModelsService{catalog: catalog} }

// Allowed is today's catalogue as u's keys see it: every model u's policy admits
// by access.Policy.Admits — the rule the gateway filters GET /v1/models by, so a
// model two providers serve is admitted on both or on neither — under each
// provider serving it. Providers come in name order with their models sorted, and
// a provider with no admitted model is left out.
//
// The policy is the one user carries: the session middleware loads the user on every
// request, as the gate loads a key's owner, so an administrator's edit shows on
// the next call.
func (s *ModelsService) Allowed(user identity.User) []CatalogProvider {
	out := []CatalogProvider{}
	if len(user.Policy) == 0 {
		return out
	}

	admitted := map[string]bool{}

	for name, models := range s.catalog.Models() {
		var allowed []string

		for _, model := range models {
			ok, seen := admitted[model]
			if !seen {
				ok = user.Policy.Admits(s.catalog, model)
				admitted[model] = ok
			}

			if ok {
				allowed = append(allowed, model)
			}
		}

		if len(allowed) == 0 {
			continue
		}

		slices.Sort(allowed)
		out = append(out, CatalogProvider{Name: name, Models: allowed})
	}

	slices.SortFunc(out, func(a, b CatalogProvider) int { return strings.Compare(a.Name, b.Name) })

	return out
}
