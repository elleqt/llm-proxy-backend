package app_test

import (
	"slices"
	"testing"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/stretchr/testify/assert"
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

var _ app.ModelCatalog = fakeCatalog(nil)

var twoProviders = fakeCatalog{
	"claude":  {"sonnet", "shared", "opus"},
	"chatgpt": {"o3", "gpt-5-mini", "shared", "gpt-5"},
	"gemini":  {"pro"},
}

// A user sees each model their policy admits under every provider serving it,
// providers in name order and models sorted; a model two providers serve is listed
// only when both are allowed, as GET /v1/models does, and a provider left with
// nothing is absent.
func TestAllowedModelsFollowThePolicy(t *testing.T) {
	svc := app.NewModelsService(twoProviders)
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
