package gateway

import (
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy"
	cliproxyconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// registryCatalog is a Catalog over upstream's global model registry, the one
// every gateway reads.
func registryCatalog(t *testing.T) *Catalog {
	t.Helper()

	c, err := newCatalog(cliproxy.GlobalModelRegistry())
	require.NoError(t, err, "newCatalog")

	return c
}

// awaitProviders waits until c answers want for model: upstream registers a
// running gateway's configured models after it starts serving.
func awaitProviders(t *testing.T, catalog *Catalog, model string, want []string) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)

	for {
		got := catalog.ProvidersFor(model)
		if slices.Equal(got, want) {
			return
		}

		if time.Now().After(deadline) {
			require.Failf(t, "providers never matched", "ProvidersFor(%q) = %v, want %v", model, got, want)
		}

		time.Sleep(5 * time.Millisecond)
	}
}

// registerClient registers id with upstream's global registry and removes it
// when the test ends.
func registerClient(t *testing.T, id, provider string, models ...string) {
	t.Helper()

	infos := make([]*cliproxy.ModelInfo, 0, len(models))
	for _, m := range models {
		infos = append(infos, &cliproxy.ModelInfo{ID: m})
	}

	cliproxy.GlobalModelRegistry().RegisterClient(id, provider, infos)
	t.Cleanup(func() { cliproxy.GlobalModelRegistry().UnregisterClient(id) })
}

// TestCatalogReadsTheRegistryAsItIs: the catalogue answers from upstream's own
// registrations, under policy names, the moment they change — there is no
// copy to fall behind.
func TestCatalogReadsTheRegistryAsItIs(t *testing.T) {
	catalog := registryCatalog(t)
	model := "catalog-reads-model"

	registerClient(t, "catalog-client-compat", "openai-compatible-acme", model)

	require.Equal(t, []string{"acme"}, catalog.ProvidersFor(model), "ProvidersFor(%q)", model)

	registerClient(t, "catalog-client-codex", "codex", model, "other-"+model)

	require.Equal(t, []string{"acme", "chatgpt"}, catalog.ProvidersFor(model), "ProvidersFor(%q)", model)

	cliproxy.GlobalModelRegistry().UnregisterClient("catalog-client-compat")

	require.Equal(t, []string{"chatgpt"}, catalog.ProvidersFor(model), "ProvidersFor(%q) after acme left", model)
	// Upstream looks a name up in lower case when it finds nothing as given.
	require.Equal(t, []string{"chatgpt"}, catalog.ProvidersFor("OTHER-"+model), "ProvidersFor in upper case")
}

// TestKnownModelNamesOnlyServedModels: spelling variants of a served model
// collapse into the registry's name, and a name no provider serves is not
// known, so client input cannot mint metric series.
func TestKnownModelNamesOnlyServedModels(t *testing.T) {
	catalog := registryCatalog(t)
	model := "known-model-served"
	registerClient(t, "known-model-client", "codex", model)

	for in, want := range map[string]string{model: model, "Known-Model-SERVED": model} {
		got, ok := catalog.KnownModel(in)
		require.True(t, ok, "KnownModel(%q) known", in)
		require.Equal(t, want, got, "KnownModel(%q)", in)
	}

	got, ok := catalog.KnownModel("known-model-never-served")
	require.False(t, ok, "KnownModel of an unserved model = %q", got)
}

func TestPolicyProviderNames(t *testing.T) {
	for key, want := range map[string]string{
		"codex":                  "chatgpt",
		"openai-compatible-acme": "acme",
		"openai-compatibility":   "openai-compatibility",
		"claude":                 "claude",
		// A key naming nothing after the prefix keeps its own name, so the
		// provider it stands for is still checked.
		"openai-compatible-": "openai-compatible-",
	} {
		assert.Equal(t, want, policyProvider(key), "policyProvider(%q)", key)
	}
}

// TestCompatNamesOfBuiltinProvidersAreRefused: an openai-compatibility entry
// whose policy name is a built-in provider's would share every grant written
// for that provider. Upstream keeps them apart (openai-compatible-claude is
// not claude); the policy name would not. One whose key is the bare prefix
// has no policy name of its own at all.
func TestCompatNamesOfBuiltinProvidersAreRefused(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")

	for _, name := range []string{"claude", "Claude", "chatgpt", "codex", "openai-compatible-gemini", "", "openai-compatibility", "openai-compatible-", " OpenAI-Compatible- "} {
		// A subtest per name: a wrong answer for one still checks the others.
		t.Run(strconv.Quote(name), func(t *testing.T) {
			cfg := &cliproxyconfig.Config{AuthDir: t.TempDir()}
			cfg.OpenAICompatibility = []cliproxyconfig.OpenAICompatibility{{Name: name, BaseURL: "http://" + net.JoinHostPort("", "1")}}

			_, err := New(Params{Config: cfg, ConfigPath: filepath.Join(t.TempDir(), "unused.yaml"), Resolver: wireResolver})
			require.ErrorIs(t, err, ErrCompatName, "New with an openai-compatibility entry named %q", name)
		})
	}

	srv := start(t, &cliproxyconfig.Config{})
	before := srv.gateway.CurrentConfig()
	pushed := srv.emptyPush()

	pushed.OpenAICompatibility = []cliproxyconfig.OpenAICompatibility{{Name: "claude", BaseURL: "http://" + net.JoinHostPort("", "1")}}
	err := srv.gateway.PushConfig(pushed)
	require.ErrorIs(t, err, ErrCompatName, "PushConfig with an entry named claude")

	require.Same(t, before, srv.gateway.CurrentConfig(), "CurrentConfig reports the refused configuration")
}

// TestCatalogListsModelsByProvider: Models groups what the registry serves
// under policy names, a model two providers serve under both, and reflects a
// registration at once.
func TestCatalogListsModelsByProvider(t *testing.T) {
	c := registryCatalog(t)
	registerClient(t, "models-client-claude", "claude", "models-claude-only", "models-shared")
	registerClient(t, "models-client-compat", "openai-compatible-acme", "models-shared")

	got := c.Models()
	assert.Contains(t, got["claude"], "models-claude-only", "claude serves both of its models")
	assert.Contains(t, got["claude"], "models-shared", "claude serves both of its models")
	assert.Contains(t, got["acme"], "models-shared", "acme serves only the shared model")
	assert.NotContains(t, got["acme"], "models-claude-only", "acme serves only the shared model")

	for provider, models := range got {
		assert.True(t, slices.IsSorted(models), "%s's models %v are not sorted", provider, models)
	}
}
