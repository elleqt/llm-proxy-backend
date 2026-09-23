package gateway

import (
	"errors"
	"net"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy"
	cliproxyconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

// registryCatalog is a Catalog over upstream's global model registry, the one
// every gateway reads.
func registryCatalog(t *testing.T) *Catalog {
	t.Helper()
	c, err := newCatalog(cliproxy.GlobalModelRegistry())
	if err != nil {
		t.Fatalf("newCatalog: %v", err)
	}
	return c
}

// awaitProviders waits until c answers want for model: upstream registers a
// running gateway's configured models after it starts serving.
func awaitProviders(t *testing.T, c *Catalog, model string, want []string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		got := c.ProvidersFor(model)
		if slices.Equal(got, want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("ProvidersFor(%q) = %v, want %v", model, got, want)
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
	c := registryCatalog(t)
	model := "catalog-reads-model"

	registerClient(t, "catalog-client-compat", "openai-compatible-acme", model)
	if got := c.ProvidersFor(model); !slices.Equal(got, []string{"acme"}) {
		t.Fatalf("ProvidersFor(%q) = %v, want [acme]", model, got)
	}
	registerClient(t, "catalog-client-codex", "codex", model, "other-"+model)
	if got := c.ProvidersFor(model); !slices.Equal(got, []string{"acme", "chatgpt"}) {
		t.Fatalf("ProvidersFor(%q) = %v, want [acme chatgpt]", model, got)
	}
	cliproxy.GlobalModelRegistry().UnregisterClient("catalog-client-compat")
	if got := c.ProvidersFor(model); !slices.Equal(got, []string{"chatgpt"}) {
		t.Fatalf("ProvidersFor(%q) = %v after acme left, want [chatgpt]", model, got)
	}
	// Upstream looks a name up in lower case when it finds nothing as given.
	if got := c.ProvidersFor("OTHER-" + model); !slices.Equal(got, []string{"chatgpt"}) {
		t.Fatalf("ProvidersFor in upper case = %v, want [chatgpt]", got)
	}
}

// TestKnownModelNamesOnlyServedModels: spelling variants of a served model
// collapse into the registry's name, and a name no provider serves is not
// known, so client input cannot mint metric series.
func TestKnownModelNamesOnlyServedModels(t *testing.T) {
	c := registryCatalog(t)
	model := "known-model-served"
	registerClient(t, "known-model-client", "codex", model)
	for in, want := range map[string]string{model: model, "Known-Model-SERVED": model} {
		if got, ok := c.KnownModel(in); !ok || got != want {
			t.Fatalf("KnownModel(%q) = %q, %t; want %q, true", in, got, ok, want)
		}
	}
	if got, ok := c.KnownModel("known-model-never-served"); ok {
		t.Fatalf("KnownModel of an unserved model = %q, true; want false", got)
	}
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
		if got := policyProvider(key); got != want {
			t.Errorf("policyProvider(%q) = %q, want %q", key, got, want)
		}
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
		cfg := &cliproxyconfig.Config{AuthDir: t.TempDir()}
		cfg.OpenAICompatibility = []cliproxyconfig.OpenAICompatibility{{Name: name, BaseURL: "http://" + net.JoinHostPort("", "1")}}
		_, err := New(Params{Config: cfg, ConfigPath: filepath.Join(t.TempDir(), "unused.yaml"), Resolver: wireResolver})
		if !errors.Is(err, ErrCompatName) {
			t.Errorf("New with an openai-compatibility entry named %q = %v, want ErrCompatName", name, err)
		}
	}

	r := start(t, &cliproxyconfig.Config{})
	before := r.gateway.CurrentConfig()
	pushed := r.emptyPush()
	pushed.OpenAICompatibility = []cliproxyconfig.OpenAICompatibility{{Name: "claude", BaseURL: "http://" + net.JoinHostPort("", "1")}}
	if err := r.gateway.PushConfig(pushed); !errors.Is(err, ErrCompatName) {
		t.Fatalf("PushConfig with an entry named claude = %v, want ErrCompatName", err)
	}
	if r.gateway.CurrentConfig() != before {
		t.Fatal("CurrentConfig reports the refused configuration")
	}
}

// TestCatalogListsModelsByProvider: Models groups what the registry serves
// under policy names, a model two providers serve under both, and reflects a
// registration at once.
func TestCatalogListsModelsByProvider(t *testing.T) {
	c := registryCatalog(t)
	registerClient(t, "models-client-claude", "claude", "models-claude-only", "models-shared")
	registerClient(t, "models-client-compat", "openai-compatible-acme", "models-shared")

	got := c.Models()
	if !slices.Contains(got["claude"], "models-claude-only") || !slices.Contains(got["claude"], "models-shared") {
		t.Errorf("claude serves %v, want both of its models", got["claude"])
	}
	if !slices.Contains(got["acme"], "models-shared") || slices.Contains(got["acme"], "models-claude-only") {
		t.Errorf("acme serves %v, want only the shared model", got["acme"])
	}
	for provider, models := range got {
		if !slices.IsSorted(models) {
			t.Errorf("%s's models %v are not sorted", provider, models)
		}
	}
}
