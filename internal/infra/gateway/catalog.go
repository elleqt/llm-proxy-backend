package gateway

import (
	"errors"
	"slices"
	"strings"

	"github.com/elleqt/llm-proxy-backend/internal/app"
)

// Catalog answers which providers serve a model, under the provider names
// policies use. It reads upstream's global model registry at the moment it is
// asked, through the call upstream itself routes a request by
// (internal/util/provider.go GetProviderName → ModelRegistry.GetModelProviders),
// so the gate and upstream's routing see the same registrations: a provider
// upstream could route a model to is a provider the gate has checked.
//
// The SDK's ModelRegistry interface does not declare GetModelProviders, but
// the registry cliproxy.GlobalModelRegistry returns (*registry.ModelRegistry,
// v7.3.15) exports it. newCatalog reaches it through an interface assertion
// and fails, so New refuses to start, if an upgrade removes it.
//
// It is also the admin screens' catalogue (app.ModelCatalog): Models lists
// what the same registry serves, grouped through ProvidersFor, so a policy
// preview and the gate read one source.
type Catalog struct {
	registry modelRegistry
}

var _ app.ModelCatalog = (*Catalog)(nil)

// modelRegistry is what the catalogue reads of upstream's registry.
type modelRegistry interface {
	// GetModelProviders returns the upstream keys of the providers
	// registered for exactly modelID.
	GetModelProviders(modelID string) []string
	// GetAvailableModels lists the models available now, in the format of a
	// handler type; every entry of the "openai" format has an "id".
	GetAvailableModels(handlerType string) []map[string]any
}

// ErrModelRegistry reports an upstream model registry that does not say which
// providers serve a model: no policy could then be applied to a model request.
var ErrModelRegistry = errors.New("gateway: upstream's model registry does not report a model's providers")

// newCatalog reads registry, which must report a model's providers.
func newCatalog(registry any) (*Catalog, error) {
	r, ok := registry.(modelRegistry)
	if !ok {
		return nil, ErrModelRegistry
	}
	return &Catalog{registry: r}, nil
}

// ProvidersFor returns the policy names of every provider serving model,
// sorted. Like upstream's GetProviderName it looks model up exactly, then in
// lower case if that finds nothing. Nil means no provider serves it.
func (c *Catalog) ProvidersFor(model string) []string {
	keys := c.registry.GetModelProviders(model)
	if len(keys) == 0 {
		if lower := strings.ToLower(model); lower != model {
			keys = c.registry.GetModelProviders(lower)
		}
	}
	if len(keys) == 0 {
		return nil
	}
	names := make([]string, 0, len(keys))
	for _, key := range keys {
		if name := policyProvider(key); name != "" && !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

// KnownModel is the metrics canonicaliser (metrics.WithKnownModel): the name
// the registry serves model under — as given, else in lower case, the lookup
// ProvidersFor makes — and false when no provider serves it, so a string a
// client sent never becomes a label value of its own.
func (c *Catalog) KnownModel(model string) (string, bool) {
	if len(c.registry.GetModelProviders(model)) > 0 {
		return model, true
	}
	if lower := strings.ToLower(model); lower != model && len(c.registry.GetModelProviders(lower)) > 0 {
		return lower, true
	}
	return "", false
}

// Models maps each provider, by policy name, to the models it serves now,
// sorted: every model upstream lists as available (the registry's own
// availability, which leaves out a model whose every client is suspended),
// under each of its providers.
func (c *Catalog) Models() map[string][]string {
	out := make(map[string][]string)
	for _, entry := range c.registry.GetAvailableModels("openai") {
		id, _ := entry["id"].(string)
		if id == "" {
			continue
		}
		for _, provider := range c.ProvidersFor(id) {
			if !slices.Contains(out[provider], id) {
				out[provider] = append(out[provider], id)
			}
		}
	}
	for _, models := range out {
		slices.Sort(models)
	}
	return out
}

// openAICompatiblePrefix starts the upstream key of every named
// openai-compatibility provider (internal/util/provider.go
// OpenAICompatibleProviderKey).
const openAICompatiblePrefix = "openai-compatible-"

// policyProvider is the one naming layer between upstream provider keys and
// the provider names policies are written in: codex is "chatgpt", a named
// openai-compatibility provider is its configured name, and every other key is
// its own name. Registry keys are already lower case. A key that would map to
// no name ("openai-compatible-" alone) keeps its own, so every provider
// serving a model is named and checked; admit refuses such an entry anyway.
func policyProvider(key string) string {
	if key == "codex" {
		return "chatgpt"
	}
	if name := strings.TrimPrefix(key, openAICompatiblePrefix); name != "" {
		return name
	}
	return key
}

// compatProviderKey is the upstream key of the openai-compatibility entry
// called name (internal/util/provider.go OpenAICompatibleProviderKey): the
// name lower-cased and prefixed, unless it is empty, "openai-compatibility"
// or already prefixed.
func compatProviderKey(name string) string {
	key := strings.ToLower(strings.TrimSpace(name))
	switch {
	case key == "":
		return "openai-compatibility"
	case key == "openai-compatibility" || strings.HasPrefix(key, openAICompatiblePrefix):
		return key
	default:
		return openAICompatiblePrefix + key
	}
}

// compatNameRefused reports whether an openai-compatibility entry called name
// must be refused: its key names nothing after the prefix, so it has no
// policy name of its own, or its policy name is reserved.
func compatNameRefused(name string) bool {
	key := compatProviderKey(name)
	return strings.TrimPrefix(key, openAICompatiblePrefix) == "" || reservedProviderName(policyProvider(key))
}

// builtinProviders are the upstream keys of the providers upstream serves
// itself (v7.3.15: sdk/cliproxy/service_executors.go baselineExecutorAuths,
// the model registration switch in sdk/cliproxy/service_models.go, and the
// "home" provider of home mode). A policy name any of them has, or the key
// itself, is reserved: an openai-compatibility entry going by it would share
// every grant written for the built-in provider.
var builtinProviders = []string{
	"codex", "claude", "gemini", "gemini-interactions", "vertex", "aistudio",
	"antigravity", "kimi", "kimi-ai", "kimi.ai", "kimi.com", "xai", "devin",
	"meta", "home", "openai-compatibility",
}

// reservedProviderName reports whether name, a policy name, is one a built-in
// provider goes by or its upstream key.
func reservedProviderName(name string) bool {
	for _, key := range builtinProviders {
		if name == key || name == policyProvider(key) {
			return true
		}
	}
	return false
}
