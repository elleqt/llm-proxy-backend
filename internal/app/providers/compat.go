package providers

import (
	"cmp"
	"context"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
)

// compatName is what an OpenAI-compatible provider may be called: its policy
// name, so lower case and free of the rule syntax's ":" and "*".
var compatName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// reasoningLevel is what a reasoning level may be, lower-cased: a word a vendor
// takes as a reasoning_effort value, never something carrying JSON or spaces.
var reasoningLevel = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// Bounds on a definition: an administrator types it, a vendor lists far fewer.
const (
	maxCompatModels    = 500
	maxCompatField     = 256
	maxCompatBaseURL   = 2048
	maxReasoningLevels = 16
)

// fieldModels is the request field, and audit key, of a definition's models.
const fieldModels = "models"

// CompatDiscovery is what a vendor's model listing offers: the ids it serves,
// and for each one some other provider already serves, those providers' names.
// A pooled model is admitted only to users granted it on every provider
// serving it, which the form warns about.
type CompatDiscovery struct {
	Models    []string
	Conflicts map[string][]string
}

// CreateCompat adds the OpenAI-compatible provider p and returns its account.
// Like a completed login, a creation whose audit record fails is withdrawn.
func (s *Service) CreateCompat(ctx context.Context, actor identity.User, provider app.CompatProvider) (app.VendorAccount, error) {
	if err := app.RequireAdmin(actor); err != nil {
		return app.VendorAccount{}, err
	}

	// Lower case, as upstream matches names case-insensitively: "DeepSeek" is
	// "deepseek", and cannot be added beside it.
	provider.Name = strings.ToLower(strings.TrimSpace(provider.Name))
	if !compatName.MatchString(provider.Name) {
		return app.VendorAccount{}, &app.InvalidInputError{Field: "name"}
	}

	baseURL, prefix, models, err := validCompat(provider.BaseURL, provider.Prefix, provider.Models)
	if err != nil {
		return app.VendorAccount{}, err
	}

	if len(provider.APIKey) > maxCompatBaseURL {
		return app.VendorAccount{}, &app.InvalidInputError{Field: "apiKey"}
	}

	if provider.Proxy, err = validProxy(provider.Proxy); err != nil {
		return app.VendorAccount{}, err
	}

	provider.BaseURL, provider.Prefix, provider.Models = baseURL, prefix, models

	account, err := s.accounts.AddCompatProvider(ctx, provider)
	if err != nil {
		return app.VendorAccount{}, fmt.Errorf("app: add openai-compatible provider: %w", err)
	}

	// The mode is the request's choice, not the gateway's echo of it.
	detail := compatAudit(account, provider.APIKey != "")
	detail["proxy_mode"] = proxyMode(provider.Proxy)

	if err := s.audit.Record(ctx, app.AuditEvent{
		At:      s.clock.Now().UTC(),
		ActorID: actor.ID,
		Action:  "provider.compat_add",
		Target:  "provider_account/" + account.ID,
		Detail:  detail,
	}); err != nil {
		return app.VendorAccount{}, s.withdraw(ctx, account, err)
	}

	return account, nil
}

// UpdateCompat replaces the definition of the OpenAI-compatible provider id.
func (s *Service) UpdateCompat(
	ctx context.Context, actor identity.User, id string, update app.CompatProviderUpdate,
) (app.VendorAccount, error) {
	if err := app.RequireAdmin(actor); err != nil {
		return app.VendorAccount{}, err
	}

	baseURL, prefix, models, err := validCompat(update.BaseURL, update.Prefix, update.Models)
	if err != nil {
		return app.VendorAccount{}, err
	}

	if update.APIKey != nil && len(*update.APIKey) > maxCompatBaseURL {
		return app.VendorAccount{}, &app.InvalidInputError{Field: "apiKey"}
	}

	if update.Proxy, err = validProxy(update.Proxy); err != nil {
		return app.VendorAccount{}, err
	}

	update.BaseURL, update.Prefix, update.Models = baseURL, prefix, models

	account, err := s.accounts.UpdateCompatProvider(ctx, id, update)
	if err != nil {
		return app.VendorAccount{}, fmt.Errorf("app: update openai-compatible provider: %w", err)
	}

	detail := compatAudit(account, account.Compat != nil && account.Compat.HasAPIKey)
	detail["key_changed"] = update.APIKey != nil

	detail["proxy_changed"] = update.Proxy != nil
	if update.Proxy != nil {
		detail["proxy_mode"] = proxyMode(update.Proxy)
	}

	s.record(ctx, actor, "provider.compat_update", "provider_account/"+account.ID, detail)

	return s.withQuota(account), nil
}

// CompatDefaults is the default set of reasoning levels, the ones a model
// without its own list follows, as a copy the caller may change.
func (s *Service) CompatDefaults(actor identity.User) ([]string, error) {
	if err := app.RequireAdmin(actor); err != nil {
		return nil, err
	}

	return slices.Clone(app.DefaultReasoningLevels), nil
}

// DiscoverCompat lists the models the vendor at baseURL serves, asked with
// apiKey or, when that is empty, the stored key of provider accountID, and
// sent through proxy, else the provider's own, else the global proxy-url.
// Nothing is saved.
func (s *Service) DiscoverCompat(
	ctx context.Context, actor identity.User, baseURL, apiKey, accountID string, proxy *app.ProxyChoice,
) (CompatDiscovery, error) {
	if err := app.RequireAdmin(actor); err != nil {
		return CompatDiscovery{}, err
	}

	base, err := validBaseURL(baseURL)
	if err != nil {
		return CompatDiscovery{}, err
	}

	if proxy, err = validProxy(proxy); err != nil {
		return CompatDiscovery{}, err
	}

	ids, err := s.accounts.DiscoverModels(ctx, base, apiKey, accountID, proxy)
	if err != nil {
		return CompatDiscovery{}, fmt.Errorf("app: discover models: %w", err)
	}

	self := ""

	for _, a := range s.accounts.Accounts() {
		if a.ID == accountID && a.Compat != nil {
			self = a.Compat.Name
		}
	}

	servedBy := make(map[string][]string)

	for provider, models := range s.catalog.Models() {
		if provider == self {
			continue
		}

		for _, m := range models {
			servedBy[m] = append(servedBy[m], provider)
		}
	}

	conflicts := make(map[string][]string)

	for _, id := range ids {
		if providers := servedBy[id]; len(providers) > 0 {
			slices.Sort(providers)
			conflicts[id] = providers
		}
	}

	return CompatDiscovery{Models: ids, Conflicts: conflicts}, nil
}

// validCompat checks and normalises the editable part of a definition: the
// base URL, a prefix without slashes, and at least one model, each named
// once, aliases unique, reasoning levels valid.
func validCompat(baseURL, prefix string, models []app.CompatModel) (string, string, []app.CompatModel, error) {
	base, err := validBaseURL(baseURL)
	if err != nil {
		return "", "", nil, err
	}

	prefix = strings.TrimSpace(prefix)
	if len(prefix) > maxCompatField || strings.ContainsAny(prefix, "/ :*") {
		return "", "", nil, &app.InvalidInputError{Field: "prefix"}
	}

	if len(models) == 0 || len(models) > maxCompatModels {
		return "", "", nil, &app.InvalidInputError{Field: fieldModels}
	}

	out := make([]app.CompatModel, 0, len(models))
	served := make(map[string]struct{}, len(models))

	for _, model := range models {
		model.Name, model.Alias = strings.TrimSpace(model.Name), strings.TrimSpace(model.Alias)
		if model.Name == "" || len(model.Name) > maxCompatField || len(model.Alias) > maxCompatField {
			return "", "", nil, &app.InvalidInputError{Field: fieldModels}
		}

		// The name clients request it by: two entries must not claim one.
		requested := cmp.Or(model.Alias, model.Name)
		if _, dup := served[requested]; dup {
			return "", "", nil, &app.InvalidInputError{Field: fieldModels}
		}

		served[requested] = struct{}{}

		if model.ReasoningLevels, err = validReasoningLevels(model.ReasoningLevels); err != nil {
			return "", "", nil, err
		}

		out = append(out, model)
	}

	return base, prefix, out, nil
}

// canonicalReasoningLevels is the order known levels are kept in, ahead of a
// model's own values.
var canonicalReasoningLevels = []string{"none", "minimal", "low", "medium", "high", "xhigh", "max", "auto"}

// validReasoningLevels trims and lower-cases a model's own list of reasoning
// levels; nil stays nil, as it follows the default set. A present list must
// name at least one level: upstream takes an empty one for a model that does
// not reason and strips the parameter.
//
// Known levels come first in canonical order, own values after them in the
// order given: when `none` is off a list, upstream sends the first listed
// level for a `none` request, so a caller's ["high","low"] would turn `none`
// into `high`.
func validReasoningLevels(levels []string) ([]string, error) {
	if levels == nil {
		return nil, nil
	}

	if len(levels) == 0 || len(levels) > maxReasoningLevels {
		return nil, &app.InvalidInputError{Field: fieldModels}
	}

	out := make([]string, 0, len(levels))

	for _, level := range levels {
		level = strings.ToLower(strings.TrimSpace(level))
		if !reasoningLevel.MatchString(level) || slices.Contains(out, level) {
			return nil, &app.InvalidInputError{Field: fieldModels}
		}

		out = append(out, level)
	}

	slices.SortStableFunc(out, func(a, b string) int {
		return reasoningRank(a) - reasoningRank(b)
	})

	return out, nil
}

// reasoningRank is a level's place in canonicalReasoningLevels; own values
// share the last place, so a stable sort keeps their order.
func reasoningRank(level string) int {
	if i := slices.Index(canonicalReasoningLevels, level); i >= 0 {
		return i
	}

	return len(canonicalReasoningLevels)
}

// validBaseURL accepts an absolute http or https URL without credentials, a
// query or a fragment, and returns it without a trailing slash. Loopback and
// private hosts are allowed: a vendor on the same machine is a real case, and
// only an administrator gets here.
func validBaseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)

	u, err := url.Parse(raw)
	if err != nil || len(raw) > maxCompatBaseURL || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", &app.InvalidInputError{Field: "baseURL"}
	}

	return strings.TrimRight(raw, "/"), nil
}

// compatAudit is an OpenAI-compatible provider's audit detail: its id, name,
// base URL and whether it has a key, never the key.
func compatAudit(account app.VendorAccount, hasKey bool) map[string]any {
	detail := map[string]any{auditAccountID: account.ID, auditProvider: account.Provider, "has_api_key": hasKey}
	if account.Compat != nil {
		detail["base_url"] = account.Compat.BaseURL
		detail[fieldModels] = len(account.Compat.Models)
	}

	return detail
}

// validProxy checks an optional proxy choice; nil stays nil.
func validProxy(p *app.ProxyChoice) (*app.ProxyChoice, error) {
	if p == nil {
		return nil, nil //nolint:nilnil // nil is "not given", a valid answer.
	}

	valid, err := p.Validate()
	if err != nil {
		return nil, err
	}

	return &valid, nil
}

// proxyMode is the mode a choice sets, for an audit detail; nil is inherit.
func proxyMode(p *app.ProxyChoice) string {
	if p == nil {
		return string(app.ProxyInherit)
	}

	return string(p.Mode)
}
