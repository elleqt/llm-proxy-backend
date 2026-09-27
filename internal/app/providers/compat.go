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

// Bounds on a definition: an administrator types it, a vendor lists far fewer.
const (
	maxCompatModels  = 500
	maxCompatField   = 256
	maxCompatBaseURL = 2048
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

	provider.Name = strings.TrimSpace(provider.Name)
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

	provider.BaseURL, provider.Prefix, provider.Models = baseURL, prefix, models

	account, err := s.accounts.AddCompatProvider(ctx, provider)
	if err != nil {
		return app.VendorAccount{}, fmt.Errorf("app: add openai-compatible provider: %w", err)
	}

	if err := s.audit.Record(ctx, app.AuditEvent{
		At:      s.clock.Now().UTC(),
		ActorID: actor.ID,
		Action:  "provider.compat_add",
		Target:  "provider_account/" + account.ID,
		Detail:  compatAudit(account, provider.APIKey != ""),
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

	update.BaseURL, update.Prefix, update.Models = baseURL, prefix, models

	account, err := s.accounts.UpdateCompatProvider(ctx, id, update)
	if err != nil {
		return app.VendorAccount{}, fmt.Errorf("app: update openai-compatible provider: %w", err)
	}

	detail := compatAudit(account, account.Compat != nil && account.Compat.HasAPIKey)
	detail["key_changed"] = update.APIKey != nil
	s.record(ctx, actor, "provider.compat_update", "provider_account/"+account.ID, detail)

	return s.withQuota(account), nil
}

// DiscoverCompat lists the models the vendor at baseURL serves, asked with
// apiKey or, when that is empty, the stored key of provider accountID. Nothing
// is saved.
func (s *Service) DiscoverCompat(ctx context.Context, actor identity.User, baseURL, apiKey, accountID string) (CompatDiscovery, error) {
	if err := app.RequireAdmin(actor); err != nil {
		return CompatDiscovery{}, err
	}

	base, err := validBaseURL(baseURL)
	if err != nil {
		return CompatDiscovery{}, err
	}

	ids, err := s.accounts.DiscoverModels(ctx, base, apiKey, accountID)
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
// once, aliases unique.
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

		out = append(out, model)
	}

	return base, prefix, out, nil
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
