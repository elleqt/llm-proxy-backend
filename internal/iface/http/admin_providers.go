package http

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/app/providers"
	"github.com/elleqt/llm-proxy-backend/internal/iface/http/api"
)

// completeLoginWriteTime is how long POST /api/admin/providers/login/complete may
// take to answer. The gateway waits up to a minute for upstream to exchange the code
// with the vendor; the router's server-wide write timeout is far shorter, and this
// one route is given more rather than every route.
const completeLoginWriteTime = 90 * time.Second

// quotaSignal names the element type the contract declares inline in
// ProviderAccount.quota; an alias, so it stays the generated type.
type quotaSignal = struct {
	ObservedAt *time.Time `json:"observedAt,omitempty"`
	ResetAt    *time.Time `json:"resetAt,omitempty"`
	UsedRatio  float32    `json:"usedRatio"`
	Window     string     `json:"window"`
}

func (rt *router) registerAdminProviders(routes map[string]http.HandlerFunc) {
	routes["GET /api/admin/providers"] = rt.listProviderAccounts
	routes["POST /api/admin/providers/login/start"] = rt.startProviderLogin
	routes["POST /api/admin/providers/login/complete"] = rt.completeProviderLogin
	routes["POST /api/admin/providers/compat"] = rt.createCompatProvider
	routes["PUT /api/admin/providers/compat/{accountId}"] = rt.updateCompatProvider
	routes["POST /api/admin/providers/compat/discover"] = rt.discoverCompatModels
	routes["GET /api/admin/providers/compat/defaults"] = rt.getCompatDefaults
	routes["PATCH /api/admin/providers/{accountId}"] = rt.updateProviderAccount
	routes["DELETE /api/admin/providers/{accountId}"] = rt.removeProviderAccount
}

// createCompatProvider takes the provider's API key and never answers with it.
func (rt *router) createCompatProvider(rw http.ResponseWriter, req *http.Request) {
	actor, _ := callerFrom(req.Context())

	var body api.CompatProviderRequest
	if !decodeJSON(rw, req, &body) {
		return
	}

	account, err := rt.Providers.CreateCompat(req.Context(), actor.user, app.CompatProvider{
		Name: body.Name, BaseURL: body.BaseURL, APIKey: deref(body.ApiKey), Prefix: deref(body.Prefix),
		Models: compatModelsIn(body.Models), Proxy: proxyIn(body.Proxy),
	})
	if errors.Is(err, app.ErrConflict) {
		writeFieldError(rw, http.StatusConflict, codeConflict, "name", "a provider of that name exists")

		return
	}

	if err != nil {
		rt.adminFailure(rw, req, err)

		return
	}

	writeJSON(rw, http.StatusCreated, providerAccountOf(account))
}

func (rt *router) updateCompatProvider(rw http.ResponseWriter, req *http.Request) {
	actor, _ := callerFrom(req.Context())

	var body api.CompatProviderUpdate
	if !decodeJSON(rw, req, &body) {
		return
	}

	update := app.CompatProviderUpdate{
		BaseURL: body.BaseURL, APIKey: body.ApiKey, Prefix: deref(body.Prefix), Models: compatModelsIn(body.Models),
		Proxy: proxyIn(body.Proxy),
	}
	if update.APIKey == nil && body.ClearApiKey != nil && *body.ClearApiKey {
		cleared := ""
		update.APIKey = &cleared
	}

	account, err := rt.Providers.UpdateCompat(req.Context(), actor.user, req.PathValue("accountId"), update)
	if err != nil {
		rt.adminFailure(rw, req, err)

		return
	}

	writeJSON(rw, http.StatusOK, providerAccountOf(account))
}

func (rt *router) discoverCompatModels(rw http.ResponseWriter, req *http.Request) {
	actor, _ := callerFrom(req.Context())

	var body api.CompatDiscoverRequest
	if !decodeJSON(rw, req, &body) {
		return
	}

	found, err := rt.Providers.DiscoverCompat(req.Context(), actor.user, body.BaseURL, deref(body.ApiKey), deref(body.AccountId),
		proxyIn(body.Proxy))
	if err != nil {
		rt.adminFailure(rw, req, err)

		return
	}

	writeJSON(rw, http.StatusOK, api.CompatDiscoverResult{Models: found.Models, Conflicts: found.Conflicts})
}

// getCompatDefaults answers the reasoning levels a model without its own list passes.
func (rt *router) getCompatDefaults(rw http.ResponseWriter, req *http.Request) {
	actor, _ := callerFrom(req.Context())

	levels, err := rt.Providers.CompatDefaults(actor.user)
	if err != nil {
		rt.adminFailure(rw, req, err)

		return
	}

	writeJSON(rw, http.StatusOK, api.CompatDefaults{ReasoningLevels: levels})
}

// compatModelsIn keeps an absent reasoningLevels nil: the model takes the default set.
func compatModelsIn(in []api.CompatModel) []app.CompatModel {
	out := make([]app.CompatModel, 0, len(in))
	for _, m := range in {
		model := app.CompatModel{Name: m.Name, Alias: deref(m.Alias)}
		if m.ReasoningLevels != nil {
			model.ReasoningLevels = *m.ReasoningLevels
		}

		out = append(out, model)
	}

	return out
}

func deref(s *string) string {
	if s == nil {
		return ""
	}

	return *s
}

func (rt *router) listProviderAccounts(rw http.ResponseWriter, req *http.Request) {
	c, _ := callerFrom(req.Context())

	accounts, err := rt.Providers.List(req.Context(), c.user)
	if err != nil {
		rt.adminFailure(rw, req, err)

		return
	}

	out := make([]api.ProviderAccount, 0, len(accounts))
	for _, a := range accounts {
		out = append(out, providerAccountOf(a))
	}

	writeJSON(rw, http.StatusOK, out)
}

// startProviderLogin is the one response that carries the login's authorisation URL.
func (rt *router) startProviderLogin(rw http.ResponseWriter, req *http.Request) {
	actor, _ := callerFrom(req.Context())

	var body api.ProviderLoginStartRequest
	if !decodeJSON(rw, req, &body) {
		return
	}

	login, err := rt.Providers.StartLogin(req.Context(), actor.user, string(body.Provider))
	if err != nil {
		rt.adminFailure(rw, req, err)

		return
	}

	writeJSON(rw, http.StatusCreated, api.ProviderLoginSession{
		SessionId: login.SessionID, AuthURL: login.AuthURL, ExpiresAt: login.ExpiresAt.UTC(),
	})
}

// completeProviderLogin hands the pasted callback URL, which carries the vendor's
// authorisation code, to the gateway. It never appears in a response or a log line
// written here: every refusal is a fixed message.
func (rt *router) completeProviderLogin(rw http.ResponseWriter, req *http.Request) {
	if err := http.NewResponseController(rw).SetWriteDeadline(time.Now().Add(completeLoginWriteTime)); err != nil &&
		!errors.Is(err, http.ErrNotSupported) {
		rt.Log.Warn("extending the write deadline failed",
			slog.String("method", req.Method), slog.String("path", req.URL.Path), slog.Any("err", err))
	}

	actor, _ := callerFrom(req.Context())

	var body api.ProviderLoginCompleteRequest
	if !decodeJSON(rw, req, &body) {
		return
	}

	account, err := rt.Providers.CompleteLogin(req.Context(), actor.user, body.SessionId, body.CallbackURL)
	if err != nil {
		rt.adminFailure(rw, req, err)

		return
	}

	writeJSON(rw, http.StatusCreated, providerAccountOf(account))
}

// updateProviderAccount changes the fields the body names and keeps the rest.
// A body naming none is refused by the service, so a malformed or empty patch
// never reads as "enable".
func (rt *router) updateProviderAccount(rw http.ResponseWriter, req *http.Request) {
	actor, _ := callerFrom(req.Context())

	var body api.UpdateProviderAccountJSONBody
	if !decodeJSON(rw, req, &body) {
		return
	}

	account, err := rt.Providers.Update(req.Context(), actor.user, req.PathValue("accountId"), providers.AccountChange{
		Disabled: body.Disabled, Proxy: proxyIn(body.Proxy),
	})
	if err != nil {
		rt.adminFailure(rw, req, err)

		return
	}

	writeJSON(rw, http.StatusOK, providerAccountOf(account))
}

// proxyIn is a proxy choice from the contract; nil when the request names none.
func proxyIn(in *api.AccountProxyInput) *app.ProxyChoice {
	if in == nil {
		return nil
	}

	return &app.ProxyChoice{Mode: app.ProxyMode(in.Mode), URL: deref(in.Url)}
}

// proxyOut is an account's proxy as the contract shows it: the URL and the
// credentials flag only for `custom`, and the URL already stripped of userinfo.
func proxyOut(p app.AccountProxy) api.AccountProxy {
	out := api.AccountProxy{Mode: api.AccountProxyMode(p.Mode)}
	if p.Mode == app.ProxyCustom {
		out.Url = nonEmpty(p.URL)
		out.HasCredentials = &p.HasCredentials
	}

	return out
}

func (rt *router) removeProviderAccount(rw http.ResponseWriter, req *http.Request) {
	c, _ := callerFrom(req.Context())
	if err := rt.Providers.Remove(req.Context(), c.user, req.PathValue("accountId")); err != nil {
		rt.adminFailure(rw, req, err)

		return
	}

	rw.WriteHeader(http.StatusNoContent)
}

// providerAccountOf describes a vendor account as the contract's ProviderAccount. It
// carries no credential: the gateway hands over none.
func providerAccountOf(account app.VendorAccount) api.ProviderAccount {
	out := api.ProviderAccount{
		Id:              account.ID,
		Provider:        account.Provider,
		Status:          account.Status,
		Disabled:        account.Disabled,
		Label:           nonEmpty(account.Label),
		Email:           nonEmpty(account.Email),
		LastError:       nonEmpty(account.LastError),
		LastRefreshedAt: nonZero(account.LastRefreshedAt),
		Quota:           make([]quotaSignal, 0, len(account.Quota)),
		Proxy:           proxyOut(account.Proxy),
	}
	for _, q := range account.Quota {
		out.Quota = append(out.Quota, quotaSignal{
			Window:     q.Window,
			UsedRatio:  float32(q.UsedRatio),
			ResetAt:    nonZero(q.ResetAt),
			ObservedAt: nonZero(q.ObservedAt),
		})
	}

	if compat := account.Compat; compat != nil {
		models := make([]api.CompatModel, 0, len(compat.Models))
		for _, m := range compat.Models {
			model := api.CompatModel{Name: m.Name, Alias: nonEmpty(m.Alias)}
			if m.ReasoningLevels != nil { // only a model's own list
				model.ReasoningLevels = &m.ReasoningLevels
			}

			models = append(models, model)
		}

		out.Compat = &api.CompatProviderDetails{
			Name: compat.Name, BaseURL: compat.BaseURL, Prefix: nonEmpty(compat.Prefix), HasApiKey: compat.HasAPIKey, Models: models,
		}
	}

	return out
}

func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}

	return &s
}

// nonZero is t in UTC, or nil for the zero time, which the gateway uses for "never".
func nonZero(at time.Time) *time.Time {
	if at.IsZero() {
		return nil
	}

	at = at.UTC()

	return &at
}
