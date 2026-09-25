package http

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
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
	routes["PATCH /api/admin/providers/{accountId}"] = rt.updateProviderAccount
	routes["DELETE /api/admin/providers/{accountId}"] = rt.removeProviderAccount
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

// updateProviderAccount requires `disabled`: a body without it (or with null) must
// not read as "enable".
func (rt *router) updateProviderAccount(rw http.ResponseWriter, req *http.Request) {
	actor, _ := callerFrom(req.Context())

	var raw map[string]json.RawMessage
	if !decodeJSON(rw, req, &raw) {
		return
	}

	var body api.UpdateProviderAccountJSONBody
	if v, ok := raw["disabled"]; !ok || string(v) == "null" || json.Unmarshal(v, &body.Disabled) != nil {
		writeFieldError(rw, http.StatusUnprocessableEntity, codeInvalidInput, "disabled", "disabled must be true or false")

		return
	}

	account, err := rt.Providers.SetDisabled(req.Context(), actor.user, req.PathValue("accountId"), body.Disabled)
	if err != nil {
		rt.adminFailure(rw, req, err)

		return
	}

	writeJSON(rw, http.StatusOK, providerAccountOf(account))
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
	}
	for _, q := range account.Quota {
		out.Quota = append(out.Quota, quotaSignal{
			Window:     q.Window,
			UsedRatio:  float32(q.UsedRatio),
			ResetAt:    nonZero(q.ResetAt),
			ObservedAt: nonZero(q.ObservedAt),
		})
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
