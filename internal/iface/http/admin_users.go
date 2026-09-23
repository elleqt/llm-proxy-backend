package http

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/credentials"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/elleqt/llm-proxy-backend/internal/iface/http/api"
)

// The element types the contract declares inline, for which the generator emits
// anonymous structs. Aliases, so they stay the generated types: a contract change to
// one breaks the build here.
type (
	activityRequest = struct {
		At          time.Time  `json:"at"`
		LatencyMs   int        `json:"latencyMs"`
		Model       string     `json:"model"`
		Provider    string     `json:"provider"`
		StatusCode  int        `json:"statusCode"`
		Stream      bool       `json:"stream"`
		TokenId     *uuid.UUID `json:"tokenId,omitempty"`
		TokensTotal int        `json:"tokensTotal"`
	}
	activityAudit = struct {
		Action  string                  `json:"action"`
		ActorId *uuid.UUID              `json:"actorId,omitempty"`
		At      time.Time               `json:"at"`
		Detail  *map[string]interface{} `json:"detail,omitempty"`
		Target  *string                 `json:"target,omitempty"`
	}
	catalogProvider = struct {
		Models []string `json:"models"`
		Name   string   `json:"name"`
	}
	previewError = struct {
		Code string `json:"code"`
		Rule string `json:"rule"`
	}
	previewCovered = struct {
		Model    string `json:"model"`
		Provider string `json:"provider"`
	}
)

func (rt *router) registerAdminUsers(routes map[string]http.HandlerFunc) {
	routes["GET /api/admin/users"] = rt.listUsers
	routes["POST /api/admin/users"] = rt.createUser
	routes["GET /api/admin/users/{userId}"] = rt.getUser
	routes["PATCH /api/admin/users/{userId}"] = rt.updateUser
	routes["POST /api/admin/users/{userId}/password-reset"] = rt.resetUserPassword
	routes["POST /api/admin/users/{userId}/invitation"] = rt.renewUserInvitation
	routes["GET /api/admin/users/{userId}/tokens"] = rt.listUserTokens
	routes["POST /api/admin/users/{userId}/tokens"] = rt.issueUserToken
	routes["DELETE /api/admin/users/{userId}/tokens/{tokenId}"] = rt.revokeUserToken
	routes["GET /api/admin/users/{userId}/activity"] = rt.getUserActivity
	routes["GET /api/admin/catalog"] = rt.getCatalog
	routes["POST /api/admin/policy/preview"] = rt.previewPolicy
}

// pathID reads the UUID path value name. One that is not a UUID names nothing, so it
// is answered not_found, as an unknown id is.
func pathID(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue(name))
	if err != nil {
		writeError(w, http.StatusNotFound, codeNotFound, "no such resource")
		return uuid.Nil, false
	}
	return id, true
}

func (rt *router) listUsers(w http.ResponseWriter, r *http.Request) {
	c, _ := callerFrom(r.Context())
	views, err := rt.AdminUsers.ListUsers(r.Context(), c.user)
	if err != nil {
		rt.adminFailure(w, r, err)
		return
	}
	out := make([]api.AdminUser, 0, len(views))
	for _, v := range views {
		out = append(out, adminUserOf(v))
	}
	writeJSON(w, http.StatusOK, out)
}

// createUser is the one response that carries a new account's temporary password.
func (rt *router) createUser(w http.ResponseWriter, r *http.Request) {
	c, _ := callerFrom(r.Context())
	var body api.CreateUserRequest
	if !decodeJSON(w, r, &body) {
		return
	}
	in := app.NewUser{Kind: identity.Kind(body.Kind), DisplayName: body.DisplayName, Policy: body.Policy}
	if body.Email != nil {
		in.Email = *body.Email
	}
	if body.Role != nil {
		in.Role = identity.Role(*body.Role)
	}
	if body.SignIn != nil {
		in.SignIn = app.SignInMethod(*body.SignIn)
	}
	created, err := rt.AdminUsers.CreateUser(r.Context(), c.user, in)
	switch {
	case errors.Is(err, app.ErrConflict):
		writeError(w, http.StatusConflict, codeEmailTaken, "the email address is already taken")
		return
	case err != nil:
		rt.adminFailure(w, r, err)
		return
	}
	out := api.CreatedUser{User: adminUserOf(created.User)}
	if created.TemporaryPassword != nil {
		temp := temporaryPasswordOf(*created.TemporaryPassword)
		out.TemporaryPassword = &temp
	}
	writeJSON(w, http.StatusCreated, out)
}

func (rt *router) getUser(w http.ResponseWriter, r *http.Request) {
	c, _ := callerFrom(r.Context())
	id, ok := pathID(w, r, "userId")
	if !ok {
		return
	}
	v, err := rt.AdminUsers.GetUser(r.Context(), c.user, id)
	if err != nil {
		rt.adminFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, adminUserOf(v))
}

func (rt *router) updateUser(w http.ResponseWriter, r *http.Request) {
	c, _ := callerFrom(r.Context())
	id, ok := pathID(w, r, "userId")
	if !ok {
		return
	}
	var body api.UpdateUserRequest
	if !decodeJSON(w, r, &body) {
		return
	}
	ch := app.UserChanges{DisplayName: body.DisplayName, Policy: body.Policy}
	if body.Role != nil {
		role := identity.Role(*body.Role)
		ch.Role = &role
	}
	if body.Status != nil {
		status := identity.Status(*body.Status)
		ch.Status = &status
	}
	v, err := rt.AdminUsers.UpdateUser(r.Context(), c.user, id, ch)
	if err != nil {
		rt.adminFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, adminUserOf(v))
}

// resetUserPassword is the one response that carries the new temporary password.
func (rt *router) resetUserPassword(w http.ResponseWriter, r *http.Request) {
	c, _ := callerFrom(r.Context())
	id, ok := pathID(w, r, "userId")
	if !ok {
		return
	}
	temp, err := rt.AdminUsers.ResetPassword(r.Context(), c.user, id)
	if err != nil {
		rt.adminFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, temporaryPasswordOf(temp))
}

// renewUserInvitation answers ErrConflict with 204: the invitation's unique index
// refused this insert because a concurrent renewal for the same address committed
// first, so the account holds a fresh invitation — the state asked for.
func (rt *router) renewUserInvitation(w http.ResponseWriter, r *http.Request) {
	c, _ := callerFrom(r.Context())
	id, ok := pathID(w, r, "userId")
	if !ok {
		return
	}
	switch err := rt.AdminUsers.RenewInvitation(r.Context(), c.user, id); {
	case err == nil, errors.Is(err, app.ErrConflict):
		w.WriteHeader(http.StatusNoContent)
	default:
		rt.adminFailure(w, r, err)
	}
}

func (rt *router) listUserTokens(w http.ResponseWriter, r *http.Request) {
	c, _ := callerFrom(r.Context())
	id, ok := pathID(w, r, "userId")
	if !ok {
		return
	}
	toks, err := rt.AdminUsers.ListTokens(r.Context(), c.user, id)
	if err != nil {
		rt.adminFailure(w, r, err)
		return
	}
	out := make([]api.Token, 0, len(toks))
	for _, t := range toks {
		out = append(out, tokenOf(t))
	}
	writeJSON(w, http.StatusOK, out)
}

// issueUserToken is the one response that carries the token's secret.
func (rt *router) issueUserToken(w http.ResponseWriter, r *http.Request) {
	c, _ := callerFrom(r.Context())
	id, ok := pathID(w, r, "userId")
	if !ok {
		return
	}
	var body api.IssueTokenRequest
	if !decodeJSON(w, r, &body) {
		return
	}
	tok, secret, err := rt.AdminUsers.IssueToken(r.Context(), c.user, id, body.Label)
	if err != nil {
		rt.adminFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, api.IssuedToken{Token: tokenOf(tok), Secret: secret})
}

// revokeUserToken answers 204 for a token already revoked, the state asked for, as
// the cabinet does.
func (rt *router) revokeUserToken(w http.ResponseWriter, r *http.Request) {
	c, _ := callerFrom(r.Context())
	userID, ok := pathID(w, r, "userId")
	if !ok {
		return
	}
	tokenID, ok := pathID(w, r, "tokenId")
	if !ok {
		return
	}
	switch err := rt.AdminUsers.RevokeToken(r.Context(), c.user, userID, tokenID); {
	case err == nil, errors.Is(err, credentials.ErrAlreadyRevoked):
		w.WriteHeader(http.StatusNoContent)
	default:
		rt.adminFailure(w, r, err)
	}
}

func (rt *router) getUserActivity(w http.ResponseWriter, r *http.Request) {
	c, _ := callerFrom(r.Context())
	id, ok := pathID(w, r, "userId")
	if !ok {
		return
	}
	limit := app.DefaultActivityLimit
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > app.MaxActivityLimit {
			writeFieldError(w, http.StatusUnprocessableEntity, codeInvalidInput, "limit",
				"limit must be an integer from 1 to "+strconv.Itoa(app.MaxActivityLimit))
			return
		}
		limit = n
	}
	act, err := rt.AdminUsers.Activity(r.Context(), c.user, id, limit)
	if err != nil {
		rt.adminFailure(w, r, err)
		return
	}
	out := api.Activity{
		Requests: make([]activityRequest, 0, len(act.Requests)),
		Audit:    make([]activityAudit, 0, len(act.Audit)),
	}
	for _, e := range act.Requests {
		out.Requests = append(out.Requests, activityRequest{
			At:          e.At.UTC(),
			TokenId:     idPtr(e.TokenID),
			Provider:    e.Provider,
			Model:       e.Model,
			Stream:      e.Stream,
			StatusCode:  requestStatus(e),
			TokensTotal: int(e.TokensTotal),
			LatencyMs:   e.LatencyMS,
		})
	}
	for _, e := range act.Audit {
		a := activityAudit{At: e.At.UTC(), Action: e.Action, ActorId: idPtr(e.ActorID)}
		if e.Target != "" {
			target := e.Target
			a.Target = &target
		}
		if len(e.Detail) > 0 {
			detail := e.Detail
			a.Detail = &detail
		}
		out.Audit = append(out.Audit, a)
	}
	writeJSON(w, http.StatusOK, out)
}

// requestStatus is the status a proxied request ended with. The ledger records the
// vendor's status only for a failure — upstream records none on success — so a
// served request stored as 0 answered 200.
func requestStatus(e app.UsageEvent) int {
	if e.StatusCode == 0 && !e.Failed {
		return http.StatusOK
	}
	return e.StatusCode
}

func (rt *router) getCatalog(w http.ResponseWriter, r *http.Request) {
	c, _ := callerFrom(r.Context())
	providers, err := rt.AdminUsers.Catalog(c.user)
	if err != nil {
		rt.adminFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, catalogOf(providers))
}

// catalogOf writes providers as the contract's Catalog; a provider's models are []
// rather than null.
func catalogOf(providers []app.CatalogProvider) api.Catalog {
	out := api.Catalog{Providers: make([]catalogProvider, 0, len(providers))}
	for _, p := range providers {
		models := p.Models
		if models == nil {
			models = []string{}
		}
		out.Providers = append(out.Providers, catalogProvider{Name: p.Name, Models: models})
	}
	return out
}

func (rt *router) previewPolicy(w http.ResponseWriter, r *http.Request) {
	c, _ := callerFrom(r.Context())
	var body api.PolicyPreviewRequest
	if !decodeJSON(w, r, &body) {
		return
	}
	preview, err := rt.AdminUsers.PolicyPreview(c.user, body.Rules)
	if err != nil {
		rt.adminFailure(w, r, err)
		return
	}
	out := api.PolicyPreview{
		Errors:  make([]previewError, 0, len(preview.Invalid)),
		Covered: make([]previewCovered, 0, len(preview.Covered)),
	}
	for _, rule := range preview.Invalid {
		out.Errors = append(out.Errors, previewError{Rule: rule, Code: codeInvalidRule})
	}
	for _, m := range preview.Covered {
		out.Covered = append(out.Covered, previewCovered{Provider: m.Provider, Model: m.Model})
	}
	writeJSON(w, http.StatusOK, out)
}

// adminUserOf describes an account as the contract's AdminUser. It carries no
// credential: no password, hash or token.
func adminUserOf(v app.UserView) api.AdminUser {
	u := v.User
	signIn := make([]api.AdminUserSignIn, 0, len(v.SignIn))
	for _, m := range v.SignIn {
		signIn = append(signIn, api.AdminUserSignIn(m))
	}
	out := api.AdminUser{
		Id:                  u.ID,
		Kind:                api.Kind(u.Kind),
		DisplayName:         u.DisplayName,
		Role:                api.Role(u.Role),
		Status:              api.Status(u.Status),
		Policy:              policyOf(u.Policy),
		PolicySource:        api.PolicySource(u.PolicySource),
		MustChangePassword:  u.MustChangePassword,
		SignIn:              signIn,
		InvitationExpiresAt: utcPtr(v.InvitationExpiresAt),
		LastSeenAt:          utcPtr(u.LastSeenAt),
		CreatedAt:           u.CreatedAt.UTC(),
	}
	if u.Email != "" {
		email := u.Email
		out.Email = &email
	}
	return out
}

func temporaryPasswordOf(t app.TemporaryPassword) api.TemporaryPassword {
	return api.TemporaryPassword{Password: t.Password, ExpiresAt: t.ExpiresAt.UTC()}
}

// idPtr is id, or nil for the zero id, which the ledger and the audit log store for
// "none" (a request without a token, an event without an actor).
func idPtr(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}
