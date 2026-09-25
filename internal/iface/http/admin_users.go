package http

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/app/adminusers"
	"github.com/elleqt/llm-proxy-backend/internal/domain/credentials"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/elleqt/llm-proxy-backend/internal/iface/http/api"
	"github.com/google/uuid"
)

// The element types the contract declares inline, for which the generator emits
// anonymous structs. Aliases, so they stay the generated types: a contract change to
// one breaks the build here.
type (
	activityRequest = struct {
		At          time.Time  `json:"at"`
		CostUSD     *float64   `json:"costUSD,omitempty"`
		LatencyMs   int        `json:"latencyMs"`
		Model       string     `json:"model"`
		Provider    string     `json:"provider"`
		StatusCode  int        `json:"statusCode"`
		Stream      bool       `json:"stream"`
		TokenId     *uuid.UUID `json:"tokenId,omitempty"` //nolint:revive // must match the generated api struct field for the alias
		TokensTotal int        `json:"tokensTotal"`
	}
	activityAudit = struct {
		Action  string          `json:"action"`
		ActorId *uuid.UUID      `json:"actorId,omitempty"` //nolint:revive // must match the generated api struct field for the alias
		At      time.Time       `json:"at"`
		Detail  *map[string]any `json:"detail,omitempty"`
		Target  *string         `json:"target,omitempty"`
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

func (rt *router) listUsers(rw http.ResponseWriter, req *http.Request) {
	c, _ := callerFrom(req.Context())

	views, err := rt.AdminUsers.ListUsers(req.Context(), c.user)
	if err != nil {
		rt.adminFailure(rw, req, err)

		return
	}

	out := make([]api.AdminUser, 0, len(views))
	for _, v := range views {
		out = append(out, adminUserOf(v))
	}

	writeJSON(rw, http.StatusOK, out)
}

// createUser is the one response that carries a new account's temporary password.
func (rt *router) createUser(rw http.ResponseWriter, req *http.Request) {
	actor, _ := callerFrom(req.Context())

	var body api.CreateUserRequest
	if !decodeJSON(rw, req, &body) {
		return
	}

	in := adminusers.NewUser{Kind: identity.Kind(body.Kind), DisplayName: body.DisplayName, Policy: body.Policy}
	if body.Email != nil {
		in.Email = *body.Email
	}

	if body.Role != nil {
		in.Role = identity.Role(*body.Role)
	}

	if body.SignIn != nil {
		in.SignIn = app.SignInMethod(*body.SignIn)
	}

	created, err := rt.AdminUsers.CreateUser(req.Context(), actor.user, in)
	switch {
	case errors.Is(err, app.ErrConflict):
		writeError(rw, http.StatusConflict, codeEmailTaken, "the email address is already taken")

		return
	case err != nil:
		rt.adminFailure(rw, req, err)

		return
	}

	out := api.CreatedUser{User: adminUserOf(created.User)}
	if created.TemporaryPassword != nil {
		temp := temporaryPasswordOf(*created.TemporaryPassword)
		out.TemporaryPassword = &temp
	}

	writeJSON(rw, http.StatusCreated, out)
}

func (rt *router) getUser(rw http.ResponseWriter, req *http.Request) {
	actor, _ := callerFrom(req.Context())

	id, ok := pathID(rw, req, "userId")
	if !ok {
		return
	}

	view, err := rt.AdminUsers.GetUser(req.Context(), actor.user, id)
	if err != nil {
		rt.adminFailure(rw, req, err)

		return
	}

	writeJSON(rw, http.StatusOK, adminUserOf(view))
}

func (rt *router) updateUser(rw http.ResponseWriter, req *http.Request) {
	actor, _ := callerFrom(req.Context())

	id, ok := pathID(rw, req, "userId")
	if !ok {
		return
	}

	var body api.UpdateUserRequest
	if !decodeJSON(rw, req, &body) {
		return
	}

	ch := adminusers.UserChanges{DisplayName: body.DisplayName, Policy: body.Policy}
	if body.Role != nil {
		role := identity.Role(*body.Role)
		ch.Role = &role
	}

	if body.Status != nil {
		status := identity.Status(*body.Status)
		ch.Status = &status
	}

	view, err := rt.AdminUsers.UpdateUser(req.Context(), actor.user, id, ch)
	if err != nil {
		rt.adminFailure(rw, req, err)

		return
	}

	writeJSON(rw, http.StatusOK, adminUserOf(view))
}

// resetUserPassword is the one response that carries the new temporary password.
func (rt *router) resetUserPassword(rw http.ResponseWriter, req *http.Request) {
	actor, _ := callerFrom(req.Context())

	id, ok := pathID(rw, req, "userId")
	if !ok {
		return
	}

	temp, err := rt.AdminUsers.ResetPassword(req.Context(), actor.user, id)
	if err != nil {
		rt.adminFailure(rw, req, err)

		return
	}

	writeJSON(rw, http.StatusOK, temporaryPasswordOf(temp))
}

// renewUserInvitation answers ErrConflict with 204: the invitation's unique index
// refused this insert because a concurrent renewal for the same address committed
// first, so the account holds a fresh invitation — the state asked for.
func (rt *router) renewUserInvitation(rw http.ResponseWriter, req *http.Request) {
	actor, _ := callerFrom(req.Context())

	id, ok := pathID(rw, req, "userId")
	if !ok {
		return
	}

	switch err := rt.AdminUsers.RenewInvitation(req.Context(), actor.user, id); {
	case err == nil, errors.Is(err, app.ErrConflict):
		rw.WriteHeader(http.StatusNoContent)
	default:
		rt.adminFailure(rw, req, err)
	}
}

func (rt *router) listUserTokens(rw http.ResponseWriter, req *http.Request) {
	actor, _ := callerFrom(req.Context())

	id, ok := pathID(rw, req, "userId")
	if !ok {
		return
	}

	toks, err := rt.AdminUsers.ListTokens(req.Context(), actor.user, id)
	if err != nil {
		rt.adminFailure(rw, req, err)

		return
	}

	out := make([]api.Token, 0, len(toks))
	for _, t := range toks {
		out = append(out, tokenOf(t))
	}

	writeJSON(rw, http.StatusOK, out)
}

// issueUserToken is the one response that carries the token's secret.
func (rt *router) issueUserToken(rw http.ResponseWriter, req *http.Request) {
	actor, _ := callerFrom(req.Context())

	id, ok := pathID(rw, req, "userId")
	if !ok {
		return
	}

	var body api.IssueTokenRequest
	if !decodeJSON(rw, req, &body) {
		return
	}

	tok, secret, err := rt.AdminUsers.IssueToken(req.Context(), actor.user, id, body.Label)
	if err != nil {
		rt.adminFailure(rw, req, err)

		return
	}

	writeJSON(rw, http.StatusCreated, api.IssuedToken{Token: tokenOf(tok), Secret: secret})
}

// revokeUserToken answers 204 for a token already revoked, the state asked for, as
// the cabinet does.
func (rt *router) revokeUserToken(rw http.ResponseWriter, req *http.Request) {
	actor, _ := callerFrom(req.Context())

	userID, ok := pathID(rw, req, "userId")
	if !ok {
		return
	}

	tokenID, ok := pathID(rw, req, "tokenId")
	if !ok {
		return
	}

	switch err := rt.AdminUsers.RevokeToken(req.Context(), actor.user, userID, tokenID); {
	case err == nil, errors.Is(err, credentials.ErrAlreadyRevoked):
		rw.WriteHeader(http.StatusNoContent)
	default:
		rt.adminFailure(rw, req, err)
	}
}

func (rt *router) getUserActivity(rw http.ResponseWriter, req *http.Request) {
	actor, _ := callerFrom(req.Context())

	id, ok := pathID(rw, req, "userId")
	if !ok {
		return
	}

	limit := adminusers.DefaultActivityLimit

	if raw := req.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > adminusers.MaxActivityLimit {
			writeFieldError(rw, http.StatusUnprocessableEntity, codeInvalidInput, "limit",
				"limit must be an integer from 1 to "+strconv.Itoa(adminusers.MaxActivityLimit))

			return
		}

		limit = parsed
	}

	act, err := rt.AdminUsers.Activity(req.Context(), actor.user, id, limit)
	if err != nil {
		rt.adminFailure(rw, req, err)

		return
	}

	out := api.Activity{
		Requests: make([]activityRequest, 0, len(act.Requests)),
		Audit:    make([]activityAudit, 0, len(act.Audit)),
	}
	for _, event := range act.Requests {
		out.Requests = append(out.Requests, activityRequest{
			At:          event.At.UTC(),
			TokenId:     idPtr(event.TokenID),
			Provider:    event.Provider,
			Model:       event.Model,
			Stream:      event.Stream,
			StatusCode:  requestStatus(event),
			TokensTotal: int(event.TokensTotal),
			LatencyMs:   event.LatencyMS,
			CostUSD:     requestCost(event.Cost),
		})
	}

	for _, event := range act.Audit {
		audit := activityAudit{At: event.At.UTC(), Action: event.Action, ActorId: idPtr(event.ActorID)}
		if event.Target != "" {
			target := event.Target
			audit.Target = &target
		}

		if len(event.Detail) > 0 {
			detail := event.Detail
			audit.Detail = &detail
		}

		out.Audit = append(out.Audit, audit)
	}

	writeJSON(rw, http.StatusOK, out)
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

func (rt *router) getCatalog(rw http.ResponseWriter, req *http.Request) {
	c, _ := callerFrom(req.Context())

	providers, err := rt.AdminUsers.Catalog(c.user)
	if err != nil {
		rt.adminFailure(rw, req, err)

		return
	}

	writeJSON(rw, http.StatusOK, catalogOf(providers))
}

// catalogOf writes providers as the contract's Catalog; a provider's models are []
// rather than null.
func catalogOf(providers []app.CatalogProvider) api.Catalog {
	out := api.Catalog{Providers: make([]catalogProvider, 0, len(providers))}
	for _, provider := range providers {
		models := provider.Models
		if models == nil {
			models = []string{}
		}

		out.Providers = append(out.Providers, catalogProvider{Name: provider.Name, Models: models})
	}

	return out
}

func (rt *router) previewPolicy(rw http.ResponseWriter, req *http.Request) {
	actor, _ := callerFrom(req.Context())

	var body api.PolicyPreviewRequest
	if !decodeJSON(rw, req, &body) {
		return
	}

	preview, err := rt.AdminUsers.PolicyPreview(actor.user, body.Rules)
	if err != nil {
		rt.adminFailure(rw, req, err)

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

	writeJSON(rw, http.StatusOK, out)
}

// adminUserOf describes an account as the contract's AdminUser. It carries no
// credential: no password, hash or token.
func adminUserOf(view app.UserView) api.AdminUser {
	user := view.User

	signIn := make([]api.AdminUserSignIn, 0, len(view.SignIn))
	for _, m := range view.SignIn {
		signIn = append(signIn, api.AdminUserSignIn(m))
	}

	out := api.AdminUser{
		Id:                  user.ID,
		Kind:                api.Kind(user.Kind),
		DisplayName:         user.DisplayName,
		Role:                api.Role(user.Role),
		Status:              api.Status(user.Status),
		Policy:              policyOf(user.Policy),
		PolicySource:        api.PolicySource(user.PolicySource),
		MustChangePassword:  user.MustChangePassword,
		SignIn:              signIn,
		InvitationExpiresAt: utcPtr(view.InvitationExpiresAt),
		LastSeenAt:          utcPtr(user.LastSeenAt),
		CreatedAt:           user.CreatedAt.UTC(),
	}
	if user.Email != "" {
		email := user.Email
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

// requestCost is a request's cost as the contract's Activity carries it: none (null)
// when none of its tokens had a price.
func requestCost(c app.UsageCost) *float64 {
	if !c.Priced {
		return nil
	}

	total := c.TotalUSD()

	return &total
}
