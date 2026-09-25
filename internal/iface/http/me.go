package http

import (
	"errors"
	"net/http"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/domain/credentials"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/elleqt/llm-proxy-backend/internal/iface/http/api"
	"github.com/google/uuid"
)

// defaultUsageWindow is how far back GET /api/me/usage looks without a from.
const defaultUsageWindow = 7 * 24 * time.Hour

// usagePoint names the element type the contract declares inline in Usage.points, for
// which the generator emits an anonymous struct. It is an alias, so it stays the
// generated type: a contract change to the point breaks the build here.
type usagePoint = struct {
	At          time.Time `json:"at"`
	CostUSD     float64   `json:"costUSD"`
	Model       string    `json:"model"`
	Requests    int       `json:"requests"`
	TokensTotal int       `json:"tokensTotal"`
}

func (rt *router) getMe(w http.ResponseWriter, r *http.Request) {
	c, _ := callerFrom(r.Context())
	writeJSON(w, http.StatusOK, meOf(c.user))
}

// meOf describes u as the contract's Me. Restricted is read off the user, the same
// source auth.Service.ResolveSession derives the session's restriction from.
func meOf(user identity.User) api.Me {
	me := api.Me{
		Id:           user.ID,
		Kind:         api.Kind(user.Kind),
		DisplayName:  user.DisplayName,
		Role:         api.Role(user.Role),
		Restricted:   user.MustChangePassword,
		Policy:       policyOf(user.Policy),
		PolicySource: api.PolicySource(user.PolicySource),
	}
	if user.Email != "" {
		email := user.Email
		me.Email = &email
	}

	return me
}

// policyOf writes a policy as the contract's rule strings; an empty one is [].
func policyOf(p access.Policy) api.Policy {
	out := make(api.Policy, 0, len(p))
	for _, rule := range p {
		out = append(out, rule.String())
	}

	return out
}

func (rt *router) listMyTokens(rw http.ResponseWriter, req *http.Request) {
	c, _ := callerFrom(req.Context())

	toks, err := rt.Tokens.List(req.Context(), ownAuthority(c.user), c.user.ID)
	if err != nil {
		rt.internal(rw, req, err)

		return
	}

	out := make([]api.Token, 0, len(toks))
	for _, t := range toks {
		out = append(out, tokenOf(t))
	}

	writeJSON(rw, http.StatusOK, out)
}

// issueMyToken is the one response that carries the token's secret.
func (rt *router) issueMyToken(rw http.ResponseWriter, req *http.Request) {
	actor, _ := callerFrom(req.Context())

	var body api.IssueTokenRequest
	if !decodeJSON(rw, req, &body) {
		return
	}

	tok, secret, err := rt.Tokens.Issue(req.Context(), ownAuthority(actor.user), actor.user.ID, body.Label)
	switch {
	case errors.Is(err, credentials.ErrInvalidLabel):
		writeFieldError(rw, http.StatusUnprocessableEntity, codeInvalidInput, "label",
			"the label must be 1 to 64 characters with no control characters")

		return
	case errors.Is(err, app.ErrTokenLimit):
		writeError(rw, http.StatusConflict, codeTokenLimit, tokenLimitMessage)

		return
	case err != nil:
		rt.internal(rw, req, err)

		return
	}

	writeJSON(rw, http.StatusCreated, api.IssuedToken{Token: tokenOf(tok), Secret: secret})
}

// revokeMyToken answers 404 for a token owned by someone else, exactly as for one that
// does not exist: the cabinet manages the caller's own keys and nobody else's. An
// already-revoked token is the state asked for, so it is 204 as well.
func (rt *router) revokeMyToken(rw http.ResponseWriter, req *http.Request) {
	actor, _ := callerFrom(req.Context())

	id, err := uuid.Parse(req.PathValue("tokenId"))
	if err != nil {
		writeError(rw, http.StatusNotFound, codeNotFound, "no such token")

		return
	}

	switch err := rt.Tokens.Revoke(req.Context(), ownAuthority(actor.user), id); {
	case err == nil, errors.Is(err, credentials.ErrAlreadyRevoked):
		rw.WriteHeader(http.StatusNoContent)
	case errors.Is(err, app.ErrNotFound), errors.Is(err, app.ErrForbidden):
		writeError(rw, http.StatusNotFound, codeNotFound, "no such token")
	default:
		rt.internal(rw, req, err)
	}
}

// ownAuthority is u acting through the cabinet, which reaches only u's own keys. An
// administrator's role lets tokens.Service manage anyone's; that authority belongs
// to the admin API, so here it is set aside and a foreign token id is refused like
// anyone else's attempt would be. The actor recorded in the audit is still u.
func ownAuthority(u identity.User) identity.User {
	u.Role = identity.RoleUser

	return u
}

func tokenOf(token credentials.Token) api.Token {
	return api.Token{
		Id:         token.ID,
		Label:      token.Label,
		Prefix:     token.Prefix,
		CreatedAt:  token.CreatedAt.UTC(),
		LastUsedAt: utcPtr(token.LastUsedAt),
		RevokedAt:  utcPtr(token.RevokedAt),
	}
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}

	u := t.UTC()

	return &u
}

// getMyUsage answers the caller's consumption over [from, to). to defaults to now,
// from to seven days before to.
func (rt *router) getMyUsage(rw http.ResponseWriter, req *http.Request) {
	actor, _ := callerFrom(req.Context())
	query := req.URL.Query()
	to := rt.Clock.Now().UTC()

	if raw := query.Get("to"); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeFieldError(rw, http.StatusUnprocessableEntity, codeInvalidInput, "to", "to must be an RFC 3339 timestamp")

			return
		}

		to = parsed.UTC()
	}

	from := to.Add(-defaultUsageWindow)

	if raw := query.Get("from"); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeFieldError(rw, http.StatusUnprocessableEntity, codeInvalidInput, "from", "from must be an RFC 3339 timestamp")

			return
		}

		from = parsed.UTC()
	}

	if !from.Before(to) {
		writeFieldError(rw, http.StatusUnprocessableEntity, codeInvalidInput, "from", "from must be before to")

		return
	}

	series, err := rt.Usage.Series(req.Context(), actor.user.ID, from, to)
	if err != nil {
		rt.internal(rw, req, err)

		return
	}

	out := api.Usage{From: from, To: to, Bucket: api.UsageBucket(series.Bucket)}
	out.Totals.Requests = int(series.Totals.Requests)
	out.Totals.TokensTotal = int(series.Totals.TokensTotal)
	out.Totals.Cost = costSummaryOf(series.Totals.Cost)

	out.Points = make([]usagePoint, 0, len(series.Points))
	for _, p := range series.Points {
		out.Points = append(out.Points, usagePoint{
			At: p.At.UTC(), Model: p.Model, Requests: int(p.Requests), TokensTotal: int(p.TokensTotal),
			CostUSD: p.CostUSD,
		})
	}

	writeJSON(rw, http.StatusOK, out)
}

// costSummaryOf describes a summed cost as the contract's CostSummary.
func costSummaryOf(cost app.UsageCost) api.CostSummary {
	return api.CostSummary{
		TotalUSD:        cost.TotalUSD(),
		InputUSD:        cost.InputUSD,
		OutputUSD:       cost.OutputUSD,
		CacheReadUSD:    cost.CacheReadUSD,
		CacheWriteUSD:   cost.CacheWriteUSD,
		CacheSavingsUSD: cost.CacheSavingsUSD,
		UnpricedTokens:  int(cost.UnpricedTokens),
	}
}

// listMyModels answers the models the caller's keys may use now, by the caller's
// policy as the session middleware loaded it for this request.
func (rt *router) listMyModels(w http.ResponseWriter, r *http.Request) {
	c, _ := callerFrom(r.Context())
	writeJSON(w, http.StatusOK, catalogOf(rt.Models.Allowed(c.user)))
}
