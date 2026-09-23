package http

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/domain/credentials"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/elleqt/llm-proxy-backend/internal/iface/http/api"
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
// source app.AuthService.ResolveSession derives the session's restriction from.
func meOf(u identity.User) api.Me {
	me := api.Me{
		Id:           u.ID,
		Kind:         api.Kind(u.Kind),
		DisplayName:  u.DisplayName,
		Role:         api.Role(u.Role),
		Restricted:   u.MustChangePassword,
		Policy:       policyOf(u.Policy),
		PolicySource: api.PolicySource(u.PolicySource),
	}
	if u.Email != "" {
		email := u.Email
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

func (rt *router) listMyTokens(w http.ResponseWriter, r *http.Request) {
	c, _ := callerFrom(r.Context())
	toks, err := rt.Tokens.List(r.Context(), ownAuthority(c.user), c.user.ID)
	if err != nil {
		rt.internal(w, r, err)
		return
	}
	out := make([]api.Token, 0, len(toks))
	for _, t := range toks {
		out = append(out, tokenOf(t))
	}
	writeJSON(w, http.StatusOK, out)
}

// issueMyToken is the one response that carries the token's secret.
func (rt *router) issueMyToken(w http.ResponseWriter, r *http.Request) {
	c, _ := callerFrom(r.Context())
	var body api.IssueTokenRequest
	if !decodeJSON(w, r, &body) {
		return
	}
	tok, secret, err := rt.Tokens.Issue(r.Context(), ownAuthority(c.user), c.user.ID, body.Label)
	switch {
	case errors.Is(err, credentials.ErrInvalidLabel):
		writeFieldError(w, http.StatusUnprocessableEntity, codeInvalidInput, "label",
			"the label must be 1 to 64 characters with no control characters")
		return
	case errors.Is(err, app.ErrTokenLimit):
		writeError(w, http.StatusConflict, codeTokenLimit, tokenLimitMessage)
		return
	case err != nil:
		rt.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, api.IssuedToken{Token: tokenOf(tok), Secret: secret})
}

// revokeMyToken answers 404 for a token owned by someone else, exactly as for one that
// does not exist: the cabinet manages the caller's own keys and nobody else's. An
// already-revoked token is the state asked for, so it is 204 as well.
func (rt *router) revokeMyToken(w http.ResponseWriter, r *http.Request) {
	c, _ := callerFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("tokenId"))
	if err != nil {
		writeError(w, http.StatusNotFound, codeNotFound, "no such token")
		return
	}
	switch err := rt.Tokens.Revoke(r.Context(), ownAuthority(c.user), id); {
	case err == nil, errors.Is(err, credentials.ErrAlreadyRevoked):
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, app.ErrNotFound), errors.Is(err, app.ErrForbidden):
		writeError(w, http.StatusNotFound, codeNotFound, "no such token")
	default:
		rt.internal(w, r, err)
	}
}

// ownAuthority is u acting through the cabinet, which reaches only u's own keys. An
// administrator's role lets app.TokenService manage anyone's; that authority belongs
// to the admin API, so here it is set aside and a foreign token id is refused like
// anyone else's attempt would be. The actor recorded in the audit is still u.
func ownAuthority(u identity.User) identity.User {
	u.Role = identity.RoleUser
	return u
}

func tokenOf(t credentials.Token) api.Token {
	return api.Token{
		Id:         t.ID,
		Label:      t.Label,
		Prefix:     t.Prefix,
		CreatedAt:  t.CreatedAt.UTC(),
		LastUsedAt: utcPtr(t.LastUsedAt),
		RevokedAt:  utcPtr(t.RevokedAt),
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
func (rt *router) getMyUsage(w http.ResponseWriter, r *http.Request) {
	c, _ := callerFrom(r.Context())
	q := r.URL.Query()
	to := rt.Clock.Now().UTC()
	if raw := q.Get("to"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeFieldError(w, http.StatusUnprocessableEntity, codeInvalidInput, "to", "to must be an RFC 3339 timestamp")
			return
		}
		to = t.UTC()
	}
	from := to.Add(-defaultUsageWindow)
	if raw := q.Get("from"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeFieldError(w, http.StatusUnprocessableEntity, codeInvalidInput, "from", "from must be an RFC 3339 timestamp")
			return
		}
		from = t.UTC()
	}
	if !from.Before(to) {
		writeFieldError(w, http.StatusUnprocessableEntity, codeInvalidInput, "from", "from must be before to")
		return
	}

	series, err := rt.Usage.Series(r.Context(), c.user.ID, from, to)
	if err != nil {
		rt.internal(w, r, err)
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
	writeJSON(w, http.StatusOK, out)
}

// costSummaryOf describes a summed cost as the contract's CostSummary.
func costSummaryOf(c app.UsageCost) api.CostSummary {
	return api.CostSummary{
		TotalUSD:        c.TotalUSD(),
		InputUSD:        c.InputUSD,
		OutputUSD:       c.OutputUSD,
		CacheReadUSD:    c.CacheReadUSD,
		CacheWriteUSD:   c.CacheWriteUSD,
		CacheSavingsUSD: c.CacheSavingsUSD,
		UnpricedTokens:  int(c.UnpricedTokens),
	}
}

// listMyModels answers the models the caller's keys may use now, by the caller's
// policy as the session middleware loaded it for this request.
func (rt *router) listMyModels(w http.ResponseWriter, r *http.Request) {
	c, _ := callerFrom(r.Context())
	writeJSON(w, http.StatusOK, catalogOf(rt.Models.Allowed(c.user)))
}
