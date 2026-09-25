package http

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/domain/credentials"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/elleqt/llm-proxy-backend/internal/iface/http/api"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestMeDescribesTheCaller(t *testing.T) {
	env := newEnv(t)
	user := person("person@example.com")

	rule, err := access.ParseRule("claude:claude-sonnet-*")
	require.NoError(t, err, "ParseRule")

	user.Policy = access.Policy{rule}

	var me api.Me
	decodeBody(t, env.do(http.MethodGet, "/api/me", "", withCookie(env.signedIn(user))), http.StatusOK, &me)

	require.Equal(t, user.ID, me.Id, "me id")
	require.Equal(t, api.Human, me.Kind, "me kind")
	require.Equal(t, api.User, me.Role, "me role")
	require.False(t, me.Restricted, "me restricted")
	require.Equal(t, []string{"claude:claude-sonnet-*"}, me.Policy, "me policy")
	require.Equal(t, api.Local, me.PolicySource, "me policy source")
}

// Every stored token appears, secret never: the list shows the prefix that tells keys
// apart and nothing the key could be rebuilt from.
func TestTokenListShowsPrefixesAndNeverSecrets(t *testing.T) {
	env := newEnv(t)
	user := person("person@example.com")

	tok, secret, err := credentials.Generate(user.ID, "laptop")
	require.NoError(t, err, "Generate")

	used := tok.CreatedAt.Add(time.Hour)
	tok.LastUsedAt = &used
	env.tokens.EXPECT().ListByUser(mock.Anything, user.ID).Return([]credentials.Token{tok}, nil)

	rec := env.do(http.MethodGet, "/api/me/tokens", "", withCookie(env.signedIn(user)))

	var got []api.Token
	decodeBody(t, rec, http.StatusOK, &got)

	require.Len(t, got, 1, "tokens")
	require.Equal(t, tok.ID, got[0].Id, "token id")
	require.Equal(t, secret[:7], got[0].Prefix, "token prefix")
	require.NotNil(t, got[0].LastUsedAt, "token last use")
	require.Nil(t, got[0].RevokedAt, "token revoked")
	require.NotContains(t, rec.Body.String(), secret, "the token list carries the secret")
	require.NotContains(t, rec.Body.String(), tok.Hash, "the token list carries the secret's hash")
}

// An empty list is [] rather than null, as the contract's array type says.
func TestAnEmptyTokenListIsAnArray(t *testing.T) {
	e := newEnv(t)
	u := person("person@example.com")
	e.tokens.EXPECT().ListByUser(mock.Anything, u.ID).Return(nil, nil)

	rec := e.do(http.MethodGet, "/api/me/tokens", "", withCookie(e.signedIn(u)))
	require.JSONEq(t, "[]", rec.Body.String(), "an empty token list")
}

func TestIssuingATokenShowsItsSecretOnce(t *testing.T) {
	env := newEnv(t)
	user := person("person@example.com")

	var stored credentials.Token

	env.tokens.EXPECT().Create(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, tok credentials.Token) error {
		stored = tok

		return nil
	})

	var out api.IssuedToken
	decodeBody(t, env.do(http.MethodPost, "/api/me/tokens", `{"label":"laptop"}`, withCookie(env.signedIn(user))), http.StatusCreated, &out)

	require.NotEmpty(t, out.Secret, "no secret was returned")
	require.Equal(t, stored.Hash, credentials.HashSecret(out.Secret), "the secret returned is not the one whose hash was stored")
	require.Equal(t, user.ID, stored.UserID, "the token is not the caller's own")
	require.Equal(t, stored.ID, out.Token.Id, "issued token id")
	require.Equal(t, "laptop", out.Token.Label, "issued token label")
}

// An owner at the live-token limit is refused 409 token_limit on both routes that
// issue tokens.
func TestIssuingPastTheTokenLimitIsTokenLimit(t *testing.T) {
	bot := identity.NewService(uuid.New(), "CI", nil)

	for name, issue := range map[string]func(e *testEnv) *httptest.ResponseRecorder{
		"cabinet": func(e *testEnv) *httptest.ResponseRecorder {
			return e.do(http.MethodPost, "/api/me/tokens", `{"label":"laptop"}`, withCookie(e.signedIn(person("p@example.com"))))
		},
		"admin": func(e *testEnv) *httptest.ResponseRecorder {
			e.users.EXPECT().ByID(mock.Anything, bot.ID).Return(bot, nil)

			return e.do(http.MethodPost, "/api/admin/users/"+bot.ID.String()+"/tokens", `{"label":"ci"}`, withCookie(e.signedIn(admin())))
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.tokens.EXPECT().Create(mock.Anything, mock.Anything).Return(app.ErrTokenLimit)
			apiError(t, issue(e), http.StatusConflict, codeTokenLimit)
		})
	}
}

func TestAnInvalidTokenLabelIsInvalidInputOnTheLabel(t *testing.T) {
	for name, body := range map[string]string{
		"empty":         `{"label":""}`,
		"missing":       `{}`,
		"control":       `{"label":"lap\u001btop"}`,
		"over 64 runes": `{"label":"` + strings.Repeat("é", credentials.MaxLabelRunes+1) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)

			rec := e.do(http.MethodPost, "/api/me/tokens", body, withCookie(e.signedIn(person("p@example.com"))))
			wantField(t, apiError(t, rec, http.StatusUnprocessableEntity, codeInvalidInput), "label")
		})
	}
}

// The cabinet manages the caller's own keys. Someone else's token is not found — for
// an administrator too, whose authority over other people's keys belongs to the admin
// API, not to the cabinet.
func TestRevokingSomeoneElsesTokenIsNotFound(t *testing.T) {
	for _, role := range []identity.Role{identity.RoleUser, identity.RoleAdmin} {
		t.Run(string(role), func(t *testing.T) {
			env := newEnv(t)
			user := person("person@example.com")
			user.Role = role

			theirs, _, err := credentials.Generate(uuid.New(), "theirs")
			require.NoError(t, err, "Generate")

			env.tokens.EXPECT().ByID(mock.Anything, theirs.ID).Return(theirs, nil)
			// No Save expectation: revoking it fails the test.
			rec := env.do(http.MethodDelete, "/api/me/tokens/"+theirs.ID.String(), "", withCookie(env.signedIn(user)))
			apiError(t, rec, http.StatusNotFound, codeNotFound)
		})
	}
}

func TestRevokingOwnToken(t *testing.T) {
	env := newEnv(t)
	user := person("person@example.com")

	mine, _, err := credentials.Generate(user.ID, "mine")
	require.NoError(t, err, "Generate")

	env.tokens.EXPECT().ByID(mock.Anything, mine.ID).Return(mine, nil)

	var saved credentials.Token

	env.tokens.EXPECT().Save(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, tok credentials.Token) error {
		saved = tok

		return nil
	})

	rec := env.do(http.MethodDelete, "/api/me/tokens/"+mine.ID.String(), "", withCookie(env.signedIn(user)))
	require.Equal(t, http.StatusNoContent, rec.Code, "status")
	require.False(t, saved.Active(), "the token was not revoked")
}

func TestRevokeAnswersForTokensThatCannotBeRevoked(t *testing.T) {
	t.Run("already revoked is done", func(t *testing.T) {
		env := newEnv(t)
		user := person("person@example.com")

		tok, _, _ := credentials.Generate(user.ID, "old")
		require.NoError(t, tok.Revoke(user.ID, time.Now()), "Revoke")

		env.tokens.EXPECT().ByID(mock.Anything, tok.ID).Return(tok, nil)

		rec := env.do(http.MethodDelete, "/api/me/tokens/"+tok.ID.String(), "", withCookie(env.signedIn(user)))
		require.Equal(t, http.StatusNoContent, rec.Code, "status")
	})
	t.Run("unknown id", func(t *testing.T) {
		e := newEnv(t)
		id := uuid.New()
		e.tokens.EXPECT().ByID(mock.Anything, id).Return(credentials.Token{}, app.ErrNotFound)
		apiError(t, e.do(http.MethodDelete, "/api/me/tokens/"+id.String(), "", withCookie(e.signedIn(person("p@example.com")))),
			http.StatusNotFound, codeNotFound)
	})
	t.Run("not a uuid", func(t *testing.T) {
		e := newEnv(t)
		apiError(t, e.do(http.MethodDelete, "/api/me/tokens/not-a-uuid", "", withCookie(e.signedIn(person("p@example.com")))),
			http.StatusNotFound, codeNotFound)
	})
}

// Without from and to the window is the seven days up to now; the range reaches the
// ledger as given, and the series comes back in the contract's shape.
func TestUsageDefaultsToTheLastSevenDays(t *testing.T) {
	env := newEnv(t)
	user := person("person@example.com")
	now := env.clock.Now()
	env.usage.EXPECT().SeriesForUser(mock.Anything, user.ID, now.Add(-7*24*time.Hour), now).Return(app.UsageSeries{
		Bucket: app.UsageBucketDay,
		Totals: app.UsageTotals{Requests: 3, TokensTotal: 70, Cost: app.UsageCost{
			InputUSD: 1, OutputUSD: 2, CacheReadUSD: 0.25, CacheWriteUSD: 0.5, CacheSavingsUSD: -0.75, UnpricedTokens: 9, Priced: true,
		}},
		Points: []app.UsagePoint{{At: now.Truncate(24 * time.Hour), Model: "m", Requests: 3, TokensTotal: 70, CostUSD: 3.75}},
	}, nil)

	var out api.Usage
	decodeBody(t, env.do(http.MethodGet, "/api/me/usage", "", withCookie(env.signedIn(user))), http.StatusOK, &out)

	require.Equal(t, api.Day, out.Bucket, "bucket")
	require.Equal(t, 3, out.Totals.Requests, "total requests")
	require.Equal(t, 70, out.Totals.TokensTotal, "total tokens")
	require.Len(t, out.Points, 1, "points")
	require.Equal(t, "m", out.Points[0].Model, "point model")
	require.True(t, out.From.Equal(now.Add(-7*24*time.Hour)), "from = %v, want %v", out.From, now.Add(-7*24*time.Hour))
	require.True(t, out.To.Equal(now), "to = %v, want %v", out.To, now)

	want := api.CostSummary{
		TotalUSD: 3.75, InputUSD: 1, OutputUSD: 2, CacheReadUSD: 0.25, CacheWriteUSD: 0.5,
		CacheSavingsUSD: -0.75, UnpricedTokens: 9,
	}
	require.Equal(t, want, out.Totals.Cost, "total cost")
	require.Equal(t, 3.75, out.Points[0].CostUSD, "point cost")
}

func TestUsageTakesAnExplicitRangeAndRefusesABadOne(t *testing.T) {
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)

	env := newEnv(t)
	user := person("person@example.com")
	env.usage.EXPECT().SeriesForUser(mock.Anything, user.ID, from, to).Return(app.UsageSeries{Bucket: app.UsageBucketHour}, nil)
	rec := env.do(http.MethodGet, "/api/me/usage?from=2026-09-01T03:00:00%2B03:00&to=2026-09-02T00:00:00Z", "", withCookie(env.signedIn(user)))

	var raw map[string]json.RawMessage
	decodeBody(t, rec, http.StatusOK, &raw)

	require.JSONEq(t, "[]", string(raw["points"]), "points of an empty series")

	for query, field := range map[string]string{
		"from=yesterday":                                    "from",
		"to=2026-13-01T00:00:00Z":                           "to",
		"from=2026-09-02T00:00:00Z&to=2026-09-02T00:00:00Z": "from",
		"from=2026-09-03T00:00:00Z&to=2026-09-02T00:00:00Z": "from",
	} {
		rec := env.do(http.MethodGet, "/api/me/usage?"+query, "", withCookie(env.signedIn(user)))
		f := apiError(t, rec, http.StatusUnprocessableEntity, codeInvalidInput).Field
		require.NotNil(t, f, "%s: no field", query)
		require.Equal(t, field, *f, "%s: field", query)
	}
}

func TestUsageLedgerFailureIsInternal(t *testing.T) {
	e := newEnv(t)
	e.usage.EXPECT().SeriesForUser(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(app.UsageSeries{}, errors.New("connection refused"))
	apiError(t, e.do(http.MethodGet, "/api/me/usage", "", withCookie(e.signedIn(person("p@example.com")))),
		http.StatusInternalServerError, codeInternal)
}

func TestConnectNamesThePublicAPI(t *testing.T) {
	e := newEnv(t)

	var out api.ConnectInfo
	decodeBody(t, e.do(http.MethodGet, "/api/connect", "", withCookie(e.signedIn(person("p@example.com")))), http.StatusOK, &out)

	require.Equal(t, testAPIURL, out.ApiBaseURL, "apiBaseURL")
}

// The caller's models follow the policy the session loads with each request: an
// administrator's edit shows on the next call, a provider with nothing allowed is
// absent, and an empty policy is an empty list rather than null.
func TestMyModelsFollowTheCurrentPolicy(t *testing.T) {
	env := newEnv(t)
	served := map[string][]string{"claude": {"b", "a"}, "chatgpt": {"x"}}
	env.catalog.EXPECT().Models().Return(served).Maybe()
	env.catalog.EXPECT().ProvidersFor(mock.Anything).RunAndReturn(func(model string) []string {
		if model == "x" {
			return []string{"chatgpt"}
		}

		return []string{"claude"}
	}).Maybe()

	u := person("p@example.com")
	current := u
	env.users.EXPECT().ByID(mock.Anything, u.ID).RunAndReturn(func(context.Context, uuid.UUID) (identity.User, error) {
		return current, nil
	})
	cookie := withCookie(env.signedIn(u))

	for _, tc := range []struct {
		rule string
		want string
	}{
		{"claude:*", `{"providers":[{"models":["a","b"],"name":"claude"}]}`},
		{"chatgpt:*", `{"providers":[{"models":["x"],"name":"chatgpt"}]}`},
		{"", `{"providers":[]}`},
	} {
		current.Policy = nil

		if tc.rule != "" {
			rule, err := access.ParseRule(tc.rule)
			require.NoError(t, err, "ParseRule %q", tc.rule)

			current.Policy = access.Policy{rule}
		}

		rec := env.do(http.MethodGet, "/api/me/models", "", cookie)
		assert.Equal(t, http.StatusOK, rec.Code, "policy %q: GET /api/me/models status; body %s", tc.rule, rec.Body)
		assert.JSONEq(t, tc.want, rec.Body.String(), "policy %q: GET /api/me/models", tc.rule)
	}
}
