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

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/domain/credentials"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/elleqt/llm-proxy-backend/internal/iface/http/api"
)

func TestMeDescribesTheCaller(t *testing.T) {
	e := newEnv(t)
	u := person("person@example.com")
	rule, err := access.ParseRule("claude:claude-sonnet-*")
	if err != nil {
		t.Fatal(err)
	}
	u.Policy = access.Policy{rule}
	var me api.Me
	decodeBody(t, e.do(http.MethodGet, "/api/me", "", withCookie(e.signedIn(u))), http.StatusOK, &me)
	if me.Id != u.ID || me.Kind != api.Kind("human") || me.Role != api.Role("user") || me.Restricted ||
		len(me.Policy) != 1 || me.Policy[0] != "claude:claude-sonnet-*" || me.PolicySource != api.PolicySource("local") {
		t.Fatalf("me = %+v, want %+v", me, u)
	}
}

// Every stored token appears, secret never: the list shows the prefix that tells keys
// apart and nothing the key could be rebuilt from.
func TestTokenListShowsPrefixesAndNeverSecrets(t *testing.T) {
	e := newEnv(t)
	u := person("person@example.com")
	tok, secret, err := credentials.Generate(u.ID, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	used := tok.CreatedAt.Add(time.Hour)
	tok.LastUsedAt = &used
	e.tokens.EXPECT().ListByUser(mock.Anything, u.ID).Return([]credentials.Token{tok}, nil)

	rec := e.do(http.MethodGet, "/api/me/tokens", "", withCookie(e.signedIn(u)))
	var got []api.Token
	decodeBody(t, rec, http.StatusOK, &got)
	if len(got) != 1 || got[0].Id != tok.ID || got[0].Prefix != secret[:7] || got[0].LastUsedAt == nil || got[0].RevokedAt != nil {
		t.Fatalf("tokens = %+v, want the laptop token with its prefix and last use", got)
	}
	if strings.Contains(rec.Body.String(), secret) || strings.Contains(rec.Body.String(), tok.Hash) {
		t.Fatal("the token list carries the secret or its hash")
	}
}

// An empty list is [] rather than null, as the contract's array type says.
func TestAnEmptyTokenListIsAnArray(t *testing.T) {
	e := newEnv(t)
	u := person("person@example.com")
	e.tokens.EXPECT().ListByUser(mock.Anything, u.ID).Return(nil, nil)
	rec := e.do(http.MethodGet, "/api/me/tokens", "", withCookie(e.signedIn(u)))
	if strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("body = %s, want []", rec.Body)
	}
}

func TestIssuingATokenShowsItsSecretOnce(t *testing.T) {
	e := newEnv(t)
	u := person("person@example.com")
	var stored credentials.Token
	e.tokens.EXPECT().Create(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, tok credentials.Token) error {
		stored = tok
		return nil
	})
	var out api.IssuedToken
	decodeBody(t, e.do(http.MethodPost, "/api/me/tokens", `{"label":"laptop"}`, withCookie(e.signedIn(u))), http.StatusCreated, &out)
	if out.Secret == "" || credentials.HashSecret(out.Secret) != stored.Hash {
		t.Fatal("the secret returned is not the one whose hash was stored")
	}
	if stored.UserID != u.ID || out.Token.Id != stored.ID || out.Token.Label != "laptop" {
		t.Fatalf("issued %+v for %s, want the caller's own laptop token", out.Token, stored.UserID)
	}
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
			if f := apiError(t, rec, http.StatusUnprocessableEntity, codeInvalidInput).Field; f == nil || *f != "label" {
				t.Fatalf("field = %v, want label", f)
			}
		})
	}
}

// The cabinet manages the caller's own keys. Someone else's token is not found — for
// an administrator too, whose authority over other people's keys belongs to the admin
// API, not to the cabinet.
func TestRevokingSomeoneElsesTokenIsNotFound(t *testing.T) {
	for _, role := range []identity.Role{identity.RoleUser, identity.RoleAdmin} {
		t.Run(string(role), func(t *testing.T) {
			e := newEnv(t)
			u := person("person@example.com")
			u.Role = role
			theirs, _, err := credentials.Generate(uuid.New(), "theirs")
			if err != nil {
				t.Fatal(err)
			}
			e.tokens.EXPECT().ByID(mock.Anything, theirs.ID).Return(theirs, nil)
			// No Save expectation: revoking it fails the test.
			rec := e.do(http.MethodDelete, "/api/me/tokens/"+theirs.ID.String(), "", withCookie(e.signedIn(u)))
			apiError(t, rec, http.StatusNotFound, codeNotFound)
		})
	}
}

func TestRevokingOwnToken(t *testing.T) {
	e := newEnv(t)
	u := person("person@example.com")
	mine, _, err := credentials.Generate(u.ID, "mine")
	if err != nil {
		t.Fatal(err)
	}
	e.tokens.EXPECT().ByID(mock.Anything, mine.ID).Return(mine, nil)
	var saved credentials.Token
	e.tokens.EXPECT().Save(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, tok credentials.Token) error {
		saved = tok
		return nil
	})
	rec := e.do(http.MethodDelete, "/api/me/tokens/"+mine.ID.String(), "", withCookie(e.signedIn(u)))
	if rec.Code != http.StatusNoContent || saved.Active() {
		t.Fatalf("status = %d, revoked = %t; want 204 and the token revoked", rec.Code, !saved.Active())
	}
}

func TestRevokeAnswersForTokensThatCannotBeRevoked(t *testing.T) {
	t.Run("already revoked is done", func(t *testing.T) {
		e := newEnv(t)
		u := person("person@example.com")
		tok, _, _ := credentials.Generate(u.ID, "old")
		if err := tok.Revoke(u.ID, time.Now()); err != nil {
			t.Fatal(err)
		}
		e.tokens.EXPECT().ByID(mock.Anything, tok.ID).Return(tok, nil)
		if rec := e.do(http.MethodDelete, "/api/me/tokens/"+tok.ID.String(), "", withCookie(e.signedIn(u))); rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204", rec.Code)
		}
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
	e := newEnv(t)
	u := person("person@example.com")
	now := e.clock.Now()
	e.usage.EXPECT().SeriesForUser(mock.Anything, u.ID, now.Add(-7*24*time.Hour), now).Return(app.UsageSeries{
		Bucket: app.UsageBucketDay,
		Totals: app.UsageTotals{Requests: 3, TokensTotal: 70, Cost: app.UsageCost{
			InputUSD: 1, OutputUSD: 2, CacheReadUSD: 0.25, CacheWriteUSD: 0.5, CacheSavingsUSD: -0.75, UnpricedTokens: 9, Priced: true,
		}},
		Points: []app.UsagePoint{{At: now.Truncate(24 * time.Hour), Model: "m", Requests: 3, TokensTotal: 70, CostUSD: 3.75}},
	}, nil)
	var out api.Usage
	decodeBody(t, e.do(http.MethodGet, "/api/me/usage", "", withCookie(e.signedIn(u))), http.StatusOK, &out)
	if out.Bucket != "day" || out.Totals.Requests != 3 || out.Totals.TokensTotal != 70 ||
		len(out.Points) != 1 || out.Points[0].Model != "m" || !out.From.Equal(now.Add(-7*24*time.Hour)) || !out.To.Equal(now) {
		t.Fatalf("usage = %+v", out)
	}
	want := api.CostSummary{TotalUSD: 3.75, InputUSD: 1, OutputUSD: 2, CacheReadUSD: 0.25, CacheWriteUSD: 0.5,
		CacheSavingsUSD: -0.75, UnpricedTokens: 9}
	if out.Totals.Cost != want || out.Points[0].CostUSD != 3.75 {
		t.Fatalf("cost = %+v, point cost %v; want %+v and 3.75", out.Totals.Cost, out.Points[0].CostUSD, want)
	}
}

func TestUsageTakesAnExplicitRangeAndRefusesABadOne(t *testing.T) {
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)

	e := newEnv(t)
	u := person("person@example.com")
	e.usage.EXPECT().SeriesForUser(mock.Anything, u.ID, from, to).Return(app.UsageSeries{Bucket: app.UsageBucketHour}, nil)
	rec := e.do(http.MethodGet, "/api/me/usage?from=2026-09-01T03:00:00%2B03:00&to=2026-09-02T00:00:00Z", "", withCookie(e.signedIn(u)))
	var raw map[string]json.RawMessage
	decodeBody(t, rec, http.StatusOK, &raw)
	if string(raw["points"]) != "[]" {
		t.Fatalf("points = %s, want [] for an empty series", raw["points"])
	}

	for query, field := range map[string]string{
		"from=yesterday":                                    "from",
		"to=2026-13-01T00:00:00Z":                           "to",
		"from=2026-09-02T00:00:00Z&to=2026-09-02T00:00:00Z": "from",
		"from=2026-09-03T00:00:00Z&to=2026-09-02T00:00:00Z": "from",
	} {
		rec := e.do(http.MethodGet, "/api/me/usage?"+query, "", withCookie(e.signedIn(u)))
		if f := apiError(t, rec, http.StatusUnprocessableEntity, codeInvalidInput).Field; f == nil || *f != field {
			t.Fatalf("%s: field = %v, want %s", query, f, field)
		}
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
	if out.ApiBaseURL != testAPIURL {
		t.Fatalf("apiBaseURL = %q, want %q", out.ApiBaseURL, testAPIURL)
	}
}

// The caller's models follow the policy the session loads with each request: an
// administrator's edit shows on the next call, a provider with nothing allowed is
// absent, and an empty policy is an empty list rather than null.
func TestMyModelsFollowTheCurrentPolicy(t *testing.T) {
	e := newEnv(t)
	served := map[string][]string{"claude": {"b", "a"}, "chatgpt": {"x"}}
	e.catalog.EXPECT().Models().Return(served).Maybe()
	e.catalog.EXPECT().ProvidersFor(mock.Anything).RunAndReturn(func(model string) []string {
		if model == "x" {
			return []string{"chatgpt"}
		}
		return []string{"claude"}
	}).Maybe()
	u := person("p@example.com")
	current := u
	e.users.EXPECT().ByID(mock.Anything, u.ID).RunAndReturn(func(context.Context, uuid.UUID) (identity.User, error) {
		return current, nil
	})
	cookie := withCookie(e.signedIn(u))

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
			if err != nil {
				t.Fatal(err)
			}
			current.Policy = access.Policy{rule}
		}
		rec := e.do(http.MethodGet, "/api/me/models", "", cookie)
		if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != tc.want {
			t.Errorf("policy %q: GET /api/me/models = %d %s, want 200 %s", tc.rule, rec.Code, rec.Body, tc.want)
		}
	}
}
