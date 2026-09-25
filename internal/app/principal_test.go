package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/app/mocks"
	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/domain/credentials"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestPrincipalRoundTrips(t *testing.T) {
	principal := app.Principal{UserID: uuid.New(), TokenID: uuid.New()}

	rendered := principal.String()
	require.Equal(t, principal.UserID.String()+":"+principal.TokenID.String(), rendered, "String()")

	got, err := app.ParsePrincipal(rendered)
	require.NoError(t, err, "ParsePrincipal(%q)", rendered)
	require.Equal(t, principal, got, "ParsePrincipal(String())")
}

func TestParsePrincipalRejectsMalformedInput(t *testing.T) {
	user, token := uuid.New(), uuid.New()
	for name, in := range map[string]string{
		"empty":            "",
		"one uuid":         user.String(),
		"empty token":      user.String() + ":",
		"empty user":       ":" + token.String(),
		"three parts":      user.String() + ":" + token.String() + ":" + uuid.NewString(),
		"not a uuid":       user.String() + ":sk-secret",
		"swapped with sep": user.String() + "|" + token.String(),
		"nil user":         uuid.Nil.String() + ":" + token.String(),
		"nil token":        user.String() + ":" + uuid.Nil.String(),
		"urn form":         "urn:uuid:" + user.String() + ":" + token.String(),
		"braced":           "{" + user.String() + "}:" + token.String(),
		"no hyphens":       strings.ReplaceAll(user.String(), "-", "") + ":" + token.String(),
		"upper case":       strings.ToUpper(user.String()) + ":" + token.String(),
		"padded":           " " + user.String() + ":" + token.String(),
	} {
		p, err := app.ParsePrincipal(in)
		assert.ErrorIs(t, err, app.ErrMalformedPrincipal, "%s: ParsePrincipal(%q) = %+v", name, in, p)
	}
}

const presented = "sk-presented-secret"

// liveToken is an active token for owner whose hash is the hash of presented.
func liveToken(owner uuid.UUID) credentials.Token {
	return credentials.Token{ID: uuid.New(), UserID: owner, Hash: credentials.HashSecret(presented)}
}

func activeHuman() identity.User {
	return identity.User{ID: uuid.New(), Kind: identity.KindHuman, Status: identity.StatusActive}
}

func TestResolveReturnsTheOwnerAndTheToken(t *testing.T) {
	rule, err := access.ParseRule("claude:*")
	require.NoError(t, err)

	human := activeHuman()
	human.Email = "alice@example.com"
	human.Policy = access.Policy{rule}
	// The label travels with the principal too: a person's email, a service
	// account's name.
	for name, tc := range map[string]struct {
		owner identity.User
		label string
	}{
		"human":   {human, "alice@example.com"},
		"service": {identity.NewService(uuid.New(), "chat-panel", access.Policy{rule}), "chat-panel"},
	} {
		t.Run(name, func(t *testing.T) {
			owner := tc.owner
			users, tokens := mocks.NewUserRepo(t), mocks.NewTokenRepo(t)
			tok := liveToken(owner.ID)
			// The lookup is by the hash of what was presented, never the secret itself.
			tokens.EXPECT().ByHash(mock.Anything, credentials.HashSecret(presented)).Return(tok, nil)
			users.EXPECT().ByID(mock.Anything, owner.ID).Return(owner, nil)

			got, policy, err := app.NewTokenResolver(users, tokens).Resolve(context.Background(), presented)
			require.NoError(t, err, "Resolve")
			require.Equal(t, app.Principal{UserID: owner.ID, TokenID: tok.ID, Owner: tc.label}, got, "Resolve")
			// The owner's policy travels with the principal: whoever decides
			// what the request may do does not read the owner again.
			require.True(t, policy.Allows("claude", "any-model"), "Resolve policy = %v, want the owner's claude:*", policy)
			require.False(t, policy.Allows("chatgpt", "any-model"), "Resolve policy = %v, want the owner's claude:*", policy)
		})
	}
}

// TestResolveRefusalsAreIndistinguishable: an unknown, a revoked and a blocked
// owner's key must produce the very same error, or a caller holding a leaked
// key learns whether it was once valid.
func TestResolveRefusalsAreIndistinguishable(t *testing.T) {
	revokedAt := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	blocked := activeHuman()
	blocked.Status = identity.StatusBlocked
	blockedService := identity.NewService(uuid.New(), "chat-panel", access.Policy{})
	blockedService.Status = identity.StatusBlocked

	for _, tc := range []struct {
		name   string
		expect func(users *mocks.UserRepo, tokens *mocks.TokenRepo)
	}{
		{"unknown token", func(_ *mocks.UserRepo, tokens *mocks.TokenRepo) {
			tokens.EXPECT().ByHash(mock.Anything, mock.Anything).Return(credentials.Token{}, app.ErrNotFound)
		}},
		{"revoked token", func(_ *mocks.UserRepo, tokens *mocks.TokenRepo) {
			tok := liveToken(uuid.New())
			tok.RevokedAt = &revokedAt
			tokens.EXPECT().ByHash(mock.Anything, mock.Anything).Return(tok, nil)
		}},
		{"blocked owner", func(users *mocks.UserRepo, tokens *mocks.TokenRepo) {
			tokens.EXPECT().ByHash(mock.Anything, mock.Anything).Return(liveToken(blocked.ID), nil)
			users.EXPECT().ByID(mock.Anything, blocked.ID).Return(blocked, nil)
		}},
		{"blocked service account", func(users *mocks.UserRepo, tokens *mocks.TokenRepo) {
			tokens.EXPECT().ByHash(mock.Anything, mock.Anything).Return(liveToken(blockedService.ID), nil)
			users.EXPECT().ByID(mock.Anything, blockedService.ID).Return(blockedService, nil)
		}},
		{"owner gone", func(users *mocks.UserRepo, tokens *mocks.TokenRepo) {
			owner := uuid.New()
			tokens.EXPECT().ByHash(mock.Anything, mock.Anything).Return(liveToken(owner), nil)
			users.EXPECT().ByID(mock.Anything, owner).Return(identity.User{}, app.ErrNotFound)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			users, tokens := mocks.NewUserRepo(t), mocks.NewTokenRepo(t)
			tc.expect(users, tokens)

			got, policy, err := app.NewTokenResolver(users, tokens).Resolve(context.Background(), presented)
			require.Same(t, app.ErrInvalidCredentials, err, "Resolve = %+v; want exactly ErrInvalidCredentials", got)
			require.Zero(t, got, "a refusal returned a principal")
			require.Nil(t, policy, "a refusal returned a policy")
		})
	}
}

// TestResolveRefusesAnEmptySecretWithoutALookup: the strict mocks carry no
// expectations, so any repository call fails the test.
func TestResolveRefusesAnEmptySecretWithoutALookup(t *testing.T) {
	users, tokens := mocks.NewUserRepo(t), mocks.NewTokenRepo(t)
	_, _, err := app.NewTokenResolver(users, tokens).Resolve(context.Background(), "")
	require.Same(t, app.ErrInvalidCredentials, err, "Resolve(\"\")")
}

// TestResolveReportsAFailedLookupAsAFailure: a database outage is not a
// refusal. Reporting it as invalid credentials would tell a valid client its
// key is bad; it must stay distinguishable, and must not carry the secret.
func TestResolveReportsAFailedLookupAsAFailure(t *testing.T) {
	outage := errors.New("connection refused")
	owner := activeHuman()

	for _, tc := range []struct {
		name   string
		expect func(users *mocks.UserRepo, tokens *mocks.TokenRepo)
	}{
		{"token lookup", func(_ *mocks.UserRepo, tokens *mocks.TokenRepo) {
			tokens.EXPECT().ByHash(mock.Anything, mock.Anything).Return(credentials.Token{}, outage)
		}},
		{"owner lookup", func(users *mocks.UserRepo, tokens *mocks.TokenRepo) {
			tokens.EXPECT().ByHash(mock.Anything, mock.Anything).Return(liveToken(owner.ID), nil)
			users.EXPECT().ByID(mock.Anything, owner.ID).Return(identity.User{}, outage)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			users, tokens := mocks.NewUserRepo(t), mocks.NewTokenRepo(t)
			tc.expect(users, tokens)

			_, _, err := app.NewTokenResolver(users, tokens).Resolve(context.Background(), presented)
			require.ErrorIs(t, err, outage, "Resolve: want the lookup failure")
			require.NotErrorIs(t, err, app.ErrInvalidCredentials, "Resolve: a lookup failure is not a refusal")
			require.NotContains(t, err.Error(), presented, "error carries the secret")
		})
	}
}
