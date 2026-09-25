// Package postgres_test exercises the repositories against a real Postgres.
//
// External test package on purpose: the container harness lives in pgtest, which
// imports postgres, so an internal test file here would be an import cycle.
package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/domain/credentials"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/pgtest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// TestTokenRepo shares one container across its subtests: a pool costs roughly two
// seconds to stand up, and these cases do not need isolation from each other — each
// owns its own user and its own tokens.
func TestTokenRepo(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.NewTestPool(t)
	users, tokens := postgres.NewUserRepo(pool), postgres.NewTokenRepo(pool)

	newOwner := func(t *testing.T, name string) identity.User {
		t.Helper()

		owner := identity.NewService(uuid.New(), name, access.Policy{})
		require.NoError(t, users.Create(ctx, owner), "create user")

		return owner
	}

	t.Run("ByHashResolvesToken", func(t *testing.T) {
		owner := newOwner(t, "chat-panel")

		tok, secret, err := credentials.Generate(owner.ID, "panel")
		require.NoError(t, err, "generate")

		require.NoError(t, tokens.Create(ctx, tok), "create token")

		got, err := tokens.ByHash(ctx, credentials.HashSecret(secret))
		require.NoError(t, err, "ByHash")

		require.Equal(t, tok.ID, got.ID, "ByHash id")
		require.Equal(t, owner.ID, got.UserID, "ByHash owner")
		require.Equal(t, tok.Label, got.Label, "ByHash label")
		require.Equal(t, tok.Prefix, got.Prefix, "ByHash prefix")
		require.Nil(t, got.LastUsedAt, "fresh token came back used")
		require.Nil(t, got.RevokedAt, "fresh token came back revoked")
		require.Nil(t, got.RevokedBy, "fresh token came back revoked")
	})

	t.Run("ByHashUnknownIsNotFound", func(t *testing.T) {
		// The application layer switches on app.ErrNotFound; a driver error leaking
		// through here would make every caller import pgx to tell "no such token"
		// from "the database is down".
		_, err := tokens.ByHash(ctx, "nope")
		require.ErrorIs(t, err, app.ErrNotFound)
	})

	t.Run("ByIDResolvesToken", func(t *testing.T) {
		// The revoke path knows a token's id, not its secret, and has to load the row
		// to check who owns it before it writes.
		owner := newOwner(t, "id-lookup")

		tok, _, err := credentials.Generate(owner.ID, "by-id")
		require.NoError(t, err, "generate")

		require.NoError(t, tokens.Create(ctx, tok), "create token")

		got, err := tokens.ByID(ctx, tok.ID)
		require.NoError(t, err, "ByID")

		require.Equal(t, tok.ID, got.ID, "ByID id")
		require.Equal(t, owner.ID, got.UserID, "ByID owner")
		require.Equal(t, tok.Label, got.Label, "ByID label")
	})

	t.Run("ByIDUnknownIsNotFound", func(t *testing.T) {
		_, err := tokens.ByID(ctx, uuid.New())
		require.ErrorIs(t, err, app.ErrNotFound)
	})

	t.Run("TouchLastUsedOnUnknownTokenIsNotAnError", func(t *testing.T) {
		// Deliberately asymmetric with Save, which does report app.ErrNotFound on zero
		// rows. This call sits on the proxy hot path: a token revoked or deleted
		// between authentication and the stamp must not fail a request that is already
		// being served, or gateway availability starts depending on the tokens table.
		// Making the two consistent is the obvious future edit; this is the test that
		// must stop it.
		require.NoError(t, tokens.TouchLastUsed(ctx, uuid.New(), time.Now().UTC()), "TouchLastUsed on a missing token")
	})

	t.Run("TouchLastUsedPersists", func(t *testing.T) {
		owner := newOwner(t, "batch-runner")

		tok, _, err := credentials.Generate(owner.ID, "runner")
		require.NoError(t, err, "generate")

		require.NoError(t, tokens.Create(ctx, tok), "create token")

		when := time.Now().UTC().Truncate(time.Second)
		require.NoError(t, tokens.TouchLastUsed(ctx, tok.ID, when), "TouchLastUsed")

		list, err := tokens.ListByUser(ctx, owner.ID)
		require.NoError(t, err, "ListByUser")

		require.Len(t, list, 1, "ListByUser")
		require.NotNil(t, list[0].LastUsedAt, "last used not persisted")
		require.True(t, list[0].LastUsedAt.Equal(when), "last used = %v, want %v", list[0].LastUsedAt, when)
	})

	t.Run("TouchLastUsedNeverMovesBackwards", func(t *testing.T) {
		// Stamps arrive in the order requests complete, not start, and from
		// several batches: an older one landing late must not rewind the stamp.
		owner := newOwner(t, "streamer")

		tok, _, err := credentials.Generate(owner.ID, "stream")
		require.NoError(t, err, "generate")

		require.NoError(t, tokens.Create(ctx, tok), "create token")

		later := time.Now().UTC().Truncate(time.Second)
		for _, at := range []time.Time{later, later.Add(-5 * time.Minute)} {
			require.NoError(t, tokens.TouchLastUsed(ctx, tok.ID, at), "TouchLastUsed(%v)", at)
		}

		got, err := tokens.ByID(ctx, tok.ID)
		require.NoError(t, err, "ByID")

		require.NotNil(t, got.LastUsedAt, "last used not persisted")
		require.True(t, got.LastUsedAt.Equal(later),
			"last used = %v, want %v: an older stamp moved it back", got.LastUsedAt, later)
	})

	t.Run("SaveRoundTripsRevocation", func(t *testing.T) {
		admin := newOwner(t, "admin-account")
		owner := newOwner(t, "retired-agent")

		tok, secret, err := credentials.Generate(owner.ID, "agent")
		require.NoError(t, err, "generate")

		require.NoError(t, tokens.Create(ctx, tok), "create token")

		when := time.Now().UTC().Truncate(time.Second)
		require.NoError(t, tok.Revoke(admin.ID, when), "Revoke")

		require.NoError(t, tokens.Save(ctx, tok), "Save")

		// A revoked token still resolves: authentication must be able to tell a
		// revoked credential from an unknown one, and only the stored revocation
		// fields carry that difference.
		got, err := tokens.ByHash(ctx, credentials.HashSecret(secret))
		require.NoError(t, err, "ByHash after revoke")

		require.False(t, got.Active(), "revoked token came back active: %+v", got)
		require.NotNil(t, got.RevokedAt, "revoked_at not stored")
		require.True(t, got.RevokedAt.Equal(when), "revoked_at = %v, want %v", got.RevokedAt, when)
		require.NotNil(t, got.RevokedBy, "revoked_by not stored")
		require.Equal(t, admin.ID, *got.RevokedBy, "revoked_by")
	})

	// The limit counts live tokens only, holds under concurrent creates for one
	// owner, and a revocation makes room.
	t.Run("CreateStopsAtTheLiveTokenLimit", func(t *testing.T) {
		owner := newOwner(t, "busy-agent")
		create := func() (credentials.Token, error) {
			tok, _, err := credentials.Generate(owner.ID, "key")
			require.NoError(t, err, "generate")

			return tok, tokens.Create(ctx, tok)
		}

		revoked, err := create()
		require.NoError(t, err, "create")

		require.NoError(t, revoked.Revoke(owner.ID, time.Now()), "Revoke")

		require.NoError(t, tokens.Save(ctx, revoked), "Save")

		var first credentials.Token

		for idx := range app.MaxLiveTokensPerOwner - 3 {
			tok, err := create()
			require.NoError(t, err, "create %d", idx)

			if idx == 0 {
				first = tok
			}
		}

		// Three places left, eight racing for them.
		errs := make(chan error, 8)
		for range cap(errs) {
			tok, _, err := credentials.Generate(owner.ID, "key")
			require.NoError(t, err, "generate")

			go func() { errs <- tokens.Create(ctx, tok) }()
		}

		var created, refused int

		for range cap(errs) {
			switch err := <-errs; {
			case err == nil:
				created++
			case errors.Is(err, app.ErrTokenLimit):
				refused++
			default:
				require.Failf(t, "racing create", "unexpected error: %v", err)
			}
		}

		require.Equal(t, 3, created, "racing creates: created")
		require.Equal(t, 5, refused, "racing creates: refused")

		require.NoError(t, first.Revoke(owner.ID, time.Now()), "Revoke")

		require.NoError(t, tokens.Save(ctx, first), "Save")

		_, err = create()
		require.NoError(t, err, "create after a revocation: want room for one")

		_, err = create()
		require.ErrorIs(t, err, app.ErrTokenLimit, "create past the limit")
	})

	t.Run("CreateForUnknownOwnerIsNotFound", func(t *testing.T) {
		tok, _, err := credentials.Generate(uuid.New(), "orphan")
		require.NoError(t, err, "generate")

		require.ErrorIs(t, tokens.Create(ctx, tok), app.ErrNotFound)
	})

	t.Run("SaveUnknownTokenIsNotFound", func(t *testing.T) {
		unknown := credentials.Token{ID: uuid.New(), Label: "ghost"}
		require.ErrorIs(t, tokens.Save(ctx, unknown), app.ErrNotFound)
	})
}
