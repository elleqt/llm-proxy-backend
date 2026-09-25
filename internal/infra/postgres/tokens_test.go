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
)

// TestTokenRepo shares one container across its subtests: a pool costs roughly two
// seconds to stand up, and these cases do not need isolation from each other — each
// owns its own user and its own tokens.
func TestTokenRepo(t *testing.T) { //nolint:gocognit,gocyclo,cyclop // subtests share one Postgres container; each subtest is linear
	ctx := context.Background()
	pool := pgtest.NewTestPool(t)
	users, tokens := postgres.NewUserRepo(pool), postgres.NewTokenRepo(pool)

	newOwner := func(t *testing.T, name string) identity.User {
		t.Helper()

		owner := identity.NewService(uuid.New(), name, access.Policy{})
		if err := users.Create(ctx, owner); err != nil {
			t.Fatalf("create user: %v", err)
		}

		return owner
	}

	t.Run("ByHashResolvesToken", func(t *testing.T) {
		owner := newOwner(t, "chat-panel")

		tok, secret, err := credentials.Generate(owner.ID, "panel")
		if err != nil {
			t.Fatalf("generate: %v", err)
		}

		if err := tokens.Create(ctx, tok); err != nil {
			t.Fatalf("create token: %v", err)
		}

		got, err := tokens.ByHash(ctx, credentials.HashSecret(secret))
		if err != nil {
			t.Fatalf("ByHash: %v", err)
		}

		if got.ID != tok.ID || got.UserID != owner.ID {
			t.Fatalf("ByHash returned %+v, want id %s owner %s", got, tok.ID, owner.ID)
		}

		if got.Label != tok.Label || got.Prefix != tok.Prefix {
			t.Fatalf("ByHash returned label %q prefix %q, want %q / %q",
				got.Label, got.Prefix, tok.Label, tok.Prefix)
		}

		if got.LastUsedAt != nil || got.RevokedAt != nil || got.RevokedBy != nil {
			t.Fatalf("fresh token came back used or revoked: %+v", got)
		}
	})

	t.Run("ByHashUnknownIsNotFound", func(t *testing.T) {
		// The application layer switches on app.ErrNotFound; a driver error leaking
		// through here would make every caller import pgx to tell "no such token"
		// from "the database is down".
		if _, err := tokens.ByHash(ctx, "nope"); !errors.Is(err, app.ErrNotFound) {
			t.Fatalf("err = %v, want app.ErrNotFound", err)
		}
	})

	t.Run("ByIDResolvesToken", func(t *testing.T) {
		// The revoke path knows a token's id, not its secret, and has to load the row
		// to check who owns it before it writes.
		owner := newOwner(t, "id-lookup")

		tok, _, err := credentials.Generate(owner.ID, "by-id")
		if err != nil {
			t.Fatalf("generate: %v", err)
		}

		if err := tokens.Create(ctx, tok); err != nil {
			t.Fatalf("create token: %v", err)
		}

		got, err := tokens.ByID(ctx, tok.ID)
		if err != nil {
			t.Fatalf("ByID: %v", err)
		}

		if got.ID != tok.ID || got.UserID != owner.ID || got.Label != tok.Label {
			t.Fatalf("ByID returned %+v, want id %s owner %s label %q",
				got, tok.ID, owner.ID, tok.Label)
		}
	})

	t.Run("ByIDUnknownIsNotFound", func(t *testing.T) {
		if _, err := tokens.ByID(ctx, uuid.New()); !errors.Is(err, app.ErrNotFound) {
			t.Fatalf("err = %v, want app.ErrNotFound", err)
		}
	})

	t.Run("TouchLastUsedOnUnknownTokenIsNotAnError", func(t *testing.T) {
		// Deliberately asymmetric with Save, which does report app.ErrNotFound on zero
		// rows. This call sits on the proxy hot path: a token revoked or deleted
		// between authentication and the stamp must not fail a request that is already
		// being served, or gateway availability starts depending on the tokens table.
		// Making the two consistent is the obvious future edit; this is the test that
		// must stop it.
		if err := tokens.TouchLastUsed(ctx, uuid.New(), time.Now().UTC()); err != nil {
			t.Fatalf("TouchLastUsed on a missing token = %v, want nil", err)
		}
	})

	t.Run("TouchLastUsedPersists", func(t *testing.T) {
		owner := newOwner(t, "batch-runner")

		tok, _, err := credentials.Generate(owner.ID, "runner")
		if err != nil {
			t.Fatalf("generate: %v", err)
		}

		if err := tokens.Create(ctx, tok); err != nil {
			t.Fatalf("create token: %v", err)
		}

		when := time.Now().UTC().Truncate(time.Second)
		if err := tokens.TouchLastUsed(ctx, tok.ID, when); err != nil {
			t.Fatalf("TouchLastUsed: %v", err)
		}

		list, err := tokens.ListByUser(ctx, owner.ID)
		if err != nil {
			t.Fatalf("ListByUser: %v", err)
		}

		if len(list) != 1 || list[0].LastUsedAt == nil || !list[0].LastUsedAt.Equal(when) {
			t.Fatalf("last used not persisted: %+v", list)
		}
	})

	t.Run("TouchLastUsedNeverMovesBackwards", func(t *testing.T) {
		// Stamps arrive in the order requests complete, not start, and from
		// several batches: an older one landing late must not rewind the stamp.
		owner := newOwner(t, "streamer")

		tok, _, err := credentials.Generate(owner.ID, "stream")
		if err != nil {
			t.Fatalf("generate: %v", err)
		}

		if err := tokens.Create(ctx, tok); err != nil {
			t.Fatalf("create token: %v", err)
		}

		later := time.Now().UTC().Truncate(time.Second)
		for _, at := range []time.Time{later, later.Add(-5 * time.Minute)} {
			if err := tokens.TouchLastUsed(ctx, tok.ID, at); err != nil {
				t.Fatalf("TouchLastUsed(%v): %v", at, err)
			}
		}

		got, err := tokens.ByID(ctx, tok.ID)
		if err != nil {
			t.Fatalf("ByID: %v", err)
		}

		if got.LastUsedAt == nil || !got.LastUsedAt.Equal(later) {
			t.Fatalf("last used = %v, want %v: an older stamp moved it back", got.LastUsedAt, later)
		}
	})

	t.Run("SaveRoundTripsRevocation", func(t *testing.T) {
		admin := newOwner(t, "admin-account")
		owner := newOwner(t, "retired-agent")

		tok, secret, err := credentials.Generate(owner.ID, "agent")
		if err != nil {
			t.Fatalf("generate: %v", err)
		}

		if err := tokens.Create(ctx, tok); err != nil {
			t.Fatalf("create token: %v", err)
		}

		when := time.Now().UTC().Truncate(time.Second)
		if err := tok.Revoke(admin.ID, when); err != nil {
			t.Fatalf("Revoke: %v", err)
		}

		if err := tokens.Save(ctx, tok); err != nil {
			t.Fatalf("Save: %v", err)
		}

		// A revoked token still resolves: authentication must be able to tell a
		// revoked credential from an unknown one, and only the stored revocation
		// fields carry that difference.
		got, err := tokens.ByHash(ctx, credentials.HashSecret(secret))
		if err != nil {
			t.Fatalf("ByHash after revoke: %v", err)
		}

		if got.Active() {
			t.Fatalf("revoked token came back active: %+v", got)
		}

		if got.RevokedAt == nil || !got.RevokedAt.Equal(when) {
			t.Fatalf("revoked_at = %v, want %v", got.RevokedAt, when)
		}

		if got.RevokedBy == nil || *got.RevokedBy != admin.ID {
			t.Fatalf("revoked_by = %v, want %s", got.RevokedBy, admin.ID)
		}
	})

	// The limit counts live tokens only, holds under concurrent creates for one
	// owner, and a revocation makes room.
	t.Run("CreateStopsAtTheLiveTokenLimit", func(t *testing.T) {
		owner := newOwner(t, "busy-agent")
		create := func() (credentials.Token, error) {
			tok, _, err := credentials.Generate(owner.ID, "key")
			if err != nil {
				t.Fatalf("generate: %v", err)
			}

			return tok, tokens.Create(ctx, tok)
		}

		revoked, err := create()
		if err != nil {
			t.Fatalf("create: %v", err)
		}

		if err := revoked.Revoke(owner.ID, time.Now()); err != nil {
			t.Fatalf("Revoke: %v", err)
		}

		if err := tokens.Save(ctx, revoked); err != nil {
			t.Fatalf("Save: %v", err)
		}

		var first credentials.Token

		for idx := range app.MaxLiveTokensPerOwner - 3 {
			tok, err := create()
			if err != nil {
				t.Fatalf("create %d: %v", idx, err)
			}

			if idx == 0 {
				first = tok
			}
		}

		// Three places left, eight racing for them.
		errs := make(chan error, 8)
		for range cap(errs) {
			tok, _, err := credentials.Generate(owner.ID, "key")
			if err != nil {
				t.Fatalf("generate: %v", err)
			}

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
				t.Fatalf("racing create: %v", err)
			}
		}

		if created != 3 || refused != 5 {
			t.Fatalf("racing creates: %d created, %d refused, want 3 and 5", created, refused)
		}

		if err := first.Revoke(owner.ID, time.Now()); err != nil {
			t.Fatalf("Revoke: %v", err)
		}

		if err := tokens.Save(ctx, first); err != nil {
			t.Fatalf("Save: %v", err)
		}

		if _, err := create(); err != nil {
			t.Fatalf("create after a revocation: %v, want room for one", err)
		}

		if _, err := create(); !errors.Is(err, app.ErrTokenLimit) {
			t.Fatalf("create past the limit: %v, want app.ErrTokenLimit", err)
		}
	})

	t.Run("CreateForUnknownOwnerIsNotFound", func(t *testing.T) {
		tok, _, err := credentials.Generate(uuid.New(), "orphan")
		if err != nil {
			t.Fatalf("generate: %v", err)
		}

		if err := tokens.Create(ctx, tok); !errors.Is(err, app.ErrNotFound) {
			t.Fatalf("err = %v, want app.ErrNotFound", err)
		}
	})

	t.Run("SaveUnknownTokenIsNotFound", func(t *testing.T) {
		unknown := credentials.Token{ID: uuid.New(), Label: "ghost"}
		if err := tokens.Save(ctx, unknown); !errors.Is(err, app.ErrNotFound) {
			t.Fatalf("err = %v, want app.ErrNotFound", err)
		}
	})
}
