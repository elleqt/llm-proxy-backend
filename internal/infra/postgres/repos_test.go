package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/audit"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/identities"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/loginattempts"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/passwords"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/pgtest"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/sessions"
	pgusers "github.com/elleqt/llm-proxy-backend/internal/infra/postgres/users"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// TestSupportingRepos covers the four smaller repositories on a single container.
// They are grouped because none of them needs a database to itself and each pool
// costs roughly two seconds.
func TestSupportingRepos(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.NewTestPool(t)
	users := pgusers.New(pool)

	newUser := func(t *testing.T, name string) uuid.UUID {
		t.Helper()

		u := identity.NewService(uuid.New(), name, access.Policy{})
		require.NoError(t, users.Create(ctx, u), "create user")

		return u.ID
	}

	t.Run("Passwords", func(t *testing.T) {
		repo := passwords.New(pool)
		id := newUser(t, "password-holder")

		// No password is the normal state of a service or IdP-only account, and it is
		// not the same answer as a wrong password.
		_, _, err := repo.Get(ctx, id)
		require.ErrorIs(t, err, app.ErrNotFound, "Get before Set")

		expiry := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
		require.NoError(t, repo.Set(ctx, id, "hash-one", &expiry), "Set")

		hash, gotExpiry, err := repo.Get(ctx, id)
		require.NoError(t, err, "Get")
		require.Equal(t, "hash-one", hash)
		require.NotNil(t, gotExpiry)
		require.WithinDuration(t, expiry, *gotExpiry, 0, "expiry")

		// Changing a password is the same call as setting one: a second Set must
		// replace the row, and must clear an expiry the new password does not carry.
		require.NoError(t, repo.Set(ctx, id, "hash-two", nil), "Set again")

		hash, gotExpiry, err = repo.Get(ctx, id)
		require.NoError(t, err, "Get after replace")
		require.Equal(t, "hash-two", hash)
		require.Nil(t, gotExpiry)
	})

	t.Run("Sessions", func(t *testing.T) {
		repo := sessions.New(pool)
		id := newUser(t, "session-holder")

		live := app.Session{
			IDHash:    "live-session-hash",
			UserID:    id,
			IP:        "198.51.100.9",
			UserAgent: "a browser",
			CreatedAt: time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond),
			ExpiresAt: time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond),
		}
		require.NoError(t, repo.Create(ctx, live), "Create")

		got, err := repo.ByHash(ctx, live.IDHash)
		require.NoError(t, err, "ByHash")
		require.Equal(t, id, got.UserID, "ByHash UserID")
		require.Equal(t, live.IP, got.IP, "ByHash IP")
		require.Equal(t, live.UserAgent, got.UserAgent, "ByHash UserAgent")
		require.WithinDuration(t, live.CreatedAt, got.CreatedAt, 0, "window start")
		require.WithinDuration(t, live.ExpiresAt, got.ExpiresAt, 0, "window end")
		// Neither the plaintext id nor a restriction is in the row, so neither can
		// come back out. The restriction is the user's, read at every request.
		require.Empty(t, got.ID, "ByHash returned a plaintext session id")
		require.False(t, got.Restricted, "ByHash reported a restriction: the table has no column for one")

		_, err = repo.ByHash(ctx, "no-such-session")
		require.ErrorIs(t, err, app.ErrNotFound, "ByHash unknown")

		// The expiry is enforced by the query against the database's clock, not by
		// the caller against its own. A session that outlived its window is gone to
		// every reader, and no amount of clock skew in a gateway process brings it
		// back.
		expired := app.Session{
			IDHash:    "expired-session-hash",
			UserID:    id,
			CreatedAt: time.Now().UTC().Add(-2 * time.Hour),
			ExpiresAt: time.Now().UTC().Add(-time.Second),
		}
		require.NoError(t, repo.Create(ctx, expired), "Create expired")

		_, err = repo.ByHash(ctx, expired.IDHash)
		require.ErrorIs(t, err, app.ErrNotFound, "ByHash expired")
		// A restricted session that the caller marked restricted is stored without
		// it: Create has no column to put it in, so the two facts cannot diverge.
		marked := app.Session{
			IDHash:     "marked-session-hash",
			UserID:     id,
			Restricted: true,
			CreatedAt:  time.Now().UTC(),
			ExpiresAt:  time.Now().UTC().Add(time.Hour),
		}
		require.NoError(t, repo.Create(ctx, marked), "Create marked")

		back, err := repo.ByHash(ctx, marked.IDHash)
		require.NoError(t, err, "ByHash marked")
		require.False(t, back.Restricted, "a restriction survived a round trip through the store")

		require.NoError(t, repo.Delete(ctx, live.IDHash), "Delete")

		_, err = repo.ByHash(ctx, live.IDHash)
		require.ErrorIs(t, err, app.ErrNotFound, "ByHash after Delete")
		// Sign-out is idempotent: a row that expired a second earlier must not make
		// signing out fail.
		require.NoError(t, repo.Delete(ctx, live.IDHash), "Delete again")
	})

	t.Run("Identities", func(t *testing.T) {
		repo := identities.New(pool)
		id := newUser(t, "federated-person")

		const issuer, subject = "issuer-a", "subject-1"

		_, err := repo.BySubject(ctx, issuer, subject)
		require.ErrorIs(t, err, app.ErrNotFound, "BySubject before Link")
		require.NoError(t, repo.Link(ctx, id, issuer, subject), "Link")

		got, err := repo.BySubject(ctx, issuer, subject)
		require.NoError(t, err, "BySubject")
		require.Equal(t, id, got, "BySubject")
		// The same subject string issued by a different provider is a different
		// person; matching on subject alone would hand one account to the other IdP.
		_, err = repo.BySubject(ctx, "issuer-b", subject)
		require.ErrorIs(t, err, app.ErrNotFound, "cross-issuer BySubject")

		// Relinking an already-claimed subject is a unique violation on
		// (issuer, subject). It has to surface as app.ErrConflict: the OIDC flow must
		// tell "this subject is already linked" from "the database is unreachable",
		// and it cannot import the driver's error type to do it.
		other := newUser(t, "second-person")
		require.ErrorIs(t, repo.Link(ctx, other, issuer, subject), app.ErrConflict, "relink")
		// And the original link is untouched — a failed relink must not reassign it.
		got, err = repo.BySubject(ctx, issuer, subject)
		require.NoError(t, err, "after failed relink")
		require.Equal(t, id, got, "after failed relink")
	})

	t.Run("PendingIdentities", func(t *testing.T) {
		repo := identities.New(pool)
		invited := newUser(t, "invited-person")
		expired := newUser(t, "stale-invite")

		const issuer = "issuer-a"

		addPending(ctx, t, pool, invited, issuer, "invited@example.com", time.Hour)
		addPending(ctx, t, pool, expired, issuer, "stale@example.com", -time.Hour)

		got, err := repo.PendingByEmail(ctx, issuer, "Invited@Example.com")
		require.NoError(t, err, "PendingByEmail")
		require.Equal(t, invited, got, "PendingByEmail")
		// An invitation that has run out must not be redeemable: otherwise whoever
		// later controls the address inherits the account it was reserved for.
		_, err = repo.PendingByEmail(ctx, issuer, "stale@example.com")
		require.ErrorIs(t, err, app.ErrNotFound, "expired invite")
		require.NoError(t, repo.ConsumePending(ctx, invited), "ConsumePending")

		_, err = repo.PendingByEmail(ctx, issuer, "invited@example.com")
		require.ErrorIs(t, err, app.ErrNotFound, "after ConsumePending")
	})

	t.Run("LoginAttempts", func(t *testing.T) {
		repo := loginattempts.New(pool)

		const (
			email = "throttled@example.com"
			limit = 3
		)

		now := time.Now().UTC().Truncate(time.Second)
		window := now.Add(15 * time.Minute)

		// An address that has never failed is not a missing row to report, it is zero
		// failures; the throttle must not special-case the first attempt.
		count, locked, err := repo.Failures(ctx, email)
		require.NoError(t, err, "Failures on unseen address")
		require.Zero(t, count, "Failures on unseen address")
		require.Nil(t, locked, "Failures on unseen address")

		_, _, err = repo.Charge(ctx, email, limit, now, window)
		require.NoError(t, err, "Charge")
		// Varying the capitalisation must not open a second counter, or the lockout is
		// trivially bypassed.
		count, locked, err = repo.Charge(ctx, "Throttled@Example.COM", limit, now, window)
		require.NoError(t, err, "Charge mixed case")
		require.Equal(t, 2, count, "Charge mixed case")
		require.Nil(t, locked, "Charge mixed case")

		count, locked, err = repo.Failures(ctx, email)
		require.NoError(t, err, "Failures")
		require.Equal(t, 2, count, "Failures")
		require.Nil(t, locked, "Failures")
		require.NoError(t, repo.Clear(ctx, email), "Clear")

		count, locked, err = repo.Failures(ctx, email)
		require.NoError(t, err, "after Clear")
		require.Zero(t, count, "after Clear")
		require.Nil(t, locked, "after Clear")
	})

	// The point of Charge being one statement: a burst against one address is
	// serialised by the database, so every attempt gets its own count and the lock
	// lands on exactly the limit-th one. A read followed by a write would hand several
	// attempts the same count and let the burst run past the limit.
	t.Run("LoginAttemptsChargeIsAtomicUnderABurst", func(t *testing.T) {
		repo := loginattempts.New(pool)

		const (
			email        = "burst@example.com"
			burst, limit = 12, 4
		)

		now := time.Now().UTC().Truncate(time.Second)
		window := now.Add(15 * time.Minute)

		type charged struct {
			count  int
			locked *time.Time
			err    error
		}

		results := make(chan charged, burst)
		start := make(chan struct{})

		for range burst {
			go func() {
				<-start

				c, l, err := repo.Charge(ctx, email, limit, now, window)
				results <- charged{c, l, err}
			}()
		}

		close(start)

		seen := make(map[int]bool, burst)
		for range burst {
			result := <-results
			require.NoError(t, result.err, "Charge")
			require.False(t, seen[result.count], "two charges saw count %d: the increment is not atomic", result.count)

			seen[result.count] = true
			if result.count < limit {
				require.Nil(t, result.locked, "count %d is under the limit %d but locked", result.count, limit)

				continue
			}
			// Past the limit the window must stay where the limit-th charge put
			// it: a burst must not push the unlock further away.
			require.NotNil(t, result.locked, "count %d: not locked", result.count)
			require.WithinDuration(t, window, *result.locked, 0, "count %d: locked until", result.count)
		}

		for c := 1; c <= burst; c++ {
			require.True(t, seen[c], "counts %v are not exactly 1..%d", seen, burst)
		}
	})

	// The limit is per window. After a lock lapses the count starts over: limit-1
	// failures in the new window leave the address unlocked, the limit-th locks it
	// again with a new window.
	t.Run("LoginAttemptsLapsedLockRestartsTheCount", func(t *testing.T) {
		repo := loginattempts.New(pool)

		const (
			email = "lapsed@example.com"
			limit = 3
		)

		first := time.Now().UTC().Truncate(time.Second)

		firstWindow := first.Add(time.Minute)
		for range limit {
			_, _, err := repo.Charge(ctx, email, limit, first, firstWindow)
			require.NoError(t, err, "Charge")
		}

		later := firstWindow

		laterWindow := later.Add(time.Minute)
		for want := 1; want < limit; want++ {
			count, locked, err := repo.Charge(ctx, email, limit, later, laterWindow)
			require.NoError(t, err, "Charge %d after the window", want)
			require.Equal(t, want, count, "Charge %d after the window", want)
			require.Nil(t, locked, "Charge %d after the window", want)
		}

		count, locked, err := repo.Charge(ctx, email, limit, later, laterWindow)
		require.NoError(t, err, "limit-th Charge after the window")
		require.Equal(t, limit, count, "limit-th Charge after the window")
		require.NotNil(t, locked, "limit-th Charge after the window")
		require.WithinDuration(t, laterWindow, *locked, 0, "limit-th Charge after the window")
	})

	// Failures that never reached the limit are stale once the last one is a window
	// old: the next charge starts at 1. A second short of that, they still count.
	t.Run("LoginAttemptsStaleCountRestarts", func(t *testing.T) {
		repo := loginattempts.New(pool)

		const limit = 3

		first := time.Now().UTC().Truncate(time.Second)
		for _, tc := range []struct {
			email string
			at    time.Time
			want  int
		}{
			{"stale-inside@example.com", first.Add(time.Minute - time.Second), limit},
			{"stale-outside@example.com", first.Add(time.Minute), 1},
		} {
			for range limit - 1 {
				_, _, err := repo.Charge(ctx, tc.email, limit, first, first.Add(time.Minute))
				require.NoError(t, err, "Charge")
			}

			count, _, err := repo.Charge(ctx, tc.email, limit, tc.at, tc.at.Add(time.Minute))
			require.NoError(t, err, "%s: Charge %v after the last failure", tc.email, tc.at.Sub(first))
			require.Equal(t, tc.want, count, "%s: Charge %v after the last failure", tc.email, tc.at.Sub(first))
		}
	})

	t.Run("Audit", func(t *testing.T) {
		sink := audit.New(pool)
		actor := newUser(t, "auditor")

		at := time.Now().UTC().Truncate(time.Second)
		require.NoError(t, sink.Record(ctx, app.AuditEvent{
			At:        at,
			ActorID:   actor,
			Action:    "token.revoke",
			Target:    "token/abc",
			Detail:    map[string]any{"reason": "rotation"},
			IP:        "203.0.113.7",
			UserAgent: "test-agent",
		}), "Record")
		// actor_user_id carries a foreign key to users, so an unset actor has to be
		// stored as NULL; binding the zero UUID would fail the key and lose exactly
		// the system-initiated events the log exists to keep.
		require.NoError(t, sink.Record(ctx, app.AuditEvent{Action: "system.startup"}), "Record without actor")

		var (
			gotActor  *uuid.UUID
			gotTarget string
			gotDetail []byte
			gotAt     time.Time
		)

		err := pool.QueryRow(ctx,
			`SELECT actor_user_id, target, detail, at FROM audit_events WHERE action = $1`,
			"token.revoke").Scan(&gotActor, &gotTarget, &gotDetail, &gotAt)
		require.NoError(t, err, "read back")
		require.NotNil(t, gotActor, "actor")
		require.Equal(t, actor, *gotActor, "actor")
		require.Equal(t, "token/abc", gotTarget, "target")
		require.JSONEq(t, `{"reason": "rotation"}`, string(gotDetail), "detail")
		require.WithinDuration(t, at, gotAt, 0, "at")

		var (
			systemActor  *uuid.UUID
			systemDetail []byte
		)

		err = pool.QueryRow(ctx,
			`SELECT actor_user_id, detail FROM audit_events WHERE action = $1`,
			"system.startup").Scan(&systemActor, &systemDetail)
		require.NoError(t, err, "read back system event")
		require.Nil(t, systemActor, "system actor")
		// A nil detail map must land as an empty object, not JSON null, so consumers
		// have one empty shape to handle rather than two.
		require.Equal(t, "{}", string(systemDetail), "detail")
	})
}

func addPending(ctx context.Context, t *testing.T, pool *pgxpool.Pool, userID uuid.UUID, issuer, email string, ttl time.Duration) {
	t.Helper()

	_, err := pool.Exec(ctx,
		`INSERT INTO pending_identities (user_id, issuer, expected_email, expires_at)
		 VALUES ($1, $2, $3, $4)`,
		userID, issuer, email, time.Now().UTC().Add(ttl))
	require.NoError(t, err, "seed pending identity")
}
