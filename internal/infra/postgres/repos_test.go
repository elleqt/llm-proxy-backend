package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/pgtest"
)

// TestSupportingRepos covers the four smaller repositories on a single container.
// They are grouped because none of them needs a database to itself and each pool
// costs roughly two seconds.
func TestSupportingRepos(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.NewTestPool(t)
	users := postgres.NewUserRepo(pool)

	newUser := func(t *testing.T, name string) uuid.UUID {
		t.Helper()
		u := identity.NewService(uuid.New(), name, access.Policy{})
		if err := users.Create(ctx, u); err != nil {
			t.Fatalf("create user: %v", err)
		}
		return u.ID
	}

	t.Run("Passwords", func(t *testing.T) {
		repo := postgres.NewPasswordRepo(pool)
		id := newUser(t, "password-holder")

		// No password is the normal state of a service or IdP-only account, and it is
		// not the same answer as a wrong password.
		if _, _, err := repo.Get(ctx, id); !errors.Is(err, app.ErrNotFound) {
			t.Fatalf("Get before Set: err = %v, want app.ErrNotFound", err)
		}

		expiry := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
		if err := repo.Set(ctx, id, "hash-one", &expiry); err != nil {
			t.Fatalf("Set: %v", err)
		}
		hash, gotExpiry, err := repo.Get(ctx, id)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if hash != "hash-one" || gotExpiry == nil || !gotExpiry.Equal(expiry) {
			t.Fatalf("Get = %q / %v, want %q / %v", hash, gotExpiry, "hash-one", expiry)
		}

		// Changing a password is the same call as setting one: a second Set must
		// replace the row, and must clear an expiry the new password does not carry.
		if err := repo.Set(ctx, id, "hash-two", nil); err != nil {
			t.Fatalf("Set again: %v", err)
		}
		hash, gotExpiry, err = repo.Get(ctx, id)
		if err != nil {
			t.Fatalf("Get after replace: %v", err)
		}
		if hash != "hash-two" || gotExpiry != nil {
			t.Fatalf("Get = %q / %v, want %q / nil", hash, gotExpiry, "hash-two")
		}
	})

	t.Run("Sessions", func(t *testing.T) {
		repo := postgres.NewSessionRepo(pool)
		id := newUser(t, "session-holder")

		live := app.Session{
			IDHash:    "live-session-hash",
			UserID:    id,
			IP:        "198.51.100.9",
			UserAgent: "a browser",
			CreatedAt: time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond),
			ExpiresAt: time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond),
		}
		if err := repo.Create(ctx, live); err != nil {
			t.Fatalf("Create: %v", err)
		}

		got, err := repo.ByHash(ctx, live.IDHash)
		if err != nil {
			t.Fatalf("ByHash: %v", err)
		}
		if got.UserID != id || got.IP != live.IP || got.UserAgent != live.UserAgent {
			t.Fatalf("ByHash = %+v, want %+v", got, live)
		}
		if !got.CreatedAt.Equal(live.CreatedAt) || !got.ExpiresAt.Equal(live.ExpiresAt) {
			t.Fatalf("window = %v..%v, want %v..%v",
				got.CreatedAt, got.ExpiresAt, live.CreatedAt, live.ExpiresAt)
		}
		// Neither the plaintext id nor a restriction is in the row, so neither can
		// come back out. The restriction is the user's, read at every request.
		if got.ID != "" {
			t.Fatalf("ByHash returned a plaintext session id %q", got.ID)
		}
		if got.Restricted {
			t.Fatal("ByHash reported a restriction: the table has no column for one")
		}

		if _, err := repo.ByHash(ctx, "no-such-session"); !errors.Is(err, app.ErrNotFound) {
			t.Fatalf("ByHash unknown: err = %v, want app.ErrNotFound", err)
		}

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
		if err := repo.Create(ctx, expired); err != nil {
			t.Fatalf("Create expired: %v", err)
		}
		if _, err := repo.ByHash(ctx, expired.IDHash); !errors.Is(err, app.ErrNotFound) {
			t.Fatalf("ByHash expired: err = %v, want app.ErrNotFound", err)
		}
		// A restricted session that the caller marked restricted is stored without
		// it: Create has no column to put it in, so the two facts cannot diverge.
		marked := app.Session{
			IDHash:     "marked-session-hash",
			UserID:     id,
			Restricted: true,
			CreatedAt:  time.Now().UTC(),
			ExpiresAt:  time.Now().UTC().Add(time.Hour),
		}
		if err := repo.Create(ctx, marked); err != nil {
			t.Fatalf("Create marked: %v", err)
		}
		back, err := repo.ByHash(ctx, marked.IDHash)
		if err != nil {
			t.Fatalf("ByHash marked: %v", err)
		}
		if back.Restricted {
			t.Fatal("a restriction survived a round trip through the store")
		}

		if err := repo.Delete(ctx, live.IDHash); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if _, err := repo.ByHash(ctx, live.IDHash); !errors.Is(err, app.ErrNotFound) {
			t.Fatalf("ByHash after Delete: err = %v, want app.ErrNotFound", err)
		}
		// Sign-out is idempotent: a row that expired a second earlier must not make
		// signing out fail.
		if err := repo.Delete(ctx, live.IDHash); err != nil {
			t.Fatalf("Delete again: %v", err)
		}
	})

	t.Run("Identities", func(t *testing.T) {
		repo := postgres.NewIdentityRepo(pool)
		id := newUser(t, "federated-person")
		const issuer, subject = "issuer-a", "subject-1"

		if _, err := repo.BySubject(ctx, issuer, subject); !errors.Is(err, app.ErrNotFound) {
			t.Fatalf("BySubject before Link: err = %v, want app.ErrNotFound", err)
		}
		if err := repo.Link(ctx, id, issuer, subject); err != nil {
			t.Fatalf("Link: %v", err)
		}
		got, err := repo.BySubject(ctx, issuer, subject)
		if err != nil {
			t.Fatalf("BySubject: %v", err)
		}
		if got != id {
			t.Fatalf("BySubject = %s, want %s", got, id)
		}
		// The same subject string issued by a different provider is a different
		// person; matching on subject alone would hand one account to the other IdP.
		if _, err := repo.BySubject(ctx, "issuer-b", subject); !errors.Is(err, app.ErrNotFound) {
			t.Fatalf("cross-issuer BySubject: err = %v, want app.ErrNotFound", err)
		}

		// Relinking an already-claimed subject is a unique violation on
		// (issuer, subject). It has to surface as app.ErrConflict: the OIDC flow must
		// tell "this subject is already linked" from "the database is unreachable",
		// and it cannot import the driver's error type to do it.
		other := newUser(t, "second-person")
		if err := repo.Link(ctx, other, issuer, subject); !errors.Is(err, app.ErrConflict) {
			t.Fatalf("relink: err = %v, want app.ErrConflict", err)
		}
		// And the original link is untouched — a failed relink must not reassign it.
		if got, err := repo.BySubject(ctx, issuer, subject); err != nil || got != id {
			t.Fatalf("after failed relink: %s / %v, want %s", got, err, id)
		}
	})

	t.Run("PendingIdentities", func(t *testing.T) {
		repo := postgres.NewIdentityRepo(pool)
		invited := newUser(t, "invited-person")
		expired := newUser(t, "stale-invite")
		const issuer = "issuer-a"

		addPending(t, ctx, pool, invited, issuer, "invited@example.com", time.Hour)
		addPending(t, ctx, pool, expired, issuer, "stale@example.com", -time.Hour)

		got, err := repo.PendingByEmail(ctx, issuer, "Invited@Example.com")
		if err != nil {
			t.Fatalf("PendingByEmail: %v", err)
		}
		if got != invited {
			t.Fatalf("PendingByEmail = %s, want %s", got, invited)
		}
		// An invitation that has run out must not be redeemable: otherwise whoever
		// later controls the address inherits the account it was reserved for.
		if _, err := repo.PendingByEmail(ctx, issuer, "stale@example.com"); !errors.Is(err, app.ErrNotFound) {
			t.Fatalf("expired invite: err = %v, want app.ErrNotFound", err)
		}

		if err := repo.ConsumePending(ctx, invited); err != nil {
			t.Fatalf("ConsumePending: %v", err)
		}
		if _, err := repo.PendingByEmail(ctx, issuer, "invited@example.com"); !errors.Is(err, app.ErrNotFound) {
			t.Fatalf("after ConsumePending: err = %v, want app.ErrNotFound", err)
		}
	})

	t.Run("LoginAttempts", func(t *testing.T) {
		repo := postgres.NewLoginAttemptRepo(pool)
		const email = "throttled@example.com"
		const limit = 3
		now := time.Now().UTC().Truncate(time.Second)
		window := now.Add(15 * time.Minute)

		// An address that has never failed is not a missing row to report, it is zero
		// failures; the throttle must not special-case the first attempt.
		count, locked, err := repo.Failures(ctx, email)
		if err != nil || count != 0 || locked != nil {
			t.Fatalf("Failures on unseen address = %d / %v / %v, want 0 / nil / nil", count, locked, err)
		}

		if _, _, err := repo.Charge(ctx, email, limit, now, window); err != nil {
			t.Fatalf("Charge: %v", err)
		}
		// Varying the capitalisation must not open a second counter, or the lockout is
		// trivially bypassed.
		count, locked, err = repo.Charge(ctx, "Throttled@Example.COM", limit, now, window)
		if err != nil || count != 2 || locked != nil {
			t.Fatalf("Charge mixed case = %d / %v / %v, want 2 / nil / nil", count, locked, err)
		}
		count, locked, err = repo.Failures(ctx, email)
		if err != nil || count != 2 || locked != nil {
			t.Fatalf("Failures = %d / %v / %v, want 2 / nil / nil", count, locked, err)
		}

		if err := repo.Clear(ctx, email); err != nil {
			t.Fatalf("Clear: %v", err)
		}
		count, locked, err = repo.Failures(ctx, email)
		if err != nil || count != 0 || locked != nil {
			t.Fatalf("after Clear = %d / %v / %v, want 0 / nil / nil", count, locked, err)
		}
	})

	// The point of Charge being one statement: a burst against one address is
	// serialised by the database, so every attempt gets its own count and the lock
	// lands on exactly the limit-th one. A read followed by a write would hand several
	// attempts the same count and let the burst run past the limit.
	t.Run("LoginAttemptsChargeIsAtomicUnderABurst", func(t *testing.T) {
		repo := postgres.NewLoginAttemptRepo(pool)
		const email = "burst@example.com"
		const burst, limit = 12, 4
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
			r := <-results
			if r.err != nil {
				t.Fatalf("Charge: %v", r.err)
			}
			if seen[r.count] {
				t.Fatalf("two charges saw count %d: the increment is not atomic", r.count)
			}
			seen[r.count] = true
			switch {
			case r.count < limit && r.locked != nil:
				t.Fatalf("count %d is under the limit %d but locked until %v", r.count, limit, r.locked)
			case r.count >= limit && (r.locked == nil || !r.locked.Equal(window)):
				// Past the limit the window must stay where the limit-th charge put
				// it: a burst must not push the unlock further away.
				t.Fatalf("count %d: locked until %v, want %v", r.count, r.locked, window)
			}
		}
		for c := 1; c <= burst; c++ {
			if !seen[c] {
				t.Fatalf("counts %v are not exactly 1..%d", seen, burst)
			}
		}
	})

	// The limit is per window. After a lock lapses the count starts over: limit-1
	// failures in the new window leave the address unlocked, the limit-th locks it
	// again with a new window.
	t.Run("LoginAttemptsLapsedLockRestartsTheCount", func(t *testing.T) {
		repo := postgres.NewLoginAttemptRepo(pool)
		const email = "lapsed@example.com"
		const limit = 3
		first := time.Now().UTC().Truncate(time.Second)
		firstWindow := first.Add(time.Minute)
		for range limit {
			if _, _, err := repo.Charge(ctx, email, limit, first, firstWindow); err != nil {
				t.Fatalf("Charge: %v", err)
			}
		}

		later := firstWindow
		laterWindow := later.Add(time.Minute)
		for want := 1; want < limit; want++ {
			count, locked, err := repo.Charge(ctx, email, limit, later, laterWindow)
			if err != nil || count != want || locked != nil {
				t.Fatalf("Charge %d after the window = %d / %v / %v, want %d / nil / nil",
					want, count, locked, err, want)
			}
		}
		count, locked, err := repo.Charge(ctx, email, limit, later, laterWindow)
		if err != nil || count != limit || locked == nil || !locked.Equal(laterWindow) {
			t.Fatalf("limit-th Charge after the window = %d / %v / %v, want %d / %v / nil",
				count, locked, err, limit, laterWindow)
		}
	})

	// Failures that never reached the limit are stale once the last one is a window
	// old: the next charge starts at 1. A second short of that, they still count.
	t.Run("LoginAttemptsStaleCountRestarts", func(t *testing.T) {
		repo := postgres.NewLoginAttemptRepo(pool)
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
				if _, _, err := repo.Charge(ctx, tc.email, limit, first, first.Add(time.Minute)); err != nil {
					t.Fatalf("Charge: %v", err)
				}
			}
			count, _, err := repo.Charge(ctx, tc.email, limit, tc.at, tc.at.Add(time.Minute))
			if err != nil || count != tc.want {
				t.Fatalf("%s: Charge %v after the last failure = %d / %v, want %d / nil",
					tc.email, tc.at.Sub(first), count, err, tc.want)
			}
		}
	})

	t.Run("Audit", func(t *testing.T) {
		sink := postgres.NewAuditSink(pool)
		actor := newUser(t, "auditor")

		at := time.Now().UTC().Truncate(time.Second)
		if err := sink.Record(ctx, app.AuditEvent{
			At:        at,
			ActorID:   actor,
			Action:    "token.revoke",
			Target:    "token/abc",
			Detail:    map[string]any{"reason": "rotation"},
			IP:        "203.0.113.7",
			UserAgent: "test-agent",
		}); err != nil {
			t.Fatalf("Record: %v", err)
		}
		// actor_user_id carries a foreign key to users, so an unset actor has to be
		// stored as NULL; binding the zero UUID would fail the key and lose exactly
		// the system-initiated events the log exists to keep.
		if err := sink.Record(ctx, app.AuditEvent{Action: "system.startup"}); err != nil {
			t.Fatalf("Record without actor: %v", err)
		}

		var (
			gotActor  *uuid.UUID
			gotTarget string
			gotDetail []byte
			gotAt     time.Time
		)
		if err := pool.QueryRow(ctx,
			`SELECT actor_user_id, target, detail, at FROM audit_events WHERE action = $1`,
			"token.revoke").Scan(&gotActor, &gotTarget, &gotDetail, &gotAt); err != nil {
			t.Fatalf("read back: %v", err)
		}
		if gotActor == nil || *gotActor != actor {
			t.Fatalf("actor = %v, want %s", gotActor, actor)
		}
		if gotTarget != "token/abc" || string(gotDetail) != `{"reason": "rotation"}` {
			t.Fatalf("target = %q detail = %s", gotTarget, gotDetail)
		}
		if !gotAt.Equal(at) {
			t.Fatalf("at = %v, want %v", gotAt, at)
		}

		var systemActor *uuid.UUID
		var systemDetail []byte
		if err := pool.QueryRow(ctx,
			`SELECT actor_user_id, detail FROM audit_events WHERE action = $1`,
			"system.startup").Scan(&systemActor, &systemDetail); err != nil {
			t.Fatalf("read back system event: %v", err)
		}
		if systemActor != nil {
			t.Fatalf("system actor = %v, want NULL", systemActor)
		}
		// A nil detail map must land as an empty object, not JSON null, so consumers
		// have one empty shape to handle rather than two.
		if string(systemDetail) != "{}" {
			t.Fatalf("detail = %s, want {}", systemDetail)
		}
	})
}

func addPending(t *testing.T, ctx context.Context, pool *pgxpool.Pool, userID uuid.UUID, issuer, email string, ttl time.Duration) {
	t.Helper()
	if _, err := pool.Exec(ctx,
		`INSERT INTO pending_identities (user_id, issuer, expected_email, expires_at)
		 VALUES ($1, $2, $3, $4)`,
		userID, issuer, email, time.Now().UTC().Add(ttl)); err != nil {
		t.Fatalf("seed pending identity: %v", err)
	}
}
