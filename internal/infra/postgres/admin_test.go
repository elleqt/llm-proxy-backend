package postgres_test

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/domain/credentials"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/pgtest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAdminRepos covers the repository methods the administration service reads and
// writes through, on one container.
func TestAdminRepos(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.NewTestPool(t)
	users := postgres.NewUserRepo(pool)
	passwords := postgres.NewPasswordRepo(pool)
	idents := postgres.NewIdentityRepo(pool)

	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	seq := 0
	human := func(t *testing.T, email, name string) identity.User {
		t.Helper()

		seq++

		user := identity.User{
			ID: uuid.New(), Kind: identity.KindHuman, Email: email, DisplayName: name,
			Role: identity.RoleUser, Status: identity.StatusActive, PolicySource: identity.PolicyLocal,
			CreatedAt: base.Add(time.Duration(seq) * time.Second),
		}
		require.NoError(t, users.Create(ctx, user), "create %s", name)

		return user
	}

	t.Run("ListAndView", func(t *testing.T) {
		alice := human(t, "alice@example.com", "Alice")
		bob := human(t, "bob@example.com", "Bob")
		carol := human(t, "carol@example.com", "Carol")
		dave := human(t, "dave@example.com", "Dave")
		seq++
		bot := identity.NewService(uuid.New(), "chat-panel", access.Policy{})

		bot.CreatedAt = base.Add(time.Duration(seq) * time.Second)
		require.NoError(t, users.Create(ctx, bot), "create bot")

		eve := human(t, "eve@example.com", "Eve")
		fay := human(t, "fay@example.com", "Fay")
		gus := human(t, "gus@example.com", "Gus")

		lapsed := time.Now().UTC().Add(-time.Minute)
		for id, exp := range map[uuid.UUID]*time.Time{alice.ID: nil, eve.ID: nil, fay.ID: &lapsed} {
			require.NoError(t, passwords.Set(ctx, id, "hash", exp), "set password")
		}

		for i, id := range []uuid.UUID{bob.ID, eve.ID, gus.ID} {
			require.NoError(t, idents.Link(ctx, id, "issuer-a", "subject-"+string(rune('a'+i))), "link")
		}

		addPending(ctx, t, pool, carol.ID, "issuer-a", carol.Email, time.Hour)
		addPending(ctx, t, pool, dave.ID, "issuer-a", dave.Email, -time.Hour)
		// A leftover invitation beside a link has nothing left to claim.
		addPending(ctx, t, pool, gus.ID, "issuer-a", gus.Email, time.Hour)

		pw, oidc := app.SignInPassword, app.SignInOIDC
		want := map[uuid.UUID]struct {
			signIn  []app.SignInMethod
			invited bool
		}{
			alice.ID: {[]app.SignInMethod{pw}, false},
			bob.ID:   {[]app.SignInMethod{oidc}, false},
			carol.ID: {[]app.SignInMethod{}, true},
			dave.ID:  {[]app.SignInMethod{}, true}, // lapsed, still shown so it can be renewed
			bot.ID:   {[]app.SignInMethod{}, false},
			eve.ID:   {[]app.SignInMethod{pw, oidc}, false},
			fay.ID:   {[]app.SignInMethod{}, false}, // expired temporary password
			gus.ID:   {[]app.SignInMethod{oidc}, false},
		}

		all, err := users.List(ctx)
		require.NoError(t, err, "List")

		order := []uuid.UUID{alice.ID, bob.ID, carol.ID, dave.ID, bot.ID, eve.ID, fay.ID, gus.ID}
		require.Equal(t, order, viewIDs(all), "List order, want oldest first")

		for _, view := range all {
			expected := want[view.User.ID]
			assert.Equal(t, expected.signIn, view.SignIn, "%s: sign-in", view.User.DisplayName)
			assert.Equal(t, expected.invited, view.InvitationExpiresAt != nil,
				"%s: invitation expiry = %v, want set: %v", view.User.DisplayName, view.InvitationExpiresAt, expected.invited)
		}

		// want the lapsed invitation's expiry
		daveView, err := users.View(ctx, dave.ID)
		require.NoError(t, err, "View")
		require.Equal(t, dave.Email, daveView.User.Email, "View email")
		require.NotNil(t, daveView.InvitationExpiresAt, "View invitation expiry")
		require.True(t, daveView.InvitationExpiresAt.Before(time.Now()), "View invitation expiry %v is not lapsed", *daveView.InvitationExpiresAt)

		_, err = users.View(ctx, uuid.New())
		require.ErrorIs(t, err, app.ErrNotFound, "View unknown")
	})

	t.Run("UpdateAdminState", func(t *testing.T) {
		user := human(t, "hana@example.com", "Hana")
		require.NoError(t, users.SetMustChangePassword(ctx, user.ID, true), "SetMustChangePassword")
		// A rename and a block racing each other: each writes only its own column,
		// so both land whichever commits first.
		name, blocked := "Hana H.", identity.StatusBlocked

		var wg sync.WaitGroup

		errs := make([]error, 2)

		for i, ch := range []app.AdminChange{{DisplayName: &name}, {Status: &blocked}} {
			wg.Go(func() {
				errs[i] = users.UpdateAdminState(ctx, user.ID, ch)
			})
		}

		wg.Wait()

		require.NoError(t, errors.Join(errs...), "UpdateAdminState")

		admin, policy := identity.RoleAdmin, mustPolicy(t, "alpha:model-*")
		err := users.UpdateAdminState(ctx, user.ID, app.AdminChange{Role: &admin, Policy: &policy})
		require.NoError(t, err, "UpdateAdminState role+policy")

		got, err := users.ByID(ctx, user.ID)
		require.NoError(t, err, "ByID")
		// An edit was lost if any of these differ.
		require.Equal(t, name, got.DisplayName, "display name")
		require.Equal(t, identity.StatusBlocked, got.Status, "status")
		require.Equal(t, identity.RoleAdmin, got.Role, "role")
		require.True(t, got.Policy.Allows("alpha", "model-x"), "policy lost: %+v", got.Policy)
		require.Equal(t, identity.PolicyLocal, got.PolicySource, "policy source")
		// UpdateAdminState widened its write if any of these changed.
		require.Equal(t, "hana@example.com", got.Email, "email")
		require.True(t, got.MustChangePassword, "must change password")

		// The IdP lock is decided by the write itself, against the stored source.
		fed := human(t, "ian@example.com", "Ian")

		fed.Policy, fed.PolicySource = mustPolicy(t, "beta:*"), identity.PolicyIDP
		require.NoError(t, users.SaveIdentityState(ctx, fed), "SaveIdentityState")

		err = users.UpdateAdminState(ctx, fed.ID, app.AdminChange{Policy: &policy, RefuseIDPPolicy: true})
		require.ErrorIs(t, err, app.ErrPolicyManagedByIDP, "locked policy")

		got, _ = users.ByID(ctx, fed.ID)
		require.Equal(t, identity.PolicyIDP, got.PolicySource, "a refused edit was written")
		require.True(t, got.Policy.Allows("beta", "m"), "a refused edit was written: %+v", got)

		require.NoError(t, users.UpdateAdminState(ctx, fed.ID, app.AdminChange{Policy: &policy}), "unlocked policy")

		got, _ = users.ByID(ctx, fed.ID)
		require.Equal(t, identity.PolicyLocal, got.PolicySource, "frozen idp policy not converted")
		require.False(t, got.Policy.Allows("beta", "m"), "frozen idp policy not converted: %+v", got)

		err = users.UpdateAdminState(ctx, uuid.New(), app.AdminChange{DisplayName: &name})
		require.ErrorIs(t, err, app.ErrNotFound, "unknown user")
	})

	// The shell's unblock: the status and its audit row land together or not at all.
	t.Run("Unblock", func(t *testing.T) {
		user := human(t, "locked@example.com", "Locked")

		blocked := identity.StatusBlocked
		require.NoError(t, users.UpdateAdminState(ctx, user.ID, app.AdminChange{Status: &blocked}), "block")

		status := func() identity.Status {
			t.Helper()

			got, err := users.ByID(ctx, user.ID)
			require.NoError(t, err, "ByID")

			return got.Status
		}
		event := func(actor uuid.UUID) app.AuditEvent {
			return app.AuditEvent{
				At: time.Now(), ActorID: actor, Action: "user.update", Target: user.ID.String(),
				Detail: map[string]any{"via": "cli", "status": "active"},
			}
		}
		// The audit row fails (its actor does not exist): the account stays blocked.
		require.Error(t, users.Unblock(ctx, user.ID, event(uuid.New())), "Unblock succeeded with an audit row that cannot be written")
		require.Equal(t, identity.StatusBlocked, status(), "status after a failed unblock")

		require.NoError(t, users.Unblock(ctx, user.ID, event(uuid.Nil)), "Unblock")
		require.Equal(t, identity.StatusActive, status(), "status")

		var n int

		err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE target = $1 AND action = 'user.update'
		   AND actor_user_id IS NULL AND detail->>'via' = 'cli'`, user.ID.String()).Scan(&n)
		require.NoError(t, err, "unblock audit rows")
		require.Equal(t, 1, n, "unblock audit rows")

		require.ErrorIs(t, users.Unblock(ctx, uuid.New(), event(uuid.Nil)), app.ErrNotFound, "unknown user")
	})

	t.Run("CreateAccount", func(t *testing.T) {
		actor := human(t, "creator@example.com", "Creator")
		expiry := time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)
		account := func(actorID uuid.UUID) app.NewAccount {
			user := identity.User{
				ID: uuid.New(), Kind: identity.KindHuman, Email: "Jo@Example.com", DisplayName: "Jo",
				Role: identity.RoleUser, Status: identity.StatusActive, PolicySource: identity.PolicyLocal, MustChangePassword: true,
			}

			return app.NewAccount{
				User:     user,
				Password: &app.StoredPassword{Hash: "temp-hash", ExpiresAt: &expiry},
				Audit:    app.AuditEvent{ActorID: actorID, Action: "user.create", Target: user.ID.String()},
			}
		}
		count := func(t *testing.T, query string, args ...any) int {
			t.Helper()

			var n int
			require.NoError(t, pool.QueryRow(ctx, query, args...).Scan(&n), "count")

			return n
		}

		// The audit row is the last write, and it fails (its actor does not exist).
		// Everything before it must go with it.
		failed := account(uuid.New())
		require.Error(t, users.CreateAccount(ctx, failed), "CreateAccount succeeded with an audit row that cannot be written")
		require.Zero(t, count(t, `SELECT count(*) FROM users WHERE lower(email) = 'jo@example.com'`), "a failed creation left user rows")
		require.Zero(t, count(t, `SELECT count(*) FROM user_passwords WHERE user_id = $1`, failed.User.ID), "a failed creation left a password")
		require.Zero(t, count(t, `SELECT count(*) FROM audit_events WHERE target = $1`, failed.User.ID.String()), "a failed creation left an audit row")

		// So the retry finds nothing in its way.
		retry := account(actor.ID)
		require.NoError(t, users.CreateAccount(ctx, retry), "retry")

		hash, exp, err := passwords.Get(ctx, retry.User.ID)
		require.NoError(t, err, "password")
		require.Equal(t, "temp-hash", hash, "password hash")
		require.NotNil(t, exp, "password expiry")
		require.True(t, exp.Equal(expiry), "password expiry = %v, want %v", *exp, expiry)

		auditRows := count(t, `SELECT count(*) FROM audit_events WHERE target = $1 AND action = 'user.create'`, retry.User.ID.String())
		require.Equal(t, 1, auditRows, "audit rows")

		require.ErrorIs(t, users.CreateAccount(ctx, account(actor.ID)), app.ErrConflict, "same address again")

		// An invitation is written in the same unit.
		invited := account(actor.ID)
		invited.User.Email, invited.Password = "kim@example.com", nil

		invited.Invitation = &app.Invitation{Issuer: "https://idp.example.com/", Email: "kim@example.com", ExpiresAt: expiry}
		require.NoError(t, users.CreateAccount(ctx, invited), "CreateAccount invited")

		got, err := idents.PendingByEmail(ctx, "https://idp.example.com/", "kim@example.com")
		require.NoError(t, err, "PendingByEmail")
		require.Equal(t, invited.User.ID, got, "PendingByEmail")
	})

	t.Run("SessionsDeleteByUser", func(t *testing.T) {
		repo := postgres.NewSessionRepo(pool)
		target, bystander := human(t, "gina@example.com", "Gina"), human(t, "hal@example.com", "Hal")

		now := time.Now().UTC()
		for i, s := range []app.Session{
			{IDHash: "gina-1", UserID: target.ID}, {IDHash: "gina-2", UserID: target.ID}, {IDHash: "hal-1", UserID: bystander.ID},
		} {
			s.CreatedAt, s.ExpiresAt = now, now.Add(time.Duration(i+1)*time.Hour)
			require.NoError(t, repo.Create(ctx, s), "Create")
		}

		require.NoError(t, repo.DeleteByUser(ctx, target.ID), "DeleteByUser")

		for _, h := range []string{"gina-1", "gina-2"} {
			_, err := repo.ByHash(ctx, h)
			require.ErrorIs(t, err, app.ErrNotFound, "%s survived DeleteByUser", h)
		}

		_, err := repo.ByHash(ctx, "hal-1")
		require.NoError(t, err, "another user's session was deleted")

		require.NoError(t, repo.DeleteByUser(ctx, target.ID), "DeleteByUser with nothing left")
	})

	t.Run("SessionsDeleteByUserExcept", func(t *testing.T) {
		repo := postgres.NewSessionRepo(pool)
		target, bystander := human(t, "iris@example.com", "Iris"), human(t, "jon@example.com", "Jon")

		now := time.Now().UTC()
		for _, session := range []app.Session{
			{IDHash: "iris-kept", UserID: target.ID},
			{IDHash: "iris-1", UserID: target.ID},
			{IDHash: "iris-2", UserID: target.ID},
			{IDHash: "jon-1", UserID: bystander.ID},
		} {
			session.CreatedAt, session.ExpiresAt = now, now.Add(time.Hour)
			require.NoError(t, repo.Create(ctx, session), "Create")
		}

		require.NoError(t, repo.DeleteByUserExcept(ctx, target.ID, "iris-kept"), "DeleteByUserExcept")

		for _, h := range []string{"iris-1", "iris-2"} {
			_, err := repo.ByHash(ctx, h)
			require.ErrorIs(t, err, app.ErrNotFound, "%s survived DeleteByUserExcept", h)
		}

		for _, h := range []string{"iris-kept", "jon-1"} {
			_, err := repo.ByHash(ctx, h)
			require.NoError(t, err, "%s was deleted", h)
		}
	})

	t.Run("Invite", func(t *testing.T) {
		const issuer = "https://idp.example.com/realms/demo/"

		in := time.Now().UTC().Add(time.Hour)

		invited := human(t, "ivy@example.com", "Ivy")
		err := idents.Invite(ctx, invited.ID, app.Invitation{Issuer: issuer, Email: "Ivy@Example.com", ExpiresAt: in})
		require.NoError(t, err, "Invite")

		got, err := idents.PendingByEmail(ctx, issuer, "ivy@example.com")
		require.NoError(t, err, "PendingByEmail")
		require.Equal(t, invited.ID, got, "PendingByEmail")
		// Stored byte for byte: the issuer without its trailing slash is another issuer.
		_, err = idents.PendingByEmail(ctx, "https://idp.example.com/realms/demo", "ivy@example.com")
		require.ErrorIs(t, err, app.ErrNotFound, "normalised issuer matched")

		// A stale invitation for the address, expired or live, whoever it was for, is
		// replaced rather than colliding with the case-insensitive unique index.
		for name, ttl := range map[string]time.Duration{"expired": -time.Hour, "live": time.Hour} {
			stale := human(t, "stale-"+name+"@example.org", "Stale "+name)
			addPending(ctx, t, pool, stale.ID, issuer, "Again-"+name+"@example.com", ttl)

			fresh := human(t, "again-"+name+"@example.com", "Fresh "+name)
			err := idents.Invite(ctx, fresh.ID, app.Invitation{Issuer: issuer, Email: "again-" + name + "@example.com", ExpiresAt: in})
			require.NoError(t, err, "%s: re-invite", name)

			got, err := idents.PendingByEmail(ctx, issuer, "AGAIN-"+name+"@example.com")
			require.NoError(t, err, "%s: PendingByEmail", name)
			require.Equal(t, fresh.ID, got, "%s: PendingByEmail, want the new account", name)

			var n int

			err = pool.QueryRow(ctx, `SELECT count(*) FROM pending_identities WHERE user_id = $1`, stale.ID).Scan(&n)
			require.NoError(t, err, "%s: stale invitation rows", name)
			require.Zero(t, n, "%s: stale invitation rows", name)
		}

		// The same address at another issuer is another invitation and is left alone;
		// re-inviting an account to a new address replaces its own old invitation.
		other := human(t, "other-issuer@example.org", "Other issuer")
		addPending(ctx, t, pool, other.ID, "https://other.example.com", "ivy@example.com", time.Hour)

		err = idents.Invite(ctx, invited.ID, app.Invitation{Issuer: issuer, Email: "ivy.new@example.com", ExpiresAt: in})
		require.NoError(t, err, "Invite to a new address")

		_, err = idents.PendingByEmail(ctx, issuer, "ivy@example.com")
		require.ErrorIs(t, err, app.ErrNotFound, "the account's old invitation survived")

		got, err = idents.PendingByEmail(ctx, issuer, "ivy.new@example.com")
		require.NoError(t, err, "new address")
		require.Equal(t, invited.ID, got, "new address")

		got, err = idents.PendingByEmail(ctx, "https://other.example.com", "ivy@example.com")
		require.NoError(t, err, "other issuer's invitation")
		require.Equal(t, other.ID, got, "other issuer's invitation")

		// A linked account gets no invitation, and the refusal writes nothing: the
		// invitation it already held is still there, untouched.
		linked := human(t, "lee@example.com", "Lee")
		addPending(ctx, t, pool, linked.ID, issuer, "lee@example.com", time.Hour)

		require.NoError(t, idents.Link(ctx, linked.ID, issuer, "subject-lee"), "Link")

		err = idents.Invite(ctx, linked.ID, app.Invitation{Issuer: issuer, Email: "lee.new@example.com", ExpiresAt: in})
		require.ErrorIs(t, err, app.ErrAlreadyLinked, "linked")

		got, err = idents.PendingByEmail(ctx, issuer, "lee@example.com")
		require.NoError(t, err, "a refused invite deleted the old row")
		require.Equal(t, linked.ID, got, "a refused invite deleted the old row")
	})

	t.Run("RecentUsage", func(t *testing.T) {
		repo := postgres.NewActivityRepo(pool)
		user, other := human(t, "uma@example.com", "Uma"), human(t, "vic@example.com", "Vic")

		tok, _, err := credentials.Generate(user.ID, "laptop")
		require.NoError(t, err, "Generate")
		require.NoError(t, postgres.NewTokenRepo(pool).Create(ctx, tok), "create token")

		at := time.Now().UTC().Truncate(time.Microsecond)
		addUsage(ctx, t, pool, user.ID, &tok.ID, at.Add(-3*time.Minute), "alpha", "old")
		addUsage(ctx, t, pool, user.ID, nil, at.Add(-2*time.Minute), "alpha", "middle")
		addUsage(ctx, t, pool, user.ID, &tok.ID, at.Add(-time.Minute), "beta", "newest")
		addUsage(ctx, t, pool, other.ID, nil, at, "alpha", "someone else's")

		_, err = pool.Exec(ctx, `UPDATE usage_events SET cost_input_usd = 0.5, cost_output_usd = 1,
			cost_cache_read_usd = 0.25, cost_cache_write_usd = 2, cache_savings_usd = -1, unpriced_tokens = 3, priced = true
			WHERE user_id = $1 AND model = 'newest'`, user.ID)
		require.NoError(t, err, "price the newest row")

		got, err := repo.RecentUsage(ctx, user.ID, 2)
		require.NoError(t, err, "RecentUsage")
		// want newest then middle
		require.Len(t, got, 2, "RecentUsage")
		require.Equal(t, "newest", got[0].Model, "RecentUsage first")
		require.Equal(t, "middle", got[1].Model, "RecentUsage second")

		event := got[0]
		require.True(t, event.At.Equal(at.Add(-time.Minute)), "event at = %v, want %v", event.At, at.Add(-time.Minute))
		require.Equal(t, user.ID, event.UserID, "event user")
		require.Equal(t, tok.ID, event.TokenID, "event token")
		require.Equal(t, "beta", event.Provider, "event provider")
		require.True(t, event.Stream, "event stream")
		require.Equal(t, http.StatusOK, event.StatusCode, "event status")
		require.Equal(t, int64(42), event.TokensTotal, "event tokens")
		require.Equal(t, 1500, event.LatencyMS, "event latency")

		want := app.UsageCost{
			InputUSD: 0.5, OutputUSD: 1, CacheReadUSD: 0.25, CacheWriteUSD: 2,
			CacheSavingsUSD: -1, UnpricedTokens: 3, Priced: true,
		}
		require.Equal(t, want, event.Cost, "stored cost")
		require.Equal(t, uuid.Nil, got[1].TokenID, "NULL token")
		require.Zero(t, got[1].Cost, "unpriced row's cost")
	})

	t.Run("RecentAudit", func(t *testing.T) {
		repo := postgres.NewActivityRepo(pool)
		sink := postgres.NewAuditSink(pool)
		user, admin, other := human(t, "wes@example.com", "Wes"), human(t, "xena@example.com", "Xena"), human(t, "yan@example.com", "Yan")

		at := time.Now().UTC().Truncate(time.Microsecond)
		for _, event := range []app.AuditEvent{
			{At: at.Add(-5 * time.Minute), ActorID: user.ID, Action: "auth.signin", Target: user.ID.String()},
			{
				At: at.Add(-4 * time.Minute), ActorID: admin.ID, Action: "user.update", Target: user.ID.String(),
				Detail: map[string]any{"status": "blocked"},
			},
			{
				At: at.Add(-3 * time.Minute), ActorID: admin.ID, Action: "token.issue", Target: "token/t1",
				Detail: map[string]any{"owner_id": user.ID.String()},
			},
			{At: at.Add(-2 * time.Minute), ActorID: admin.ID, Action: "user.update", Target: other.ID.String()},
			{At: at.Add(-time.Minute), Action: "system.prune"},
		} {
			require.NoError(t, sink.Record(ctx, event), "Record")
		}

		got, err := repo.RecentAudit(ctx, user.ID, 10)
		require.NoError(t, err, "RecentAudit")

		actions := make([]string, 0, len(got))
		for _, e := range got {
			actions = append(actions, e.Action)
		}

		require.Equal(t, []string{"token.issue", "user.update", "auth.signin"}, actions, "RecentAudit")
		require.Equal(t, admin.ID, got[1].ActorID, "event actor")
		require.Equal(t, "blocked", got[1].Detail["status"], "event detail status")
		require.True(t, got[1].At.Equal(at.Add(-4*time.Minute)), "event at = %v, want %v", got[1].At, at.Add(-4*time.Minute))

		// want only the newest
		page, err := repo.RecentAudit(ctx, user.ID, 1)
		require.NoError(t, err, "RecentAudit limit 1")
		require.Len(t, page, 1, "RecentAudit limit 1")
		require.Equal(t, "token.issue", page[0].Action, "RecentAudit limit 1")
	})
}

func viewIDs(views []app.UserView) []uuid.UUID {
	ids := make([]uuid.UUID, 0, len(views))
	for _, v := range views {
		ids = append(ids, v.User.ID)
	}

	return ids
}

func addUsage(ctx context.Context, t *testing.T, pool *pgxpool.Pool, userID uuid.UUID, tokenID *uuid.UUID, at time.Time, provider, model string) {
	t.Helper()

	_, err := pool.Exec(ctx,
		`INSERT INTO usage_events (at, user_id, token_id, provider, model, stream, tokens_total, latency_ms, status_code)
		 VALUES ($1, $2, $3, $4, $5, true, 42, 1500, 200)`,
		at, userID, tokenID, provider, model)
	require.NoError(t, err, "seed usage event")
}
