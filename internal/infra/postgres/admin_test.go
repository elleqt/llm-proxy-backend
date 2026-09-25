package postgres_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
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
)

// TestAdminRepos covers the repository methods the administration service reads and
// writes through, on one container.
func TestAdminRepos(t *testing.T) { //nolint:gocognit,gocyclo,cyclop // subtests share one Postgres container; each subtest is linear
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
		if err := users.Create(ctx, user); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}

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
		if err := users.Create(ctx, bot); err != nil {
			t.Fatalf("create bot: %v", err)
		}

		eve := human(t, "eve@example.com", "Eve")
		fay := human(t, "fay@example.com", "Fay")
		gus := human(t, "gus@example.com", "Gus")

		lapsed := time.Now().UTC().Add(-time.Minute)
		for id, exp := range map[uuid.UUID]*time.Time{alice.ID: nil, eve.ID: nil, fay.ID: &lapsed} {
			if err := passwords.Set(ctx, id, "hash", exp); err != nil {
				t.Fatalf("set password: %v", err)
			}
		}

		for i, id := range []uuid.UUID{bob.ID, eve.ID, gus.ID} {
			if err := idents.Link(ctx, id, "issuer-a", "subject-"+string(rune('a'+i))); err != nil {
				t.Fatalf("link: %v", err)
			}
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
		if err != nil {
			t.Fatalf("List: %v", err)
		}

		if got, order := viewIDs(all), []uuid.UUID{alice.ID, bob.ID, carol.ID, dave.ID, bot.ID, eve.ID, fay.ID, gus.ID}; !slices.Equal(got, order) {
			t.Fatalf("List order = %v, want oldest first %v", got, order)
		}

		for _, view := range all {
			expected := want[view.User.ID]
			if !slices.Equal(view.SignIn, expected.signIn) {
				t.Errorf("%s: sign-in = %v, want %v", view.User.DisplayName, view.SignIn, expected.signIn)
			}

			if (view.InvitationExpiresAt != nil) != expected.invited {
				t.Errorf("%s: invitation expiry = %v, want set: %v", view.User.DisplayName, view.InvitationExpiresAt, expected.invited)
			}
		}

		daveView, err := users.View(ctx, dave.ID)
		if err != nil {
			t.Fatalf("View: %v", err)
		}

		if daveView.User.Email != dave.Email || daveView.InvitationExpiresAt == nil || !daveView.InvitationExpiresAt.Before(time.Now()) {
			t.Fatalf("View = %+v, want the lapsed invitation's expiry", daveView)
		}

		if _, err := users.View(ctx, uuid.New()); !errors.Is(err, app.ErrNotFound) {
			t.Fatalf("View unknown: err = %v, want app.ErrNotFound", err)
		}
	})

	t.Run("UpdateAdminState", func(t *testing.T) {
		user := human(t, "hana@example.com", "Hana")
		if err := users.SetMustChangePassword(ctx, user.ID, true); err != nil {
			t.Fatalf("SetMustChangePassword: %v", err)
		}
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

		if err := errors.Join(errs...); err != nil {
			t.Fatalf("UpdateAdminState: %v", err)
		}

		admin, policy := identity.RoleAdmin, mustPolicy(t, "alpha:model-*")
		if err := users.UpdateAdminState(ctx, user.ID, app.AdminChange{Role: &admin, Policy: &policy}); err != nil {
			t.Fatalf("UpdateAdminState role+policy: %v", err)
		}

		got, err := users.ByID(ctx, user.ID)
		if err != nil {
			t.Fatalf("ByID: %v", err)
		}

		if got.DisplayName != name || got.Status != identity.StatusBlocked || got.Role != identity.RoleAdmin ||
			!got.Policy.Allows("alpha", "model-x") || got.PolicySource != identity.PolicyLocal {
			t.Fatalf("an edit was lost: %+v", got)
		}

		if got.Email != "hana@example.com" || !got.MustChangePassword {
			t.Fatalf("UpdateAdminState widened its write: email %q, must change %v", got.Email, got.MustChangePassword)
		}

		// The IdP lock is decided by the write itself, against the stored source.
		fed := human(t, "ian@example.com", "Ian")

		fed.Policy, fed.PolicySource = mustPolicy(t, "beta:*"), identity.PolicyIDP
		if err := users.SaveIdentityState(ctx, fed); err != nil {
			t.Fatalf("SaveIdentityState: %v", err)
		}

		if err := users.UpdateAdminState(ctx, fed.ID, app.AdminChange{Policy: &policy, RefuseIDPPolicy: true}); !errors.Is(err, app.ErrPolicyManagedByIDP) {
			t.Fatalf("locked policy: err = %v, want app.ErrPolicyManagedByIDP", err)
		}

		if got, _ := users.ByID(ctx, fed.ID); got.PolicySource != identity.PolicyIDP || !got.Policy.Allows("beta", "m") {
			t.Fatalf("a refused edit was written: %+v", got)
		}

		if err := users.UpdateAdminState(ctx, fed.ID, app.AdminChange{Policy: &policy}); err != nil {
			t.Fatalf("unlocked policy: %v", err)
		}

		if got, _ := users.ByID(ctx, fed.ID); got.PolicySource != identity.PolicyLocal || got.Policy.Allows("beta", "m") {
			t.Fatalf("frozen idp policy not converted: %+v", got)
		}

		if err := users.UpdateAdminState(ctx, uuid.New(), app.AdminChange{DisplayName: &name}); !errors.Is(err, app.ErrNotFound) {
			t.Fatalf("unknown user: err = %v, want app.ErrNotFound", err)
		}
	})

	// The shell's unblock: the status and its audit row land together or not at all.
	t.Run("Unblock", func(t *testing.T) {
		user := human(t, "locked@example.com", "Locked")

		blocked := identity.StatusBlocked
		if err := users.UpdateAdminState(ctx, user.ID, app.AdminChange{Status: &blocked}); err != nil {
			t.Fatal(err)
		}

		status := func() identity.Status {
			t.Helper()

			got, err := users.ByID(ctx, user.ID)
			if err != nil {
				t.Fatal(err)
			}

			return got.Status
		}
		event := func(actor uuid.UUID) app.AuditEvent {
			return app.AuditEvent{
				At: time.Now(), ActorID: actor, Action: "user.update", Target: user.ID.String(),
				Detail: map[string]any{"via": "cli", "status": "active"},
			}
		}
		// The audit row fails (its actor does not exist): the account stays blocked.
		if err := users.Unblock(ctx, user.ID, event(uuid.New())); err == nil {
			t.Fatal("Unblock succeeded with an audit row that cannot be written")
		}

		if s := status(); s != identity.StatusBlocked {
			t.Fatalf("status after a failed unblock = %s, want blocked", s)
		}

		if err := users.Unblock(ctx, user.ID, event(uuid.Nil)); err != nil {
			t.Fatalf("Unblock: %v", err)
		}

		if s := status(); s != identity.StatusActive {
			t.Fatalf("status = %s, want active", s)
		}

		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE target = $1 AND action = 'user.update'
		   AND actor_user_id IS NULL AND detail->>'via' = 'cli'`, user.ID.String()).Scan(&n); err != nil || n != 1 {
			t.Fatalf("unblock audit rows = %d, %v; want 1", n, err)
		}

		if err := users.Unblock(ctx, uuid.New(), event(uuid.Nil)); !errors.Is(err, app.ErrNotFound) {
			t.Fatalf("unknown user: err = %v, want ErrNotFound", err)
		}
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
			if err := pool.QueryRow(ctx, query, args...).Scan(&n); err != nil {
				t.Fatalf("count: %v", err)
			}

			return n
		}

		// The audit row is the last write, and it fails (its actor does not exist).
		// Everything before it must go with it.
		failed := account(uuid.New())
		if err := users.CreateAccount(ctx, failed); err == nil {
			t.Fatal("CreateAccount succeeded with an audit row that cannot be written")
		}

		if n := count(t, `SELECT count(*) FROM users WHERE lower(email) = 'jo@example.com'`); n != 0 {
			t.Fatalf("a failed creation left %d user rows", n)
		}

		if n := count(t, `SELECT count(*) FROM user_passwords WHERE user_id = $1`, failed.User.ID); n != 0 {
			t.Fatalf("a failed creation left a password")
		}

		if n := count(t, `SELECT count(*) FROM audit_events WHERE target = $1`, failed.User.ID.String()); n != 0 {
			t.Fatalf("a failed creation left an audit row")
		}

		// So the retry finds nothing in its way.
		retry := account(actor.ID)
		if err := users.CreateAccount(ctx, retry); err != nil {
			t.Fatalf("retry: %v", err)
		}

		if hash, exp, err := passwords.Get(ctx, retry.User.ID); err != nil || hash != "temp-hash" || exp == nil || !exp.Equal(expiry) {
			t.Fatalf("password = %q / %v / %v", hash, exp, err)
		}

		if n := count(t, `SELECT count(*) FROM audit_events WHERE target = $1 AND action = 'user.create'`, retry.User.ID.String()); n != 1 {
			t.Fatalf("audit rows = %d, want 1", n)
		}

		if err := users.CreateAccount(ctx, account(actor.ID)); !errors.Is(err, app.ErrConflict) {
			t.Fatalf("same address again: err = %v, want app.ErrConflict", err)
		}

		// An invitation is written in the same unit.
		invited := account(actor.ID)
		invited.User.Email, invited.Password = "kim@example.com", nil

		invited.Invitation = &app.Invitation{Issuer: "https://idp.example.com/", Email: "kim@example.com", ExpiresAt: expiry}
		if err := users.CreateAccount(ctx, invited); err != nil {
			t.Fatalf("CreateAccount invited: %v", err)
		}

		if got, err := idents.PendingByEmail(ctx, "https://idp.example.com/", "kim@example.com"); err != nil || got != invited.User.ID {
			t.Fatalf("PendingByEmail = %s / %v, want %s", got, err, invited.User.ID)
		}
	})

	t.Run("SessionsDeleteByUser", func(t *testing.T) {
		repo := postgres.NewSessionRepo(pool)
		target, bystander := human(t, "gina@example.com", "Gina"), human(t, "hal@example.com", "Hal")

		now := time.Now().UTC()
		for i, s := range []app.Session{
			{IDHash: "gina-1", UserID: target.ID}, {IDHash: "gina-2", UserID: target.ID}, {IDHash: "hal-1", UserID: bystander.ID},
		} {
			s.CreatedAt, s.ExpiresAt = now, now.Add(time.Duration(i+1)*time.Hour)
			if err := repo.Create(ctx, s); err != nil {
				t.Fatalf("Create: %v", err)
			}
		}

		if err := repo.DeleteByUser(ctx, target.ID); err != nil {
			t.Fatalf("DeleteByUser: %v", err)
		}

		for _, h := range []string{"gina-1", "gina-2"} {
			if _, err := repo.ByHash(ctx, h); !errors.Is(err, app.ErrNotFound) {
				t.Fatalf("%s survived DeleteByUser: err = %v", h, err)
			}
		}

		if _, err := repo.ByHash(ctx, "hal-1"); err != nil {
			t.Fatalf("another user's session was deleted: %v", err)
		}

		if err := repo.DeleteByUser(ctx, target.ID); err != nil {
			t.Fatalf("DeleteByUser with nothing left: %v", err)
		}
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
			if err := repo.Create(ctx, session); err != nil {
				t.Fatalf("Create: %v", err)
			}
		}

		if err := repo.DeleteByUserExcept(ctx, target.ID, "iris-kept"); err != nil {
			t.Fatalf("DeleteByUserExcept: %v", err)
		}

		for _, h := range []string{"iris-1", "iris-2"} {
			if _, err := repo.ByHash(ctx, h); !errors.Is(err, app.ErrNotFound) {
				t.Fatalf("%s survived DeleteByUserExcept: err = %v", h, err)
			}
		}

		for _, h := range []string{"iris-kept", "jon-1"} {
			if _, err := repo.ByHash(ctx, h); err != nil {
				t.Fatalf("%s was deleted: %v", h, err)
			}
		}
	})

	t.Run("Invite", func(t *testing.T) {
		const issuer = "https://idp.example.com/realms/demo/"

		in := time.Now().UTC().Add(time.Hour)

		invited := human(t, "ivy@example.com", "Ivy")
		if err := idents.Invite(ctx, invited.ID, app.Invitation{Issuer: issuer, Email: "Ivy@Example.com", ExpiresAt: in}); err != nil {
			t.Fatalf("Invite: %v", err)
		}

		if got, err := idents.PendingByEmail(ctx, issuer, "ivy@example.com"); err != nil || got != invited.ID {
			t.Fatalf("PendingByEmail = %s / %v, want %s", got, err, invited.ID)
		}
		// Stored byte for byte: the issuer without its trailing slash is another issuer.
		if _, err := idents.PendingByEmail(ctx, "https://idp.example.com/realms/demo", "ivy@example.com"); !errors.Is(err, app.ErrNotFound) {
			t.Fatalf("normalised issuer matched: err = %v", err)
		}

		// A stale invitation for the address, expired or live, whoever it was for, is
		// replaced rather than colliding with the case-insensitive unique index.
		for name, ttl := range map[string]time.Duration{"expired": -time.Hour, "live": time.Hour} {
			stale := human(t, "stale-"+name+"@example.org", "Stale "+name)
			addPending(ctx, t, pool, stale.ID, issuer, "Again-"+name+"@example.com", ttl)

			fresh := human(t, "again-"+name+"@example.com", "Fresh "+name)
			if err := idents.Invite(ctx, fresh.ID, app.Invitation{Issuer: issuer, Email: "again-" + name + "@example.com", ExpiresAt: in}); err != nil {
				t.Fatalf("%s: re-invite: %v", name, err)
			}

			if got, err := idents.PendingByEmail(ctx, issuer, "AGAIN-"+name+"@example.com"); err != nil || got != fresh.ID {
				t.Fatalf("%s: PendingByEmail = %s / %v, want the new account %s", name, got, err, fresh.ID)
			}

			var n int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM pending_identities WHERE user_id = $1`, stale.ID).Scan(&n); err != nil || n != 0 {
				t.Fatalf("%s: stale invitation rows = %d / %v, want 0", name, n, err)
			}
		}

		// The same address at another issuer is another invitation and is left alone;
		// re-inviting an account to a new address replaces its own old invitation.
		other := human(t, "other-issuer@example.org", "Other issuer")
		addPending(ctx, t, pool, other.ID, "https://other.example.com", "ivy@example.com", time.Hour)

		if err := idents.Invite(ctx, invited.ID, app.Invitation{Issuer: issuer, Email: "ivy.new@example.com", ExpiresAt: in}); err != nil {
			t.Fatalf("Invite to a new address: %v", err)
		}

		if _, err := idents.PendingByEmail(ctx, issuer, "ivy@example.com"); !errors.Is(err, app.ErrNotFound) {
			t.Fatalf("the account's old invitation survived: err = %v", err)
		}

		if got, err := idents.PendingByEmail(ctx, issuer, "ivy.new@example.com"); err != nil || got != invited.ID {
			t.Fatalf("new address: %s / %v, want %s", got, err, invited.ID)
		}

		if got, err := idents.PendingByEmail(ctx, "https://other.example.com", "ivy@example.com"); err != nil || got != other.ID {
			t.Fatalf("other issuer's invitation: %s / %v, want %s", got, err, other.ID)
		}

		// A linked account gets no invitation, and the refusal writes nothing: the
		// invitation it already held is still there, untouched.
		linked := human(t, "lee@example.com", "Lee")
		addPending(ctx, t, pool, linked.ID, issuer, "lee@example.com", time.Hour)

		if err := idents.Link(ctx, linked.ID, issuer, "subject-lee"); err != nil {
			t.Fatalf("Link: %v", err)
		}

		if err := idents.Invite(ctx, linked.ID, app.Invitation{Issuer: issuer, Email: "lee.new@example.com", ExpiresAt: in}); !errors.Is(err, app.ErrAlreadyLinked) {
			t.Fatalf("linked: err = %v, want app.ErrAlreadyLinked", err)
		}

		if got, err := idents.PendingByEmail(ctx, issuer, "lee@example.com"); err != nil || got != linked.ID {
			t.Fatalf("a refused invite deleted the old row: %s / %v", got, err)
		}
	})

	t.Run("RecentUsage", func(t *testing.T) {
		repo := postgres.NewActivityRepo(pool)
		user, other := human(t, "uma@example.com", "Uma"), human(t, "vic@example.com", "Vic")

		tok, _, err := credentials.Generate(user.ID, "laptop")
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}

		if err := postgres.NewTokenRepo(pool).Create(ctx, tok); err != nil {
			t.Fatalf("create token: %v", err)
		}

		at := time.Now().UTC().Truncate(time.Microsecond)
		addUsage(ctx, t, pool, user.ID, &tok.ID, at.Add(-3*time.Minute), "alpha", "old")
		addUsage(ctx, t, pool, user.ID, nil, at.Add(-2*time.Minute), "alpha", "middle")
		addUsage(ctx, t, pool, user.ID, &tok.ID, at.Add(-time.Minute), "beta", "newest")
		addUsage(ctx, t, pool, other.ID, nil, at, "alpha", "someone else's")

		if _, err := pool.Exec(ctx, `UPDATE usage_events SET cost_input_usd = 0.5, cost_output_usd = 1,
			cost_cache_read_usd = 0.25, cost_cache_write_usd = 2, cache_savings_usd = -1, unpriced_tokens = 3, priced = true
			WHERE user_id = $1 AND model = 'newest'`, user.ID); err != nil {
			t.Fatalf("price the newest row: %v", err)
		}

		got, err := repo.RecentUsage(ctx, user.ID, 2)
		if err != nil {
			t.Fatalf("RecentUsage: %v", err)
		}

		if len(got) != 2 || got[0].Model != "newest" || got[1].Model != "middle" {
			t.Fatalf("RecentUsage = %+v, want newest then middle", got)
		}

		event := got[0]
		if !event.At.Equal(at.Add(-time.Minute)) || event.UserID != user.ID || event.TokenID != tok.ID || event.Provider != "beta" ||
			!event.Stream || event.StatusCode != http.StatusOK || event.TokensTotal != 42 || event.LatencyMS != 1500 {
			t.Fatalf("event = %+v", event)
		}

		if want := (app.UsageCost{
			InputUSD: 0.5, OutputUSD: 1, CacheReadUSD: 0.25, CacheWriteUSD: 2,
			CacheSavingsUSD: -1, UnpricedTokens: 3, Priced: true,
		}); event.Cost != want {
			t.Fatalf("stored cost = %+v, want %+v", event.Cost, want)
		}

		if got[1].TokenID != uuid.Nil {
			t.Fatalf("NULL token = %s, want uuid.Nil", got[1].TokenID)
		}

		if got[1].Cost != (app.UsageCost{}) {
			t.Fatalf("unpriced row's cost = %+v, want none", got[1].Cost)
		}
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
			if err := sink.Record(ctx, event); err != nil {
				t.Fatalf("Record: %v", err)
			}
		}

		got, err := repo.RecentAudit(ctx, user.ID, 10)
		if err != nil {
			t.Fatalf("RecentAudit: %v", err)
		}

		actions := make([]string, 0, len(got))
		for _, e := range got {
			actions = append(actions, e.Action)
		}

		if want := []string{"token.issue", "user.update", "auth.signin"}; !slices.Equal(actions, want) {
			t.Fatalf("RecentAudit = %v, want %v", actions, want)
		}

		if got[1].ActorID != admin.ID || got[1].Detail["status"] != "blocked" || !got[1].At.Equal(at.Add(-4*time.Minute)) {
			t.Fatalf("event = %+v", got[1])
		}

		if page, err := repo.RecentAudit(ctx, user.ID, 1); err != nil || len(page) != 1 || page[0].Action != "token.issue" {
			t.Fatalf("RecentAudit limit 1 = %+v / %v, want only the newest", page, err)
		}
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

	if _, err := pool.Exec(ctx,
		`INSERT INTO usage_events (at, user_id, token_id, provider, model, stream, tokens_total, latency_ms, status_code)
		 VALUES ($1, $2, $3, $4, $5, true, 42, 1500, 200)`,
		at, userID, tokenID, provider, model); err != nil {
		t.Fatalf("seed usage event: %v", err)
	}
}
