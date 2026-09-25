package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/pgtest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func mustPolicy(t *testing.T, rules ...string) access.Policy {
	t.Helper()

	policy := make(access.Policy, 0, len(rules))
	for _, raw := range rules {
		r, err := access.ParseRule(raw)
		require.NoError(t, err, "ParseRule(%q)", raw)

		policy = append(policy, r)
	}

	return policy
}

func ruleStrings(p access.Policy) []string {
	out := make([]string, 0, len(p))
	for _, r := range p {
		out = append(out, r.String())
	}

	return out
}

func TestUserRepo(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.NewTestPool(t)
	users := postgres.NewUserRepo(pool)

	// First, while the database is empty: later subtests create administrators.
	t.Run("AdminExistsCountsAnyAdministrator", func(t *testing.T) {
		exists, err := users.AdminExists(ctx)
		require.NoError(t, err, "AdminExists on an empty database")
		require.False(t, exists, "AdminExists on an empty database")

		person := identity.User{
			ID: uuid.New(), Kind: identity.KindHuman, Email: "plain@example.com",
			Role: identity.RoleUser, Status: identity.StatusActive, PolicySource: identity.PolicyLocal,
		}
		require.NoError(t, users.Create(ctx, person), "create user")

		exists, err = users.AdminExists(ctx)
		require.NoError(t, err, "AdminExists with only an ordinary user")
		require.False(t, exists, "AdminExists with only an ordinary user")
		// Blocked still counts: blocking the only administrator is an operator's
		// decision, and a restart must not answer it by minting a new one.
		admin := person
		admin.ID, admin.Email = uuid.New(), "blocked-admin@example.com"

		admin.Role, admin.Status = identity.RoleAdmin, identity.StatusBlocked
		require.NoError(t, users.Create(ctx, admin), "create admin")

		exists, err = users.AdminExists(ctx)
		require.NoError(t, err, "AdminExists with a blocked administrator")
		require.True(t, exists, "AdminExists with a blocked administrator")
	})

	t.Run("ServiceAccountsWithEmptyEmailCoexist", func(t *testing.T) {
		// identity.NewService never sets an email, and uniqueness is enforced by
		// users_email_lower_key, a unique index over lower(email). Postgres tolerates
		// any number of NULLs in a unique index but exactly one empty string, so
		// without the repository binding "" as NULL the second account below fails on
		// a column neither caller touched.
		first := identity.NewService(uuid.New(), "chat-panel", access.Policy{})
		second := identity.NewService(uuid.New(), "batch-runner", access.Policy{})

		require.NoError(t, users.Create(ctx, first), "create first service account")

		require.NoError(t, users.Create(ctx, second), "create second service account")

		got, err := users.ByID(ctx, second.ID)
		require.NoError(t, err, "ByID")
		// NULL must read back as the domain's "no email", not as a nil deref or a
		// sentinel the rest of the application would have to know about.
		require.Empty(t, got.Email, "NULL email must read back as empty")
		require.Equal(t, identity.KindService, got.Kind, "round trip lost Kind")
		require.Equal(t, "batch-runner", got.DisplayName, "round trip lost DisplayName")
	})

	// An OIDC sign-up with an unverified address creates a human with no email. That
	// account must not stand in the way of the verified owner of the address, who
	// may later get an account of their own.
	t.Run("EmaillessHumanDoesNotReserveAnAddress", func(t *testing.T) {
		emailless := identity.User{
			ID: uuid.New(), Kind: identity.KindHuman,
			Role: identity.RoleUser, Status: identity.StatusActive, PolicySource: identity.PolicyLocal,
		}
		require.NoError(t, users.Create(ctx, emailless), "create emailless human")

		owner := emailless

		owner.ID, owner.Email = uuid.New(), "address-owner@example.com"
		require.NoError(t, users.Create(ctx, owner), "create the address owner")
	})

	t.Run("PolicySurvivesRoundTrip", func(t *testing.T) {
		// One rule whose model half contains a colon and one whose model half contains
		// a slash: both separators occur in real model identifiers, and a codec that
		// split on every colon or treated the pattern as a path would mangle exactly
		// these two.
		want := mustPolicy(t,
			"ollama:llama3:70b",
			"openrouter:openai/gpt-4o",
			"chatgpt:*",
		)

		u := identity.NewService(uuid.New(), "policy-holder", want)
		require.NoError(t, users.Create(ctx, u), "create")

		got, err := users.ByID(ctx, u.ID)
		require.NoError(t, err, "ByID")

		require.Equal(t, ruleStrings(want), ruleStrings(got.Policy), "policy")
		// String equality alone would also pass for a rule rebuilt without
		// access.ParseRule, which matches nothing until its pattern is compiled.
		// Asking the loaded policy to authorise proves the read path went through
		// ParseRule.
		for _, entry := range []struct{ provider, model string }{
			{"ollama", "llama3:70b"},
			{"openrouter", "openai/gpt-4o"},
			{"chatgpt", "anything-at-all"},
		} {
			require.True(t, got.Policy.Allows(entry.provider, entry.model),
				"loaded policy denies %s/%s", entry.provider, entry.model)
		}

		require.False(t, got.Policy.Allows("ollama", "llama3:8b"), "loaded policy allows a model no rule grants")
	})

	t.Run("StoredRuleThatCannotParseFailsTheRead", func(t *testing.T) {
		// A rule the parser rejects is a grant the operator made that we can no longer
		// honour. Dropping it would silently narrow the allow-list, so the read fails
		// instead and the caller sees a broken row rather than a shrunken policy.
		user := identity.NewService(uuid.New(), "corrupt-policy", access.Policy{})
		require.NoError(t, users.Create(ctx, user), "create")

		_, err := pool.Exec(ctx,
			`UPDATE users SET policy = '["no-colon-here"]'::jsonb WHERE id = $1`, user.ID)
		require.NoError(t, err, "corrupt policy")

		_, err = users.ByID(ctx, user.ID)
		require.ErrorIs(t, err, access.ErrMalformedRule)
	})

	t.Run("ByEmailIsCaseInsensitive", func(t *testing.T) {
		user := identity.User{
			ID:           uuid.New(),
			Kind:         identity.KindHuman,
			Email:        "person@example.com",
			DisplayName:  "Person",
			Role:         identity.RoleUser,
			Status:       identity.StatusActive,
			PolicySource: identity.PolicyLocal,
			CreatedAt:    time.Now().UTC(),
		}
		require.NoError(t, users.Create(ctx, user), "create")

		got, err := users.ByEmail(ctx, "Person@Example.COM")
		require.NoError(t, err, "ByEmail")

		require.Equal(t, user.ID, got.ID, "ByEmail returned the wrong user")
	})

	t.Run("EmailsDifferingOnlyInCaseCannotCoexist", func(t *testing.T) {
		// ByEmail folds case, so the uniqueness that backs it has to fold case too —
		// enforced by the users_email_lower_key index, not by this repository, so it
		// binds every writer. Without it both rows exist and ByEmail returns an
		// arbitrary one of two accounts with possibly different role, status and
		// policy: sign-in and the bootstrap-admin check both read through it.
		first := identity.User{
			ID:           uuid.New(),
			Kind:         identity.KindHuman,
			Email:        "Collide@Example.com",
			DisplayName:  "First",
			Role:         identity.RoleAdmin,
			Status:       identity.StatusActive,
			PolicySource: identity.PolicyLocal,
			CreatedAt:    time.Now().UTC(),
		}
		require.NoError(t, users.Create(ctx, first), "create first")

		second := first
		second.ID = uuid.New()
		second.Email = "collide@example.com"
		second.DisplayName = "Second"

		second.Role = identity.RoleUser
		require.ErrorIs(t, users.Create(ctx, second), app.ErrConflict, "create second")

		// The stored capitalisation is preserved: uniqueness is folded in the index,
		// never by rewriting what the operator typed.
		got, err := users.ByEmail(ctx, "COLLIDE@EXAMPLE.COM")
		require.NoError(t, err, "ByEmail")

		require.Equal(t, first.ID, got.ID, "ByEmail returned the wrong user")
		require.Equal(t, "Collide@Example.com", got.Email, "stored capitalisation")
	})

	t.Run("UnknownLookupsAreNotFound", func(t *testing.T) {
		_, err := users.ByID(ctx, uuid.New())
		require.ErrorIs(t, err, app.ErrNotFound, "ByID")

		_, err = users.ByEmail(ctx, "absent@example.com")
		require.ErrorIs(t, err, app.ErrNotFound, "ByEmail")
	})

	t.Run("UpdatePolicyReplacesTheAllowList", func(t *testing.T) {
		user := identity.NewService(uuid.New(), "editable", mustPolicy(t, "chatgpt:*"))
		require.NoError(t, users.Create(ctx, user), "create")

		require.NoError(t, users.UpdatePolicy(ctx, user.ID, mustPolicy(t, "claude:*")), "UpdatePolicy")

		got, err := users.ByID(ctx, user.ID)
		require.NoError(t, err, "ByID")

		require.False(t, got.Policy.Allows("chatgpt", "gpt-4o"), "replaced rule still grants access: %v", ruleStrings(got.Policy))
		require.True(t, got.Policy.Allows("claude", "opus"), "new rule not stored: %v", ruleStrings(got.Policy))
	})

	t.Run("UpdatePolicyOnUnknownUserIsNotFound", func(t *testing.T) {
		// A silent no-op would read as success in the admin UI while the operator's
		// edit landed nowhere.
		err := users.UpdatePolicy(ctx, uuid.New(), mustPolicy(t, "claude:*"))
		require.ErrorIs(t, err, app.ErrNotFound)
	})

	t.Run("TouchLastSeenPersists", func(t *testing.T) {
		user := identity.NewService(uuid.New(), "seen", access.Policy{})
		require.NoError(t, users.Create(ctx, user), "create")

		fresh, err := users.ByID(ctx, user.ID)
		require.NoError(t, err, "ByID of a fresh user")
		require.Nil(t, fresh.LastSeenAt, "fresh user has a last-seen stamp")

		when := time.Now().UTC().Truncate(time.Second)
		require.NoError(t, users.TouchLastSeen(ctx, user.ID, when), "TouchLastSeen")

		got, err := users.ByID(ctx, user.ID)
		require.NoError(t, err, "ByID")

		require.NotNil(t, got.LastSeenAt, "last seen not persisted")
		require.True(t, got.LastSeenAt.Equal(when), "last seen = %v, want %v", got.LastSeenAt, when)
	})

	t.Run("TouchLastSeenNeverMovesBackwards", func(t *testing.T) {
		user := identity.NewService(uuid.New(), "seen-late", access.Policy{})
		require.NoError(t, users.Create(ctx, user), "create")

		later := time.Now().UTC().Truncate(time.Second)
		for _, at := range []time.Time{later, later.Add(-5 * time.Minute)} {
			require.NoError(t, users.TouchLastSeen(ctx, user.ID, at), "TouchLastSeen(%v)", at)
		}

		got, err := users.ByID(ctx, user.ID)
		require.NoError(t, err, "ByID")

		require.NotNil(t, got.LastSeenAt, "last seen not persisted")
		require.True(t, got.LastSeenAt.Equal(later),
			"last seen = %v, want %v: an older stamp moved it back", got.LastSeenAt, later)
	})

	t.Run("SaveIdentityStateWritesBackIdPOwnedFields", func(t *testing.T) {
		user := identity.User{
			ID:                 uuid.New(),
			Kind:               identity.KindHuman,
			Email:              "before@example.com",
			DisplayName:        "Before",
			Role:               identity.RoleAdmin,
			Status:             identity.StatusBlocked,
			Policy:             mustPolicy(t, "chatgpt:*"),
			PolicySource:       identity.PolicyLocal,
			MustChangePassword: true,
			CreatedAt:          time.Now().UTC(),
		}
		require.NoError(t, users.Create(ctx, user), "create")

		// Everything the IdP owns changes, and everything it does not own is set to
		// the opposite of the stored value. A widened UPDATE therefore fails here
		// instead of silently un-blocking, demoting or renaming a federated account.
		user.Email = "after@example.com"
		user.DisplayName = "After"
		user.Policy = mustPolicy(t, "claude:*", "openrouter:openai/gpt-4o")
		user.PolicySource = identity.PolicyIDP
		user.Role = identity.RoleUser
		user.Status = identity.StatusActive

		user.MustChangePassword = false
		require.NoError(t, users.SaveIdentityState(ctx, user), "SaveIdentityState")

		got, err := users.ByID(ctx, user.ID)
		require.NoError(t, err, "ByID")

		require.Equal(t, "after@example.com", got.Email, "email must be the address the provider asserted")
		// The name is FillDisplayName's alone: written back from a copy read at the
		// start of the login, it would undo an administrator's rename made meanwhile.
		require.Equal(t, "Before", got.DisplayName, "display name must stay the stored one")
		require.True(t, got.Policy.Allows("openrouter", "openai/gpt-4o"),
			"recomputed policy not stored: %v", ruleStrings(got.Policy))
		require.False(t, got.Policy.Allows("chatgpt", "gpt-4o"),
			"recomputed policy not stored: %v", ruleStrings(got.Policy))
		// PolicySource drives whether the admin UI may edit the policy at all, so an
		// IdP login that failed to flip it would leave an editable policy the next
		// login silently overwrites.
		require.Equal(t, identity.PolicyIDP, got.PolicySource, "policy source")
		require.False(t, got.PolicyEditableByAdmin(), "IdP-sourced policy must not be admin-editable")
		// Administrator decisions survive the login. An operator who blocked or
		// promoted a federated user must not have it undone by that user signing in.
		require.Equal(t, identity.RoleAdmin, got.Role, "role must keep the administrator's value")
		require.Equal(t, identity.StatusBlocked, got.Status, "status must keep the administrator's value")
		require.True(t, got.MustChangePassword, "must_change_password was cleared by an IdP login")
	})

	t.Run("SetMustChangePasswordWritesOnlyThatColumn", func(t *testing.T) {
		user := identity.User{
			ID:                 uuid.New(),
			Kind:               identity.KindHuman,
			Email:              "flagged@example.com",
			DisplayName:        "Flagged",
			Role:               identity.RoleAdmin,
			Status:             identity.StatusBlocked,
			Policy:             mustPolicy(t, "chatgpt:*"),
			PolicySource:       identity.PolicyIDP,
			MustChangePassword: true,
			CreatedAt:          time.Now().UTC(),
		}
		require.NoError(t, users.Create(ctx, user), "create")

		require.NoError(t, users.SetMustChangePassword(ctx, user.ID, false), "SetMustChangePassword")

		got, err := users.ByID(ctx, user.ID)
		require.NoError(t, err, "ByID")

		require.False(t, got.MustChangePassword, "the restriction was not lifted")
		// Everything else is untouched: this statement exists precisely so that
		// clearing the flag is not an excuse to rewrite the row.
		const widened = "SetMustChangePassword widened its write"

		require.Equal(t, identity.RoleAdmin, got.Role, widened)
		require.Equal(t, identity.StatusBlocked, got.Status, widened)
		require.Equal(t, "flagged@example.com", got.Email, widened)
		require.Equal(t, "Flagged", got.DisplayName, widened)
		require.Equal(t, identity.PolicyIDP, got.PolicySource, widened)
		require.True(t, got.Policy.Allows("chatgpt", "gpt-4o"), widened)
	})

	t.Run("SetMustChangePasswordOnUnknownUserIsNotFound", func(t *testing.T) {
		// A restriction that was never applied, or never lifted, must not read as
		// success: ChangePassword treats this call as proof the flag is gone.
		require.ErrorIs(t, users.SetMustChangePassword(ctx, uuid.New(), false), app.ErrNotFound)
	})

	t.Run("SaveIdentityStateReportsAnEmailConflict", func(t *testing.T) {
		// Reachable only since uniqueness became case-insensitive, and reached on the
		// hot path: the OIDC sign-in calls this on every federated login, so an IdP that
		// reasserts an address a local account already holds must produce a conflict
		// the flow can recognise rather than an opaque driver error.
		holder := identity.User{
			ID:           uuid.New(),
			Kind:         identity.KindHuman,
			Email:        "Taken@Example.com",
			DisplayName:  "Local account",
			Role:         identity.RoleUser,
			Status:       identity.StatusActive,
			PolicySource: identity.PolicyLocal,
			CreatedAt:    time.Now().UTC(),
		}
		federated := holder
		federated.ID = uuid.New()
		federated.Email = "federated-claimant@example.com"

		federated.DisplayName = "Federated person"
		for _, u := range []identity.User{holder, federated} {
			require.NoError(t, users.Create(ctx, u), "create %s", u.DisplayName)
		}

		// The provider asserts the address the local account already holds, differing
		// only in case.
		federated.Email = "taken@example.com"

		federated.PolicySource = identity.PolicyIDP
		require.ErrorIs(t, users.SaveIdentityState(ctx, federated), app.ErrConflict)
	})

	t.Run("FillDisplayNameFillsOnlyAnEmptyName", func(t *testing.T) {
		unnamed := identity.User{
			ID: uuid.New(), Kind: identity.KindHuman, Email: "unnamed@example.com",
			Role: identity.RoleUser, Status: identity.StatusActive, PolicySource: identity.PolicyLocal,
			CreatedAt: time.Now().UTC(),
		}
		named := unnamed

		named.ID, named.Email, named.DisplayName = uuid.New(), "named@example.com", "Set By An Admin"
		for _, u := range []identity.User{unnamed, named} {
			require.NoError(t, users.Create(ctx, u), "create")
		}

		for _, tc := range []struct {
			id         uuid.UUID
			name       string
			wantFilled bool
			wantName   string
		}{
			{unnamed.ID, "From The IdP", true, "From The IdP"},
			{named.ID, "From The IdP", false, "Set By An Admin"},
			// Filled once, the name is no longer empty: a second fill changes nothing.
			{unnamed.ID, "Another Name", false, "From The IdP"},
		} {
			filled, err := users.FillDisplayName(ctx, tc.id, tc.name)
			require.NoError(t, err, "FillDisplayName(%q)", tc.name)
			require.Equal(t, tc.wantFilled, filled, "FillDisplayName(%q) filled", tc.name)

			got, err := users.ByID(ctx, tc.id)
			require.NoError(t, err, "ByID")
			require.Equal(t, tc.wantName, got.DisplayName, "display name")
		}

		_, err := users.FillDisplayName(ctx, uuid.New(), "x")
		require.ErrorIs(t, err, app.ErrNotFound, "unknown user")
	})

	t.Run("SaveIdentityStateOnUnknownUserIsNotFound", func(t *testing.T) {
		u := identity.NewService(uuid.New(), "ghost", access.Policy{})
		require.ErrorIs(t, users.SaveIdentityState(ctx, u), app.ErrNotFound)
	})

	t.Run("TouchLastSeenOnUnknownUserIsNotAnError", func(t *testing.T) {
		// Deliberately asymmetric with UpdatePolicy and SaveIdentityState, which do
		// report app.ErrNotFound on zero rows. This one runs on the request path: a
		// user deleted between authentication and the stamp must not fail the request
		// that is already being served. Making the three consistent is the obvious
		// future edit, and this is the test that must stop it.
		require.NoError(t, users.TouchLastSeen(ctx, uuid.New(), time.Now().UTC()), "TouchLastSeen on a missing user")
	})

	t.Run("CreateDefaultsAZeroCreatedAtAndHonoursOneThatIsSet", func(t *testing.T) {
		newUser := func(name string, createdAt time.Time) identity.User {
			return identity.User{
				ID:           uuid.New(),
				Kind:         identity.KindService,
				DisplayName:  name,
				Role:         identity.RoleUser,
				Status:       identity.StatusActive,
				PolicySource: identity.PolicyLocal,
				CreatedAt:    createdAt,
			}
		}
		store := func(t *testing.T, user identity.User) time.Time {
			t.Helper()

			require.NoError(t, users.Create(ctx, user), "create %s", user.DisplayName)

			got, err := users.ByID(ctx, user.ID)
			require.NoError(t, err, "ByID %s", user.DisplayName)

			return got.CreatedAt
		}

		// created_at is NOT NULL DEFAULT now(). A caller that builds a User without a
		// timestamp means "now", not year 1, so the repository binds NULL and lets the
		// column default apply.
		before := time.Now().UTC().Add(-time.Minute)
		at := store(t, newUser("no-timestamp", time.Time{}))
		require.False(t, at.Before(before), "created_at = %v, want the column default near %v", at, before)

		// The other half of the same guard: a caller that DID set the timestamp must
		// get it back unchanged. The instant is deliberately historical — an
		// unconditional now() would pass any assertion phrased around "recent",
		// which is what every other subtest here happens to supply.
		imported := time.Date(2019, 3, 14, 15, 9, 26, 0, time.UTC)
		at = store(t, newUser("imported", imported))
		require.True(t, at.Equal(imported), "created_at = %v, want the caller's %v", at, imported)
	})
}
