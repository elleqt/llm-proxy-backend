package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/pgtest"
)

func mustPolicy(t *testing.T, rules ...string) access.Policy {
	t.Helper()
	p := make(access.Policy, 0, len(rules))
	for _, raw := range rules {
		r, err := access.ParseRule(raw)
		if err != nil {
			t.Fatalf("ParseRule(%q): %v", raw, err)
		}
		p = append(p, r)
	}
	return p
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
		if err != nil || exists {
			t.Fatalf("AdminExists on an empty database = %v, %v; want false, nil", exists, err)
		}
		person := identity.User{
			ID: uuid.New(), Kind: identity.KindHuman, Email: "plain@example.com",
			Role: identity.RoleUser, Status: identity.StatusActive, PolicySource: identity.PolicyLocal,
		}
		if err := users.Create(ctx, person); err != nil {
			t.Fatalf("create user: %v", err)
		}
		if exists, err := users.AdminExists(ctx); err != nil || exists {
			t.Fatalf("AdminExists with only an ordinary user = %v, %v; want false, nil", exists, err)
		}
		// Blocked still counts: blocking the only administrator is an operator's
		// decision, and a restart must not answer it by minting a new one.
		admin := person
		admin.ID, admin.Email = uuid.New(), "blocked-admin@example.com"
		admin.Role, admin.Status = identity.RoleAdmin, identity.StatusBlocked
		if err := users.Create(ctx, admin); err != nil {
			t.Fatalf("create admin: %v", err)
		}
		if exists, err := users.AdminExists(ctx); err != nil || !exists {
			t.Fatalf("AdminExists with a blocked administrator = %v, %v; want true, nil", exists, err)
		}
	})

	t.Run("ServiceAccountsWithEmptyEmailCoexist", func(t *testing.T) {
		// identity.NewService never sets an email, and uniqueness is enforced by
		// users_email_lower_key, a unique index over lower(email). Postgres tolerates
		// any number of NULLs in a unique index but exactly one empty string, so
		// without the repository binding "" as NULL the second account below fails on
		// a column neither caller touched.
		first := identity.NewService(uuid.New(), "chat-panel", access.Policy{})
		second := identity.NewService(uuid.New(), "batch-runner", access.Policy{})
		if err := users.Create(ctx, first); err != nil {
			t.Fatalf("create first service account: %v", err)
		}
		if err := users.Create(ctx, second); err != nil {
			t.Fatalf("create second service account: %v", err)
		}

		got, err := users.ByID(ctx, second.ID)
		if err != nil {
			t.Fatalf("ByID: %v", err)
		}
		// NULL must read back as the domain's "no email", not as a nil deref or a
		// sentinel the rest of the application would have to know about.
		if got.Email != "" {
			t.Fatalf("Email = %q, want empty", got.Email)
		}
		if got.Kind != identity.KindService || got.DisplayName != "batch-runner" {
			t.Fatalf("round trip lost fields: %+v", got)
		}
	})

	// An OIDC sign-up with an unverified address creates a human with no email. That
	// account must not stand in the way of the verified owner of the address, who
	// may later get an account of their own.
	t.Run("EmaillessHumanDoesNotReserveAnAddress", func(t *testing.T) {
		emailless := identity.User{
			ID: uuid.New(), Kind: identity.KindHuman,
			Role: identity.RoleUser, Status: identity.StatusActive, PolicySource: identity.PolicyLocal,
		}
		if err := users.Create(ctx, emailless); err != nil {
			t.Fatalf("create emailless human: %v", err)
		}
		owner := emailless
		owner.ID, owner.Email = uuid.New(), "address-owner@example.com"
		if err := users.Create(ctx, owner); err != nil {
			t.Fatalf("create the address owner: %v", err)
		}
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
		if err := users.Create(ctx, u); err != nil {
			t.Fatalf("create: %v", err)
		}

		got, err := users.ByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("ByID: %v", err)
		}
		gotRules, wantRules := ruleStrings(got.Policy), ruleStrings(want)
		if len(gotRules) != len(wantRules) {
			t.Fatalf("policy = %v, want %v", gotRules, wantRules)
		}
		for i := range wantRules {
			if gotRules[i] != wantRules[i] {
				t.Fatalf("policy = %v, want %v", gotRules, wantRules)
			}
		}
		// String equality alone would also pass for a rule rebuilt without
		// access.ParseRule, which matches nothing until its pattern is compiled.
		// Asking the loaded policy to authorise proves the read path went through
		// ParseRule.
		for _, c := range []struct{ provider, model string }{
			{"ollama", "llama3:70b"},
			{"openrouter", "openai/gpt-4o"},
			{"chatgpt", "anything-at-all"},
		} {
			if !got.Policy.Allows(c.provider, c.model) {
				t.Fatalf("loaded policy denies %s/%s", c.provider, c.model)
			}
		}
		if got.Policy.Allows("ollama", "llama3:8b") {
			t.Fatalf("loaded policy allows a model no rule grants")
		}
	})

	t.Run("StoredRuleThatCannotParseFailsTheRead", func(t *testing.T) {
		// A rule the parser rejects is a grant the operator made that we can no longer
		// honour. Dropping it would silently narrow the allow-list, so the read fails
		// instead and the caller sees a broken row rather than a shrunken policy.
		u := identity.NewService(uuid.New(), "corrupt-policy", access.Policy{})
		if err := users.Create(ctx, u); err != nil {
			t.Fatalf("create: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`UPDATE users SET policy = '["no-colon-here"]'::jsonb WHERE id = $1`, u.ID); err != nil {
			t.Fatalf("corrupt policy: %v", err)
		}
		if _, err := users.ByID(ctx, u.ID); !errors.Is(err, access.ErrMalformedRule) {
			t.Fatalf("err = %v, want access.ErrMalformedRule", err)
		}
	})

	t.Run("ByEmailIsCaseInsensitive", func(t *testing.T) {
		u := identity.User{
			ID:           uuid.New(),
			Kind:         identity.KindHuman,
			Email:        "person@example.com",
			DisplayName:  "Person",
			Role:         identity.RoleUser,
			Status:       identity.StatusActive,
			PolicySource: identity.PolicyLocal,
			CreatedAt:    time.Now().UTC(),
		}
		if err := users.Create(ctx, u); err != nil {
			t.Fatalf("create: %v", err)
		}
		got, err := users.ByEmail(ctx, "Person@Example.COM")
		if err != nil {
			t.Fatalf("ByEmail: %v", err)
		}
		if got.ID != u.ID {
			t.Fatalf("ByEmail returned %s, want %s", got.ID, u.ID)
		}
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
		if err := users.Create(ctx, first); err != nil {
			t.Fatalf("create first: %v", err)
		}

		second := first
		second.ID = uuid.New()
		second.Email = "collide@example.com"
		second.DisplayName = "Second"
		second.Role = identity.RoleUser
		if err := users.Create(ctx, second); !errors.Is(err, app.ErrConflict) {
			t.Fatalf("create second: err = %v, want app.ErrConflict", err)
		}

		// The stored capitalisation is preserved: uniqueness is folded in the index,
		// never by rewriting what the operator typed.
		got, err := users.ByEmail(ctx, "COLLIDE@EXAMPLE.COM")
		if err != nil {
			t.Fatalf("ByEmail: %v", err)
		}
		if got.ID != first.ID || got.Email != "Collide@Example.com" {
			t.Fatalf("got %s / %q, want %s / %q",
				got.ID, got.Email, first.ID, "Collide@Example.com")
		}
	})

	t.Run("UnknownLookupsAreNotFound", func(t *testing.T) {
		if _, err := users.ByID(ctx, uuid.New()); !errors.Is(err, app.ErrNotFound) {
			t.Fatalf("ByID err = %v, want app.ErrNotFound", err)
		}
		if _, err := users.ByEmail(ctx, "absent@example.com"); !errors.Is(err, app.ErrNotFound) {
			t.Fatalf("ByEmail err = %v, want app.ErrNotFound", err)
		}
	})

	t.Run("UpdatePolicyReplacesTheAllowList", func(t *testing.T) {
		u := identity.NewService(uuid.New(), "editable", mustPolicy(t, "chatgpt:*"))
		if err := users.Create(ctx, u); err != nil {
			t.Fatalf("create: %v", err)
		}
		if err := users.UpdatePolicy(ctx, u.ID, mustPolicy(t, "claude:*")); err != nil {
			t.Fatalf("UpdatePolicy: %v", err)
		}
		got, err := users.ByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("ByID: %v", err)
		}
		if got.Policy.Allows("chatgpt", "gpt-4o") {
			t.Fatalf("replaced rule still grants access: %v", ruleStrings(got.Policy))
		}
		if !got.Policy.Allows("claude", "opus") {
			t.Fatalf("new rule not stored: %v", ruleStrings(got.Policy))
		}
	})

	t.Run("UpdatePolicyOnUnknownUserIsNotFound", func(t *testing.T) {
		// A silent no-op would read as success in the admin UI while the operator's
		// edit landed nowhere.
		err := users.UpdatePolicy(ctx, uuid.New(), mustPolicy(t, "claude:*"))
		if !errors.Is(err, app.ErrNotFound) {
			t.Fatalf("err = %v, want app.ErrNotFound", err)
		}
	})

	t.Run("TouchLastSeenPersists", func(t *testing.T) {
		u := identity.NewService(uuid.New(), "seen", access.Policy{})
		if err := users.Create(ctx, u); err != nil {
			t.Fatalf("create: %v", err)
		}
		if got, err := users.ByID(ctx, u.ID); err != nil || got.LastSeenAt != nil {
			t.Fatalf("fresh user has last seen %v (err %v)", got.LastSeenAt, err)
		}

		when := time.Now().UTC().Truncate(time.Second)
		if err := users.TouchLastSeen(ctx, u.ID, when); err != nil {
			t.Fatalf("TouchLastSeen: %v", err)
		}
		got, err := users.ByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("ByID: %v", err)
		}
		if got.LastSeenAt == nil || !got.LastSeenAt.Equal(when) {
			t.Fatalf("last seen = %v, want %v", got.LastSeenAt, when)
		}
	})

	t.Run("TouchLastSeenNeverMovesBackwards", func(t *testing.T) {
		u := identity.NewService(uuid.New(), "seen-late", access.Policy{})
		if err := users.Create(ctx, u); err != nil {
			t.Fatalf("create: %v", err)
		}
		later := time.Now().UTC().Truncate(time.Second)
		for _, at := range []time.Time{later, later.Add(-5 * time.Minute)} {
			if err := users.TouchLastSeen(ctx, u.ID, at); err != nil {
				t.Fatalf("TouchLastSeen(%v): %v", at, err)
			}
		}
		got, err := users.ByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("ByID: %v", err)
		}
		if got.LastSeenAt == nil || !got.LastSeenAt.Equal(later) {
			t.Fatalf("last seen = %v, want %v: an older stamp moved it back", got.LastSeenAt, later)
		}
	})

	t.Run("SaveIdentityStateWritesBackIdPOwnedFields", func(t *testing.T) {
		u := identity.User{
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
		if err := users.Create(ctx, u); err != nil {
			t.Fatalf("create: %v", err)
		}

		// Everything the IdP owns changes, and everything it does not own is set to
		// the opposite of the stored value. A widened UPDATE therefore fails here
		// instead of silently un-blocking or demoting a federated account.
		u.Email = "after@example.com"
		u.DisplayName = "After"
		u.Policy = mustPolicy(t, "claude:*", "openrouter:openai/gpt-4o")
		u.PolicySource = identity.PolicyIDP
		u.Role = identity.RoleUser
		u.Status = identity.StatusActive
		u.MustChangePassword = false
		if err := users.SaveIdentityState(ctx, u); err != nil {
			t.Fatalf("SaveIdentityState: %v", err)
		}

		got, err := users.ByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("ByID: %v", err)
		}
		if got.Email != "after@example.com" {
			t.Fatalf("email = %q, want the address the provider asserted", got.Email)
		}
		if got.DisplayName != "After" {
			t.Fatalf("display name = %q, want \"After\"", got.DisplayName)
		}
		if !got.Policy.Allows("openrouter", "openai/gpt-4o") || got.Policy.Allows("chatgpt", "gpt-4o") {
			t.Fatalf("recomputed policy not stored: %v", ruleStrings(got.Policy))
		}
		// PolicySource drives whether the admin UI may edit the policy at all, so an
		// IdP login that failed to flip it would leave an editable policy the next
		// login silently overwrites.
		if got.PolicySource != identity.PolicyIDP || got.PolicyEditableByAdmin() {
			t.Fatalf("policy source = %q, want idp", got.PolicySource)
		}
		// Administrator decisions survive the login. An operator who blocked or
		// promoted a federated user must not have it undone by that user signing in.
		if got.Role != identity.RoleAdmin {
			t.Fatalf("role = %q, want the administrator's value %q", got.Role, identity.RoleAdmin)
		}
		if got.Status != identity.StatusBlocked {
			t.Fatalf("status = %q, want the administrator's value %q", got.Status, identity.StatusBlocked)
		}
		if !got.MustChangePassword {
			t.Fatalf("must_change_password was cleared by an IdP login")
		}
	})

	t.Run("SetMustChangePasswordWritesOnlyThatColumn", func(t *testing.T) {
		u := identity.User{
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
		if err := users.Create(ctx, u); err != nil {
			t.Fatalf("create: %v", err)
		}

		if err := users.SetMustChangePassword(ctx, u.ID, false); err != nil {
			t.Fatalf("SetMustChangePassword: %v", err)
		}
		got, err := users.ByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("ByID: %v", err)
		}
		if got.MustChangePassword {
			t.Fatal("the restriction was not lifted")
		}
		// Everything else is untouched: this statement exists precisely so that
		// clearing the flag is not an excuse to rewrite the row.
		if got.Role != identity.RoleAdmin || got.Status != identity.StatusBlocked ||
			got.Email != "flagged@example.com" || got.DisplayName != "Flagged" ||
			got.PolicySource != identity.PolicyIDP || !got.Policy.Allows("chatgpt", "gpt-4o") {
			t.Fatalf("SetMustChangePassword widened its write: %+v", got)
		}
	})

	t.Run("SetMustChangePasswordOnUnknownUserIsNotFound", func(t *testing.T) {
		// A restriction that was never applied, or never lifted, must not read as
		// success: ChangePassword treats this call as proof the flag is gone.
		if err := users.SetMustChangePassword(ctx, uuid.New(), false); !errors.Is(err, app.ErrNotFound) {
			t.Fatalf("err = %v, want app.ErrNotFound", err)
		}
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
			if err := users.Create(ctx, u); err != nil {
				t.Fatalf("create %s: %v", u.DisplayName, err)
			}
		}

		// The provider asserts the address the local account already holds, differing
		// only in case.
		federated.Email = "taken@example.com"
		federated.PolicySource = identity.PolicyIDP
		if err := users.SaveIdentityState(ctx, federated); !errors.Is(err, app.ErrConflict) {
			t.Fatalf("err = %v, want app.ErrConflict", err)
		}
	})

	t.Run("SaveIdentityStateOnUnknownUserIsNotFound", func(t *testing.T) {
		u := identity.NewService(uuid.New(), "ghost", access.Policy{})
		if err := users.SaveIdentityState(ctx, u); !errors.Is(err, app.ErrNotFound) {
			t.Fatalf("err = %v, want app.ErrNotFound", err)
		}
	})

	t.Run("TouchLastSeenOnUnknownUserIsNotAnError", func(t *testing.T) {
		// Deliberately asymmetric with UpdatePolicy and SaveIdentityState, which do
		// report app.ErrNotFound on zero rows. This one runs on the request path: a
		// user deleted between authentication and the stamp must not fail the request
		// that is already being served. Making the three consistent is the obvious
		// future edit, and this is the test that must stop it.
		if err := users.TouchLastSeen(ctx, uuid.New(), time.Now().UTC()); err != nil {
			t.Fatalf("TouchLastSeen on a missing user = %v, want nil", err)
		}
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
		store := func(t *testing.T, u identity.User) time.Time {
			t.Helper()
			if err := users.Create(ctx, u); err != nil {
				t.Fatalf("create %s: %v", u.DisplayName, err)
			}
			got, err := users.ByID(ctx, u.ID)
			if err != nil {
				t.Fatalf("ByID %s: %v", u.DisplayName, err)
			}
			return got.CreatedAt
		}

		// created_at is NOT NULL DEFAULT now(). A caller that builds a User without a
		// timestamp means "now", not year 1, so the repository binds NULL and lets the
		// column default apply.
		before := time.Now().UTC().Add(-time.Minute)
		if at := store(t, newUser("no-timestamp", time.Time{})); at.Before(before) {
			t.Fatalf("created_at = %v, want the column default near %v", at, before)
		}

		// The other half of the same guard: a caller that DID set the timestamp must
		// get it back unchanged. The instant is deliberately historical — an
		// unconditional now() would pass any assertion phrased around "recent",
		// which is what every other subtest here happens to supply.
		imported := time.Date(2019, 3, 14, 15, 9, 26, 0, time.UTC)
		if at := store(t, newUser("imported", imported)); !at.Equal(imported) {
			t.Fatalf("created_at = %v, want the caller's %v", at, imported)
		}
	})
}
