package app_test // external test package: internal/infra/postgres imports internal/app,
// so an in-package test cannot reach the repositories without a cycle.

import (
	"context"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/app/mocks"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	pgpasswords "github.com/elleqt/llm-proxy-backend/internal/infra/postgres/passwords"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/pgtest"
	pgusers "github.com/elleqt/llm-proxy-backend/internal/infra/postgres/users"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// minBootstrapPasswordLen is 128 bits at the six bits a URL-safe character carries.
const minBootstrapPasswordLen = 22

func TestBootstrap(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.NewTestPool(t)
	users, passwords := pgusers.New(pool), pgpasswords.New(pool)

	secret, err := app.Bootstrap(ctx, users, passwords, testHasher(), "admin@example.com")
	require.NoError(t, err, "Bootstrap")
	require.GreaterOrEqual(t, len(secret), minBootstrapPasswordLen, "bootstrap password length")

	admin, err := users.ByEmail(ctx, "admin@example.com")
	require.NoError(t, err, "ByEmail")
	require.Equal(t, identity.RoleAdmin, admin.Role, "bootstrap user role")
	require.True(t, admin.CanSignIn(), "the bootstrap administrator must be able to sign in")
	require.True(t, admin.MustChangePassword, "bootstrap admin must be forced to change the password")

	hash, expiresAt, err := passwords.Get(ctx, admin.ID)
	require.NoError(t, err, "password")
	// The password the operator is shown is the one that opens the account.
	require.True(t, identity.VerifyPassword(hash, secret), "the returned password does not match the stored hash")
	// An expiry would strand an operator slower than the window: the administrator
	// now exists, so no later start issues another.
	require.Nil(t, expiresAt, "bootstrap password must not expire")

	// Every later start: an administrator exists, so nothing is issued and nothing
	// is created — not even for a different address.
	for _, email := range []string{"admin@example.com", "someone-else@example.com"} {
		again, err := app.Bootstrap(ctx, users, passwords, testHasher(), email)
		require.NoError(t, err, "Bootstrap(%s) again", email)
		require.Empty(t, again, "Bootstrap(%s) again issued a password", email)
	}

	_, err = users.ByEmail(ctx, "someone-else@example.com")
	require.ErrorIs(t, err, app.ErrNotFound, "a second administrator was created")

	after, _, err := passwords.Get(ctx, admin.ID)
	require.NoError(t, err, "password after restart")
	require.Equal(t, hash, after, "a restart replaced the bootstrap administrator's password")
}

// Two installations must not share a first password: it is generated, not a default.
func TestBootstrapPasswordIsFreshEachTime(t *testing.T) {
	issue := func() string {
		users := mocks.NewUserRepo(t)
		passwords := mocks.NewPasswordRepo(t)

		users.EXPECT().AdminExists(mock.Anything).Return(false, nil)
		users.EXPECT().Create(mock.Anything, mock.Anything).Return(nil)

		var stored string

		passwords.EXPECT().Set(mock.Anything, mock.Anything, mock.Anything, (*time.Time)(nil)).
			RunAndReturn(func(_ context.Context, _ uuid.UUID, hash string, _ *time.Time) error {
				stored = hash

				return nil
			})

		secret, err := app.Bootstrap(context.Background(), users, passwords, testHasher(), "admin@example.com")
		require.NoError(t, err, "Bootstrap")
		require.True(t, identity.VerifyPassword(stored, secret), "the returned password does not match the stored hash")

		return secret
	}

	first, second := issue(), issue()
	require.NotEqual(t, first, second, "two bootstraps issued the same password")
}

// The user row and its password are two writes. A start that died between them left
// an administrator nobody has a password for, whom every later start counts as "an
// administrator exists"; the next start must finish the job rather than skip it.
func TestBootstrapFinishesAnAdministratorWhosePasswordNeverLanded(t *testing.T) {
	users := mocks.NewUserRepo(t)
	passwords := mocks.NewPasswordRepo(t)
	admin := humanUser("admin@example.com")
	admin.Role = identity.RoleAdmin
	admin.MustChangePassword = true

	users.EXPECT().AdminExists(mock.Anything).Return(true, nil)
	users.EXPECT().ByEmail(mock.Anything, "admin@example.com").Return(admin, nil)
	passwords.EXPECT().Get(mock.Anything, admin.ID).Return("", nil, app.ErrNotFound)

	var stored string

	passwords.EXPECT().Set(mock.Anything, admin.ID, mock.Anything, (*time.Time)(nil)).
		RunAndReturn(func(_ context.Context, _ uuid.UUID, hash string, _ *time.Time) error {
			stored = hash

			return nil
		})

	secret, err := app.Bootstrap(context.Background(), users, passwords, testHasher(), "admin@example.com")
	require.NoError(t, err, "Bootstrap")
	require.NotEmpty(t, secret, "the stranded administrator was not given a password")
	require.True(t, identity.VerifyPassword(stored, secret), "the stranded administrator was not given a working password")
}

// Finishing a stranded bootstrap is the only reason Bootstrap ever issues a password
// once an administrator exists, and the guard on it is what stops every restart from
// printing a fresh credential for a working account. The sharpest case is a federated
// administrator: no local password row, flag clear, signs in through the IdP. A
// password issued to them opens a full, unrestricted session for whoever reads the
// log, bypassing the IdP. A non-admin with the flag set is not the bootstrap account
// either.
//
// The password store reports no row, so only the guard stands between the call and
// Set; Set has no expectation, so issuing fails the test.
func TestBootstrapNeverIssuesToAnAccountItDidNotStrand(t *testing.T) {
	federatedAdmin := humanUser("admin@example.com")
	federatedAdmin.Role = identity.RoleAdmin
	federatedAdmin.PolicySource = identity.PolicyIDP
	flaggedUser := humanUser("admin@example.com")
	flaggedUser.MustChangePassword = true

	for name, user := range map[string]identity.User{
		"working federated admin":            federatedAdmin,
		"non-admin who must change password": flaggedUser,
	} {
		t.Run(name, func(t *testing.T) {
			users := mocks.NewUserRepo(t)
			passwords := mocks.NewPasswordRepo(t)

			users.EXPECT().AdminExists(mock.Anything).Return(true, nil)
			users.EXPECT().ByEmail(mock.Anything, "admin@example.com").Return(user, nil)
			passwords.EXPECT().Get(mock.Anything, user.ID).Return("", nil, app.ErrNotFound).Maybe()

			secret, err := app.Bootstrap(context.Background(), users, passwords, testHasher(), "admin@example.com")
			require.NoError(t, err, "Bootstrap")
			require.Empty(t, secret, "Bootstrap issued a password")
		})
	}
}

// An address that already belongs to an ordinary account is not promoted: that would
// hand the installation to whoever holds the account.
func TestBootstrapDoesNotPromoteAnExistingAccount(t *testing.T) {
	users := mocks.NewUserRepo(t)
	users.EXPECT().AdminExists(mock.Anything).Return(false, nil)
	users.EXPECT().Create(mock.Anything, mock.Anything).Return(app.ErrConflict)

	// No password store expectations: issuing one here would fail the test.
	secret, err := app.Bootstrap(context.Background(), users, mocks.NewPasswordRepo(t), testHasher(), "taken@example.com")
	require.ErrorIs(t, err, app.ErrConflict)
	require.Empty(t, secret, "a password was issued for an account that was not created")
}

// LLMPROXY_BOOTSTRAP_ADMIN_EMAIL is optional; unset means no bootstrap, not an
// administrator with no address.
func TestBootstrapWithoutAnAddressDoesNothing(t *testing.T) {
	// Mocks with no expectations: any repository call fails the test.
	secret, err := app.Bootstrap(context.Background(), mocks.NewUserRepo(t), mocks.NewPasswordRepo(t), testHasher(), "")
	require.NoError(t, err, "Bootstrap(\"\")")
	require.Empty(t, secret, "Bootstrap(\"\") issued a password")
}
