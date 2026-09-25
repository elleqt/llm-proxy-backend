package recovery_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	appauth "github.com/elleqt/llm-proxy-backend/internal/app/auth"
	"github.com/elleqt/llm-proxy-backend/internal/app/mocks"
	apprecovery "github.com/elleqt/llm-proxy-backend/internal/app/recovery"
	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/domain/credentials"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	pgactivity "github.com/elleqt/llm-proxy-backend/internal/infra/postgres/activity"
	pgaudit "github.com/elleqt/llm-proxy-backend/internal/infra/postgres/audit"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/loginattempts"
	pgpasswords "github.com/elleqt/llm-proxy-backend/internal/infra/postgres/passwords"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/pgtest"
	pgsessions "github.com/elleqt/llm-proxy-backend/internal/infra/postgres/sessions"
	pgtokens "github.com/elleqt/llm-proxy-backend/internal/infra/postgres/tokens"
	pgusers "github.com/elleqt/llm-proxy-backend/internal/infra/postgres/users"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// recoveryEnv is Recovery over a real database, beside the sign-in it must let
// people back through.
type recoveryEnv struct {
	users     *pgusers.Repo
	passwords *pgpasswords.Repo
	tokens    *pgtokens.Repo
	activity  *pgactivity.Repo
	auth      *appauth.Service
	recovery  *apprecovery.Service
}

func newRecoveryEnv(t *testing.T) *recoveryEnv {
	t.Helper()
	pool := pgtest.NewTestPool(t)
	users, passwords, sessions := pgusers.New(pool), pgpasswords.New(pool), pgsessions.New(pool)
	attempts, audit, clock := loginattempts.New(pool), pgaudit.New(pool), systemClock{}

	return &recoveryEnv{
		users: users, passwords: passwords, tokens: pgtokens.New(pool), activity: pgactivity.New(pool),
		auth: appauth.New(users, passwords, appauth.NewThrottle(attempts, testMaxFailures, testLockFor, clock),
			testHasher(), sessions, audit, clock),
		recovery: apprecovery.New(users, passwords, sessions, attempts, testHasher(), audit, clock),
	}
}

// account stores a person with a permanent password.
func (e *recoveryEnv) account(t *testing.T, email string, role identity.Role, password string) identity.User {
	t.Helper()

	ctx := context.Background()
	user := humanUser(email)

	user.Role = role
	err := e.users.Create(ctx, user)
	require.NoError(t, err, "create %s", email)

	err = e.passwords.Set(ctx, user.ID, mustHash(t, password), nil)
	require.NoError(t, err, "password of %s", email)

	return user
}

func (e *recoveryEnv) block(t *testing.T, id uuid.UUID) {
	t.Helper()

	blocked := identity.StatusBlocked
	err := e.users.UpdateAdminState(context.Background(), id, app.AdminChange{Status: &blocked})
	require.NoError(t, err, "block")
}

func (e *recoveryEnv) storedHash(t *testing.T, id uuid.UUID) string {
	t.Helper()

	hash, _, err := e.passwords.Get(context.Background(), id)
	require.NoError(t, err, "password")

	return hash
}

// cliAudit returns the detail of each audit event on id recorded with no actor, by
// action.
func (e *recoveryEnv) cliAudit(t *testing.T, id uuid.UUID) map[string]map[string]any {
	t.Helper()

	events, err := e.activity.RecentAudit(context.Background(), id, 50)
	require.NoError(t, err, "audit")

	out := map[string]map[string]any{}

	for _, ev := range events {
		if ev.ActorID == uuid.Nil && ev.Target == id.String() {
			out[ev.Action] = ev.Detail
		}
	}

	return out
}

// The operator's way back in: a person locked out by failed attempts, with a
// session open somewhere and an API key in use, gets a temporary password that
// signs in at once to a restricted session. The session someone else may hold ends,
// the old password stops working, the API key keeps working, and the audit log says
// it came from the shell.
func TestRecoveryIssuesAWorkingTemporaryPassword(t *testing.T) {
	ctx := context.Background()
	env := newRecoveryEnv(t)

	const old = "the password I forgot"

	user := env.account(t, "Person@Example.com", identity.RoleUser, old)

	held, _, err := env.auth.SignIn(ctx, user.Email, old, app.SessionMeta{})
	require.NoError(t, err, "SignIn")

	key, _, err := credentials.Generate(user.ID, "ops")
	require.NoError(t, err)

	err = env.tokens.Create(ctx, key)
	require.NoError(t, err)

	for range testMaxFailures {
		_, _, err := env.auth.SignIn(ctx, user.Email, "a wrong guess", app.SessionMeta{})
		require.ErrorIs(t, err, app.ErrInvalidCredentials, "wrong password")
	}

	_, _, err = env.auth.SignIn(ctx, user.Email, old, app.SessionMeta{})
	require.ErrorIs(t, err, app.ErrLockedOut, "after %d failures: want locked out", testMaxFailures)

	before := time.Now()

	got, err := env.recovery.ResetPassword(ctx, "  person@EXAMPLE.com ", false)
	require.NoError(t, err, "ResetPassword")
	require.Equal(t, user.ID, got.User.ID, "recovered user")
	require.False(t, got.Unblocked, "recovered %+v, want not unblocked", got.User)

	_, expiry, err := env.passwords.Get(ctx, user.ID)
	require.NoError(t, err)

	lo, hi := before.Add(app.TemporaryPasswordTTL), time.Now().Add(app.TemporaryPasswordTTL)

	require.NotNil(t, expiry, "stored expiry")
	// Postgres keeps microseconds.
	require.Less(t, expiry.Sub(got.Password.ExpiresAt).Abs(), time.Microsecond,
		"expiry stored %v, shown %v", *expiry, got.Password.ExpiresAt)
	require.WithinRange(t, got.Password.ExpiresAt, lo, hi, "shown expiry, want %s from now", app.TemporaryPasswordTTL)

	_, _, err = env.auth.ResolveSession(ctx, held.ID)
	require.ErrorIs(t, err, app.ErrNotFound, "the session open before the reset: want it ended")

	_, _, err = env.auth.SignIn(ctx, user.Email, old, app.SessionMeta{})
	require.ErrorIs(t, err, app.ErrInvalidCredentials, "the old password: want refused")

	sess, _, err := env.auth.SignIn(ctx, user.Email, got.Password.Password, app.SessionMeta{})
	require.NoError(t, err, "SignIn with the temporary password")

	resolved, _, err := env.auth.ResolveSession(ctx, sess.ID)
	require.NoError(t, err, "ResolveSession")
	require.True(t, resolved.Restricted, "session = %+v; want a restricted one", resolved)

	kept, err := env.tokens.ByID(ctx, key.ID)
	require.NoError(t, err, "API key after the reset")
	require.Nil(t, kept.RevokedAt, "API key after the reset: want it live")

	audit := env.cliAudit(t, user.ID)
	d, ok := audit["user.password_reset"]
	require.True(t, ok, "actorless audit events %v, want user.password_reset", audit)
	require.Equal(t, "cli", d["via"], "user.password_reset via")

	assertNoSecret(t, []app.AuditEvent{{Detail: audit["user.password_reset"]}}, got.Password.Password)
}

// Every refusal leaves the account as it was: the stored password is not replaced.
func TestRecoveryRefusesWhatItCannotSafelyRecover(t *testing.T) {
	ctx := context.Background()
	env := newRecoveryEnv(t)

	_, err := env.recovery.ResetPassword(ctx, "nobody@example.com", false)
	require.ErrorIs(t, err, app.ErrNotFound, "unknown address")

	// A blocked person is an administrator's decision, whatever the flag says.
	person := env.account(t, "person@example.com", identity.RoleUser, "their password")
	env.block(t, person.ID)
	hash := env.storedHash(t, person.ID)

	for _, unblock := range []bool{false, true} {
		var blocked *app.BlockedError

		_, err := env.recovery.ResetPassword(ctx, person.Email, unblock)
		require.ErrorAs(t, err, &blocked, "blocked person, unblock=%v", unblock)
		require.False(t, blocked.CanUnblock, "blocked person, unblock=%v: want not unblockable", unblock)
	}

	require.Equal(t, hash, env.storedHash(t, person.ID), "a refused recovery replaced the password")

	// A blocked administrator while another one is active: that one unblocks.
	admin := env.account(t, "admin@example.com", identity.RoleAdmin, "admin password")
	other := env.account(t, "other-admin@example.com", identity.RoleAdmin, "other password")
	env.block(t, admin.ID)

	var blocked *app.BlockedError

	_, err = env.recovery.ResetPassword(ctx, admin.Email, true)
	require.ErrorAs(t, err, &blocked, "blocked admin beside an active one")
	require.False(t, blocked.CanUnblock, "blocked admin beside an active one: want not unblockable")

	// No other active administrator — an active ordinary account does not count:
	// unblocking is offered, and done only when asked.
	env.account(t, "bystander@example.com", identity.RoleUser, "bystander password")
	env.block(t, other.ID)

	hash = env.storedHash(t, admin.ID)
	_, err = env.recovery.ResetPassword(ctx, admin.Email, false)
	require.ErrorAs(t, err, &blocked, "sole blocked admin without --unblock")
	require.True(t, blocked.CanUnblock, "sole blocked admin without --unblock: want unblockable")
	require.Equal(t, hash, env.storedHash(t, admin.ID), "a refused recovery replaced the password")

	got, err := env.recovery.ResetPassword(ctx, admin.Email, true)
	require.NoError(t, err, "sole blocked admin with --unblock")
	require.True(t, got.Unblocked, "the recovery does not report the unblock")

	_, _, err = env.auth.SignIn(ctx, admin.Email, got.Password.Password, app.SessionMeta{})
	require.NoError(t, err, "the unblocked administrator signs in")

	d := env.cliAudit(t, admin.ID)["user.update"]
	require.Equal(t, "cli", d["via"], "unblock audit via")
	require.Equal(t, string(identity.StatusActive), d["status"], "unblock audit status")
}

// The unblock is audited before anything else is tried: a reset that then fails
// leaves an active account whose unblock is on record, which a retry — finding the
// account active — would not record again.
func TestRecoveryRecordsTheUnblockEvenWhenTheResetFails(t *testing.T) {
	users := mocks.NewUserRepo(t)
	admin := humanUser("admin@example.com")
	admin.Role, admin.Status = identity.RoleAdmin, identity.StatusBlocked
	users.EXPECT().ByEmail(mock.Anything, admin.Email).Return(admin, nil)
	users.EXPECT().List(mock.Anything).Return([]app.UserView{{User: admin}}, nil)

	var unblocked []app.AuditEvent

	users.EXPECT().Unblock(mock.Anything, admin.ID, mock.Anything).
		RunAndReturn(func(_ context.Context, _ uuid.UUID, e app.AuditEvent) error {
			unblocked = append(unblocked, e)

			return nil
		})

	failure := errors.New("database went away")
	users.EXPECT().SetMustChangePassword(mock.Anything, admin.ID, true).Return(failure)
	r := apprecovery.New(users, mocks.NewPasswordRepo(t), mocks.NewSessionRepo(t), mocks.NewLoginAttemptRepo(t),
		testHasher(), mocks.NewAuditSink(t), systemClock{})

	_, err := r.ResetPassword(context.Background(), admin.Email, true)
	require.ErrorIs(t, err, failure, "want the reset's failure")

	require.Len(t, unblocked, 1, "unblock records: want one actorless user.update")
	require.Equal(t, "user.update", unblocked[0].Action, "unblock action")
	require.Equal(t, uuid.Nil, unblocked[0].ActorID, "unblock actor: want none")
	require.Equal(t, "cli", unblocked[0].Detail["via"], "unblock via")
	require.Equal(t, string(identity.StatusActive), unblocked[0].Detail["status"], "unblock status")
}

// A service account has no password to reset. It has no address either, so only a
// store that returned one by address could reach this; nothing is written if one did.
func TestRecoveryOfAServiceAccountIsNotLocal(t *testing.T) {
	users := mocks.NewUserRepo(t)
	svc := identity.NewService(uuid.New(), "chat-panel", access.Policy{})
	users.EXPECT().ByEmail(mock.Anything, "panel@example.com").Return(svc, nil)
	r := apprecovery.New(users, mocks.NewPasswordRepo(t), mocks.NewSessionRepo(t), mocks.NewLoginAttemptRepo(t),
		testHasher(), mocks.NewAuditSink(t), systemClock{})

	_, err := r.ResetPassword(context.Background(), "panel@example.com", false)
	require.ErrorIs(t, err, app.ErrNotLocal)
}
