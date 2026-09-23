package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/app/mocks"
	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/domain/credentials"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/pgtest"
)

// recoveryEnv is Recovery over a real database, beside the sign-in it must let
// people back through.
type recoveryEnv struct {
	users     *postgres.UserRepo
	passwords *postgres.PasswordRepo
	tokens    *postgres.TokenRepo
	activity  *postgres.ActivityRepo
	auth      *app.AuthService
	recovery  *app.Recovery
}

func newRecoveryEnv(t *testing.T) *recoveryEnv {
	t.Helper()
	pool := pgtest.NewTestPool(t)
	users, passwords, sessions := postgres.NewUserRepo(pool), postgres.NewPasswordRepo(pool), postgres.NewSessionRepo(pool)
	attempts, audit, clock := postgres.NewLoginAttemptRepo(pool), postgres.NewAuditSink(pool), systemClock{}
	return &recoveryEnv{
		users: users, passwords: passwords, tokens: postgres.NewTokenRepo(pool), activity: postgres.NewActivityRepo(pool),
		auth: app.NewAuthService(users, passwords, app.NewThrottle(attempts, testMaxFailures, testLockFor, clock),
			testHasher(), sessions, audit, clock),
		recovery: app.NewRecovery(users, passwords, sessions, attempts, testHasher(), audit, clock),
	}
}

// account stores a person with a permanent password.
func (e *recoveryEnv) account(t *testing.T, email string, role identity.Role, password string) identity.User {
	t.Helper()
	ctx := context.Background()
	u := humanUser(email)
	u.Role = role
	if err := e.users.Create(ctx, u); err != nil {
		t.Fatalf("create %s: %v", email, err)
	}
	if err := e.passwords.Set(ctx, u.ID, mustHash(t, password), nil); err != nil {
		t.Fatalf("password of %s: %v", email, err)
	}
	return u
}

func (e *recoveryEnv) block(t *testing.T, id uuid.UUID) {
	t.Helper()
	blocked := identity.StatusBlocked
	if err := e.users.UpdateAdminState(context.Background(), id, app.AdminChange{Status: &blocked}); err != nil {
		t.Fatalf("block: %v", err)
	}
}

func (e *recoveryEnv) storedHash(t *testing.T, id uuid.UUID) string {
	t.Helper()
	hash, _, err := e.passwords.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("password: %v", err)
	}
	return hash
}

// cliAudit returns the detail of each audit event on id recorded with no actor, by
// action.
func (e *recoveryEnv) cliAudit(t *testing.T, id uuid.UUID) map[string]map[string]any {
	t.Helper()
	events, err := e.activity.RecentAudit(context.Background(), id, 50)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
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
	e := newRecoveryEnv(t)
	const old = "the password I forgot"
	u := e.account(t, "Person@Example.com", identity.RoleUser, old)

	held, _, err := e.auth.SignIn(ctx, u.Email, old, app.SessionMeta{})
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	key, _, err := credentials.Generate(u.ID, "ops")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.tokens.Create(ctx, key); err != nil {
		t.Fatal(err)
	}
	for range testMaxFailures {
		if _, _, err := e.auth.SignIn(ctx, u.Email, "a wrong guess", app.SessionMeta{}); !errors.Is(err, app.ErrInvalidCredentials) {
			t.Fatalf("wrong password: err = %v", err)
		}
	}
	if _, _, err := e.auth.SignIn(ctx, u.Email, old, app.SessionMeta{}); !errors.Is(err, app.ErrLockedOut) {
		t.Fatalf("after %d failures: err = %v, want locked out", testMaxFailures, err)
	}

	before := time.Now()
	got, err := e.recovery.ResetPassword(ctx, "  person@EXAMPLE.com ", false)
	if err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}
	if got.User.ID != u.ID || got.Unblocked {
		t.Fatalf("recovered %+v, want %s, not unblocked", got.User, u.ID)
	}
	_, expiry, err := e.passwords.Get(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	lo, hi := before.Add(app.TemporaryPasswordTTL), time.Now().Add(app.TemporaryPasswordTTL)
	// Postgres keeps microseconds.
	if expiry == nil || expiry.Sub(got.Password.ExpiresAt).Abs() >= time.Microsecond ||
		got.Password.ExpiresAt.Before(lo) || got.Password.ExpiresAt.After(hi) {
		t.Fatalf("expiry stored %v, shown %v, want %s from now", expiry, got.Password.ExpiresAt, app.TemporaryPasswordTTL)
	}

	if _, _, err := e.auth.ResolveSession(ctx, held.ID); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("the session open before the reset: err = %v, want it ended", err)
	}
	if _, _, err := e.auth.SignIn(ctx, u.Email, old, app.SessionMeta{}); !errors.Is(err, app.ErrInvalidCredentials) {
		t.Fatalf("the old password: err = %v, want refused", err)
	}
	sess, _, err := e.auth.SignIn(ctx, u.Email, got.Password.Password, app.SessionMeta{})
	if err != nil {
		t.Fatalf("SignIn with the temporary password: %v", err)
	}
	if resolved, _, err := e.auth.ResolveSession(ctx, sess.ID); err != nil || !resolved.Restricted {
		t.Fatalf("session = %+v, %v; want a restricted one", resolved, err)
	}

	if kept, err := e.tokens.ByID(ctx, key.ID); err != nil || kept.RevokedAt != nil {
		t.Fatalf("API key after the reset = %+v, %v; want it live", kept, err)
	}
	audit := e.cliAudit(t, u.ID)
	if d, ok := audit["user.password_reset"]; !ok || d["via"] != "cli" {
		t.Fatalf("actorless audit events %v, want user.password_reset via cli", audit)
	}
	assertNoSecret(t, []app.AuditEvent{{Detail: audit["user.password_reset"]}}, got.Password.Password)
}

// Every refusal leaves the account as it was: the stored password is not replaced.
func TestRecoveryRefusesWhatItCannotSafelyRecover(t *testing.T) {
	ctx := context.Background()
	e := newRecoveryEnv(t)

	if _, err := e.recovery.ResetPassword(ctx, "nobody@example.com", false); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("unknown address: err = %v, want ErrNotFound", err)
	}

	// A blocked person is an administrator's decision, whatever the flag says.
	person := e.account(t, "person@example.com", identity.RoleUser, "their password")
	e.block(t, person.ID)
	hash := e.storedHash(t, person.ID)
	for _, unblock := range []bool{false, true} {
		var blocked *app.BlockedError
		if _, err := e.recovery.ResetPassword(ctx, person.Email, unblock); !errors.As(err, &blocked) || blocked.CanUnblock {
			t.Fatalf("blocked person, unblock=%v: err = %v, want blocked and not unblockable", unblock, err)
		}
	}
	if e.storedHash(t, person.ID) != hash {
		t.Fatal("a refused recovery replaced the password")
	}

	// A blocked administrator while another one is active: that one unblocks.
	admin := e.account(t, "admin@example.com", identity.RoleAdmin, "admin password")
	other := e.account(t, "other-admin@example.com", identity.RoleAdmin, "other password")
	e.block(t, admin.ID)
	var blocked *app.BlockedError
	if _, err := e.recovery.ResetPassword(ctx, admin.Email, true); !errors.As(err, &blocked) || blocked.CanUnblock {
		t.Fatalf("blocked admin beside an active one: err = %v, want blocked and not unblockable", err)
	}

	// No other active administrator: unblocking is offered, and done only when asked.
	e.block(t, other.ID)
	hash = e.storedHash(t, admin.ID)
	if _, err := e.recovery.ResetPassword(ctx, admin.Email, false); !errors.As(err, &blocked) || !blocked.CanUnblock {
		t.Fatalf("sole blocked admin without --unblock: err = %v, want blocked and unblockable", err)
	}
	if e.storedHash(t, admin.ID) != hash {
		t.Fatal("a refused recovery replaced the password")
	}
	got, err := e.recovery.ResetPassword(ctx, admin.Email, true)
	if err != nil {
		t.Fatalf("sole blocked admin with --unblock: %v", err)
	}
	if !got.Unblocked {
		t.Fatal("the recovery does not report the unblock")
	}
	if _, _, err := e.auth.SignIn(ctx, admin.Email, got.Password.Password, app.SessionMeta{}); err != nil {
		t.Fatalf("the unblocked administrator signs in: %v", err)
	}
	if d := e.cliAudit(t, admin.ID)["user.update"]; d["via"] != "cli" || d["status"] != string(identity.StatusActive) {
		t.Fatalf("unblock audit detail = %v, want status active via cli", d)
	}
}

// A service account has no password to reset. It has no address either, so only a
// store that returned one by address could reach this; nothing is written if one did.
func TestRecoveryOfAServiceAccountIsNotLocal(t *testing.T) {
	users := mocks.NewUserRepo(t)
	svc := identity.NewService(uuid.New(), "chat-panel", access.Policy{})
	users.EXPECT().ByEmail(mock.Anything, "panel@example.com").Return(svc, nil)
	r := app.NewRecovery(users, mocks.NewPasswordRepo(t), mocks.NewSessionRepo(t), mocks.NewLoginAttemptRepo(t),
		testHasher(), mocks.NewAuditSink(t), systemClock{})

	if _, err := r.ResetPassword(context.Background(), "panel@example.com", false); !errors.Is(err, app.ErrNotLocal) {
		t.Fatalf("err = %v, want ErrNotLocal", err)
	}
}
