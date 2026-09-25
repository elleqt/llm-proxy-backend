package auth_test

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/app/auth"
	"github.com/elleqt/llm-proxy-backend/internal/app/mocks"
	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// fixedClock pins time so an expiry window is a decision of the test rather than a
// race with the wall clock.
type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

var _ app.Clock = fixedClock{}

func humanUser(email string) identity.User {
	return identity.User{
		ID:           uuid.New(),
		Kind:         identity.KindHuman,
		Email:        email,
		DisplayName:  "A Person",
		Role:         identity.RoleUser,
		Status:       identity.StatusActive,
		PolicySource: identity.PolicyLocal,
	}
}

func mustHash(t *testing.T, plain string) string {
	t.Helper()

	h, err := identity.HashPassword(plain)
	require.NoError(t, err, "HashPassword")

	return h
}

// The throttle limits every sign-in test here runs under.
const (
	testMaxFailures = 5
	testLockFor     = 15 * time.Minute
)

// clearingThrottle stands over an address with attempts on record but no lockout, and
// requires the sign-in to charge this one and then clear them all: only a success
// may, and a success must.
func clearingThrottle(t *testing.T, email string, clock app.Clock) *auth.Throttle {
	t.Helper()

	attempts := mocks.NewLoginAttemptRepo(t)
	attempts.EXPECT().Failures(mock.Anything, email).Return(testMaxFailures-2, nil, nil)
	attempts.EXPECT().Charge(mock.Anything, email, testMaxFailures, mock.Anything, mock.Anything).
		Return(testMaxFailures-1, nil, nil)
	attempts.EXPECT().Clear(mock.Anything, email).Return(nil)

	return auth.NewThrottle(attempts, testMaxFailures, testLockFor, clock)
}

// countingThrottle stands over an address that has never failed, and requires the
// sign-in to charge one attempt against it and clear nothing.
func countingThrottle(t *testing.T, email string, clock app.Clock) *auth.Throttle {
	t.Helper()

	attempts := mocks.NewLoginAttemptRepo(t)
	attempts.EXPECT().Failures(mock.Anything, email).Return(0, nil, nil)
	attempts.EXPECT().Charge(mock.Anything, email, testMaxFailures, mock.Anything, mock.Anything).
		Return(1, nil, nil)

	return auth.NewThrottle(attempts, testMaxFailures, testLockFor, clock)
}

// The plaintext session id is the cookie and nothing else. What reaches the store is
// the hash; what reaches the audit trail is neither.
func TestSignInReturnsTheSessionIDToTheCallerAndStoresOnlyItsHash(t *testing.T) {
	ctx := context.Background()
	user := humanUser("person@example.com")
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	users := mocks.NewUserRepo(t)
	passwords := mocks.NewPasswordRepo(t)
	sessions := mocks.NewSessionRepo(t)
	audit := mocks.NewAuditSink(t)

	users.EXPECT().ByEmail(mock.Anything, "person@example.com").Return(user, nil)
	passwords.EXPECT().Get(mock.Anything, user.ID).Return(mustHash(t, "a good password"), nil, nil)

	var stored app.Session

	sessions.EXPECT().Create(mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, s app.Session) error {
			stored = s

			return nil
		})

	var recorded app.AuditEvent

	audit.EXPECT().Record(mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, e app.AuditEvent) error {
			recorded = e

			return nil
		})

	clock := fixedClock{now: now}
	svc := auth.New(users, passwords, clearingThrottle(t, "person@example.com", clock), testHasher(),
		sessions, audit, clock)

	got, _, err := svc.SignIn(ctx, "person@example.com", "a good password",
		app.SessionMeta{IP: "198.51.100.7", UserAgent: "a browser"})
	require.NoError(t, err, "SignIn")
	require.NotEmpty(t, got.ID, "SignIn returned no session id: the caller has nothing to put in a cookie")
	require.Empty(t, stored.ID, "the stored session carries the plaintext id")
	require.Equal(t, auth.HashSessionID(got.ID), stored.IDHash, "stored hash, want the SHA-256 of the returned id")
	require.Equal(t, stored.IDHash, got.IDHash, "returned hash, want the stored one")
	require.Equal(t, user.ID, stored.UserID, "stored session user")
	require.Equal(t, "198.51.100.7", stored.IP, "stored session lost its metadata")
	require.Equal(t, "a browser", stored.UserAgent, "stored session lost its metadata")
	require.True(t, stored.CreatedAt.Equal(now), "window starts at %v, want %v", stored.CreatedAt, now)
	require.True(t, stored.ExpiresAt.Equal(now.Add(auth.SessionTTL)),
		"window ends at %v, want %v", stored.ExpiresAt, now.Add(auth.SessionTTL))

	// An audit row is read by more people than the sessions table is: neither the
	// id nor its hash may be in it.
	rendered := fmt.Sprintf("%+v", recorded)
	require.NotContains(t, rendered, got.ID, "the audit event carries the session id")
	require.NotContains(t, rendered, stored.IDHash, "the audit event carries the session id hash")
}

// A temporary password opens a restricted session — and the restriction is not a
// column. The row that is written says nothing at all; resolving the cookie reads the
// fact off the user.
func TestSignInRestrictsTheSessionOfAUserWhoMustChangeTheirPassword(t *testing.T) {
	user := humanUser("temp@example.com")
	user.MustChangePassword = true
	expiry := time.Date(2026, 3, 2, 12, 0, 0, 0, time.UTC)

	users := mocks.NewUserRepo(t)
	passwords := mocks.NewPasswordRepo(t)
	sessions := mocks.NewSessionRepo(t)

	users.EXPECT().ByEmail(mock.Anything, "temp@example.com").Return(user, nil)
	passwords.EXPECT().Get(mock.Anything, user.ID).Return(mustHash(t, "issued by an admin"), &expiry, nil)

	var stored app.Session

	sessions.EXPECT().Create(mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, s app.Session) error {
			stored = s

			return nil
		})

	clock := fixedClock{now: expiry.Add(-time.Hour)}
	svc := auth.New(users, passwords, clearingThrottle(t, "temp@example.com", clock), testHasher(),
		sessions, nopAudit{}, clock)

	got, _, err := svc.SignIn(context.Background(), "temp@example.com", "issued by an admin", app.SessionMeta{})
	require.NoError(t, err, "SignIn")
	require.False(t, stored.Restricted,
		"the restriction was written to the session row: it is derived from the user, not stored")

	sessions.EXPECT().ByHash(mock.Anything, auth.HashSessionID(got.ID)).Return(stored, nil)
	users.EXPECT().ByID(mock.Anything, user.ID).Return(user, nil)

	resolved, _, err := svc.ResolveSession(context.Background(), got.ID)
	require.NoError(t, err, "ResolveSession")
	require.True(t, resolved.Restricted, "a session opened with a temporary password is not restricted")
}

func TestServiceAccountCannotSignInThroughTheService(t *testing.T) {
	users := mocks.NewUserRepo(t)
	svc := auth.New(users, nil, countingThrottle(t, "chat-panel@example.com", systemClock{}), testHasher(),
		nil, nopAudit{}, systemClock{})

	service := identity.NewService(uuid.New(), "chat-panel", access.Policy{})
	users.EXPECT().ByEmail(mock.Anything, "chat-panel@example.com").Return(service, nil)

	_, _, err := svc.SignIn(context.Background(), "chat-panel@example.com", "whatever", app.SessionMeta{})
	require.Same(t, app.ErrInvalidCredentials, err, "want exactly app.ErrInvalidCredentials, unwrapped")
}

// Every refusal is one answer. A caller must not be able to tell an unknown address
// from a wrong password, and must not be able to learn that an address belongs to a
// blocked person or to a machine.
//
// The comparison is identity (require.Same) and not errors.Is on purpose:
// fmt.Errorf("no such user: %w", ErrInvalidCredentials) satisfies errors.Is on every
// row here while putting the answer back in the message, which is the oracle this
// test exists to close.
//
// The password store is deliberately unreachable on most of these rows: a mock with
// no expectation fails the test if it is called, which pins that a blocked user's
// hash is not even read.
//
// Every row is also one answer to a stopwatch, witnessed without one: each refusal
// must allocate what one argon2 derivation allocates, so a branch that returns before
// the derivation fails here however fast the machine is. And every row is charged
// against the address it named — the unknown one too, or the lockout would tell
// existing addresses from the rest — and clears nothing: the throttle mock has no
// Clear, so a refusal that reset the count fails the test.
func TestEveryRefusalIsTheSameAnswer(t *testing.T) {
	good := humanUser("person@example.com")
	blocked := humanUser("blocked@example.com")
	blocked.Status = identity.StatusBlocked
	noPassword := humanUser("federated@example.com")
	expired := humanUser("expired@example.com")
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Minute)

	decoy := mustHash(t, "a password")
	derivation := allocatedBy(func() { identity.VerifyPassword(decoy, "not the password") })

	cases := []struct {
		name  string
		email string
		setup func(users *mocks.UserRepo, passwords *mocks.PasswordRepo)
	}{
		{
			name:  "no such user",
			email: "nobody@example.com",
			setup: func(users *mocks.UserRepo, _ *mocks.PasswordRepo) {
				users.EXPECT().ByEmail(mock.Anything, "nobody@example.com").
					Return(identity.User{}, app.ErrNotFound)
			},
		},
		{
			name:  "wrong password",
			email: good.Email,
			setup: func(users *mocks.UserRepo, passwords *mocks.PasswordRepo) {
				users.EXPECT().ByEmail(mock.Anything, good.Email).Return(good, nil)
				passwords.EXPECT().Get(mock.Anything, good.ID).
					Return(mustHash(t, "the real one"), nil, nil)
			},
		},
		{
			name:  "blocked user",
			email: blocked.Email,
			setup: func(users *mocks.UserRepo, _ *mocks.PasswordRepo) {
				users.EXPECT().ByEmail(mock.Anything, blocked.Email).Return(blocked, nil)
			},
		},
		{
			name:  "no password at all",
			email: noPassword.Email,
			setup: func(users *mocks.UserRepo, passwords *mocks.PasswordRepo) {
				users.EXPECT().ByEmail(mock.Anything, noPassword.Email).Return(noPassword, nil)
				passwords.EXPECT().Get(mock.Anything, noPassword.ID).
					Return("", nil, app.ErrNotFound)
			},
		},
		{
			name:  "expired temporary password",
			email: expired.Email,
			setup: func(users *mocks.UserRepo, passwords *mocks.PasswordRepo) {
				users.EXPECT().ByEmail(mock.Anything, expired.Email).Return(expired, nil)
				passwords.EXPECT().Get(mock.Anything, expired.ID).
					Return(mustHash(t, "expired-but-correct"), &past, nil)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			users := mocks.NewUserRepo(t)
			passwords := mocks.NewPasswordRepo(t)
			tc.setup(users, passwords)

			attempts := mocks.NewLoginAttemptRepo(t)
			attempts.EXPECT().Failures(mock.Anything, tc.email).Return(0, nil, nil)
			attempts.EXPECT().Charge(mock.Anything, tc.email, testMaxFailures, now, now.Add(testLockFor)).
				Return(1, nil, nil)

			clock := fixedClock{now: now}
			// No session store and no audit sink: a refusal that opened a session
			// or wrote a record would nil-panic here rather than pass quietly.
			svc := auth.New(users, passwords,
				auth.NewThrottle(attempts, testMaxFailures, testLockFor, clock), testHasher(), nil, nil, clock)

			var err error
			// "expired-but-correct" is the right password for the expired row; it is
			// refused because the window closed, not because it is wrong.
			spent := allocatedBy(func() {
				_, _, err = svc.SignIn(context.Background(), tc.email, "expired-but-correct", app.SessionMeta{})
			})

			require.Same(t, app.ErrInvalidCredentials, err, "want exactly app.ErrInvalidCredentials, unwrapped")
			require.GreaterOrEqual(t, spent, derivation/2,
				"refusal allocated %d bytes against %d for one derivation: "+
					"it skipped the password work and answers faster than the others", spent, derivation)
		})
	}
}

// A locked address is refused visibly, with the instant the lock lapses, and at no
// cost: no account lookup and no derivation. The lock is where an attacker's traffic
// concentrates, so spending argon2 on it would be the amplification lever. It is not
// an existence oracle, because every address is charged alike (above).
//
// Both ways a lock is found are covered: already on record, and reached by this very
// attempt's charge — the case a parallel burst produces. The right password is
// presented, and the user and password stores have no expectations, so a lookup
// fails the test; the throttle has no Clear, so a lock lifted by the right password
// fails it too.
func TestLockedAddressIsRefusedWithoutAnyPasswordWork(t *testing.T) {
	const email = "locked@example.com"

	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	until := now.Add(time.Minute)

	decoy := mustHash(t, "a password")
	derivation := allocatedBy(func() { identity.VerifyPassword(decoy, "not the password") })

	cases := []struct {
		name  string
		setup func(attempts *mocks.LoginAttemptRepo)
	}{
		{
			name: "locked on record",
			setup: func(attempts *mocks.LoginAttemptRepo) {
				attempts.EXPECT().Failures(mock.Anything, email).Return(testMaxFailures, &until, nil)
			},
		},
		{
			name: "locked by this attempt's charge",
			setup: func(attempts *mocks.LoginAttemptRepo) {
				attempts.EXPECT().Failures(mock.Anything, email).Return(testMaxFailures, nil, nil)
				attempts.EXPECT().Charge(mock.Anything, email, testMaxFailures, now, now.Add(testLockFor)).
					Return(testMaxFailures+1, &until, nil)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attempts := mocks.NewLoginAttemptRepo(t)
			tc.setup(attempts)

			clock := fixedClock{now: now}
			svc := auth.New(mocks.NewUserRepo(t), mocks.NewPasswordRepo(t),
				auth.NewThrottle(attempts, testMaxFailures, testLockFor, clock), testHasher(), nil, nil, clock)

			var err error

			spent := allocatedBy(func() {
				_, _, err = svc.SignIn(context.Background(), email, "the right password", app.SessionMeta{})
			})

			var locked *app.LockedOutError
			require.ErrorAs(t, err, &locked)
			require.ErrorIs(t, err, app.ErrLockedOut)
			require.True(t, locked.Until.Equal(until),
				"Until = %v, want %v: the client is told when to come back", locked.Until, until)
			require.Less(t, spent, derivation/2,
				"locked refusal allocated %d bytes against %d for one derivation: "+
					"it spent password work on a locked address", spent, derivation)
		})
	}
}

// allocatedBy reports the bytes f allocated. argon2 allocates its whole memory cost
// on every derivation, so this witnesses that one ran without depending on how loaded
// the machine is, which a stopwatch cannot.
func allocatedBy(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)

	return after.TotalAlloc - before.TotalAlloc
}

// Returning the same error is not enough: a refusal that skips the key derivation
// answers in microseconds where a wrong password costs milliseconds, and the
// stopwatch then tells an attacker which addresses exist.
//
// signInAttempt.verify makes that structural — every refusal reaches it and it always
// derives. This measures one path as a backstop against the structure being unpicked.
func TestSignInSpendsPasswordWorkEvenWhenThereIsNothingToVerify(t *testing.T) {
	hash := mustHash(t, "a real password")

	// Baseline: what one verification against a real hash costs on this machine.
	baseline := medianDuration(func() {
		identity.VerifyPassword(hash, "not the password")
	})

	users := mocks.NewUserRepo(t)
	users.EXPECT().ByEmail(mock.Anything, "nobody@example.com").
		Return(identity.User{}, app.ErrNotFound)
	svc := auth.New(users, nil, countingThrottle(t, "nobody@example.com", systemClock{}), testHasher(),
		nil, nil, systemClock{})

	absent := medianDuration(func() {
		_, _, err := svc.SignIn(context.Background(), "nobody@example.com", "guess", app.SessionMeta{})
		assert.Error(t, err, "SignIn succeeded for an unknown address")
	})

	// Half the baseline is a deliberately loose floor: the point is to catch the
	// early return, which is three orders of magnitude cheaper, not to measure.
	require.GreaterOrEqual(t, absent, baseline/2,
		"unknown address answered in %v against a %v verification: "+
			"the sign-in path is short-circuiting and leaks which addresses exist",
		absent, baseline)
}

func medianDuration(run func()) time.Duration {
	const samples = 3

	var got [samples]time.Duration
	for i := range got {
		start := time.Now()

		run()

		got[i] = time.Since(start)
	}

	if got[0] > got[1] {
		got[0], got[1] = got[1], got[0]
	}

	if got[1] > got[2] {
		got[1] = got[2]
	}

	if got[0] > got[1] {
		got[1] = got[0]
	}

	return got[1]
}

// Changing the password ends the restriction: the expiry goes with the old password
// and the flag goes with it. Nothing has to be done to the live session, because the
// session reads the flag rather than a copy of it.
//
// The write order is pinned. Clearing the flag before replacing the password would
// leave a user unflagged and still holding an expired temporary password, and testify
// asserts calls, not sequence, so an unpinned test passes either way.
func TestChangePasswordClearsTheRestrictionAndTheExpiry(t *testing.T) {
	user := humanUser("temp@example.com")
	user.MustChangePassword = true
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	expiry := now.Add(time.Hour)
	sess := app.Session{IDHash: "session-hash", UserID: user.ID, Restricted: true}

	users := mocks.NewUserRepo(t)
	passwords := mocks.NewPasswordRepo(t)

	users.EXPECT().ByID(mock.Anything, user.ID).Return(user, nil)
	passwords.EXPECT().Get(mock.Anything, user.ID).Return(mustHash(t, "temporary"), &expiry, nil)

	var (
		order   []string
		newHash string
	)

	passwords.EXPECT().Set(mock.Anything, user.ID, mock.Anything, (*time.Time)(nil)).
		RunAndReturn(func(_ context.Context, _ uuid.UUID, hash string, _ *time.Time) error {
			order = append(order, "set password")
			newHash = hash

			return nil
		})
	users.EXPECT().SetMustChangePassword(mock.Anything, user.ID, false).
		RunAndReturn(func(_ context.Context, _ uuid.UUID, _ bool) error {
			order = append(order, "clear flag")

			return nil
		})

	sessions := mocks.NewSessionRepo(t)
	sessions.EXPECT().DeleteByUserExcept(mock.Anything, user.ID, sess.IDHash).
		RunAndReturn(func(context.Context, uuid.UUID, string) error {
			order = append(order, "end other sessions")

			return nil
		})

	svc := auth.New(users, passwords, nil, testHasher(), sessions, nopAudit{}, fixedClock{now: now})
	// A restricted session proved the password at sign-in, so none is presented here.
	err := svc.ChangePassword(context.Background(), sess, "", "one I chose myself")
	require.NoError(t, err, "ChangePassword")
	require.True(t, identity.VerifyPassword(newHash, "one I chose myself"),
		"the stored hash does not verify the new password")
	// Other sessions end only once the old password can no longer open a new one.
	require.Equal(t, []string{"set password", "clear flag", "end other sessions"}, order, "write order")
}

// A full session may be hours old and may be a stolen cookie. Without the current
// password, stealing one is enough to rewrite the password and lock the owner out.
func TestChangePasswordRequiresTheCurrentPasswordOnAFullSession(t *testing.T) {
	user := humanUser("person@example.com")
	current := mustHash(t, "the current one")
	sess := app.Session{IDHash: "session-hash", UserID: user.ID, Restricted: false}

	t.Run("wrong current password writes nothing", func(t *testing.T) {
		users := mocks.NewUserRepo(t)
		passwords := mocks.NewPasswordRepo(t)

		users.EXPECT().ByID(mock.Anything, user.ID).Return(user, nil)
		passwords.EXPECT().Get(mock.Anything, user.ID).Return(current, nil, nil)
		// No Set expectation: a write would fail the test.

		svc := auth.New(users, passwords, nil, testHasher(), nil, nopAudit{}, systemClock{})

		err := svc.ChangePassword(context.Background(), sess, "a guess", "something new")
		require.Same(t, app.ErrInvalidCredentials, err, "want exactly app.ErrInvalidCredentials, unwrapped")
	})

	t.Run("no current password at all writes nothing", func(t *testing.T) {
		users := mocks.NewUserRepo(t)
		passwords := mocks.NewPasswordRepo(t)

		users.EXPECT().ByID(mock.Anything, user.ID).Return(user, nil)
		passwords.EXPECT().Get(mock.Anything, user.ID).Return(current, nil, nil)

		svc := auth.New(users, passwords, nil, testHasher(), nil, nopAudit{}, systemClock{})

		err := svc.ChangePassword(context.Background(), sess, "", "something new")
		require.Same(t, app.ErrInvalidCredentials, err, "want exactly app.ErrInvalidCredentials, unwrapped")
	})

	t.Run("the right current password succeeds", func(t *testing.T) {
		users := mocks.NewUserRepo(t)
		passwords := mocks.NewPasswordRepo(t)

		users.EXPECT().ByID(mock.Anything, user.ID).Return(user, nil)
		passwords.EXPECT().Get(mock.Anything, user.ID).Return(current, nil, nil)
		passwords.EXPECT().Set(mock.Anything, user.ID, mock.Anything, (*time.Time)(nil)).Return(nil)
		users.EXPECT().SetMustChangePassword(mock.Anything, user.ID, false).Return(nil)
		// Whoever else holds a cookie for the account is signed out; the caller is not.
		sessions := mocks.NewSessionRepo(t)
		sessions.EXPECT().DeleteByUserExcept(mock.Anything, user.ID, sess.IDHash).Return(nil)

		svc := auth.New(users, passwords, nil, testHasher(), sessions, nopAudit{}, systemClock{})
		err := svc.ChangePassword(context.Background(), sess, "the current one", "something new")
		require.NoError(t, err, "ChangePassword")
	})

	t.Run("sessions that could not be ended are an error", func(t *testing.T) {
		users := mocks.NewUserRepo(t)
		passwords := mocks.NewPasswordRepo(t)

		users.EXPECT().ByID(mock.Anything, user.ID).Return(user, nil)
		passwords.EXPECT().Get(mock.Anything, user.ID).Return(current, nil, nil)
		passwords.EXPECT().Set(mock.Anything, user.ID, mock.Anything, (*time.Time)(nil)).Return(nil)
		users.EXPECT().SetMustChangePassword(mock.Anything, user.ID, false).Return(nil)

		sessions := mocks.NewSessionRepo(t)
		sessions.EXPECT().DeleteByUserExcept(mock.Anything, user.ID, sess.IDHash).Return(errors.New("connection reset"))

		svc := auth.New(users, passwords, nil, testHasher(), sessions, nopAudit{}, systemClock{})
		err := svc.ChangePassword(context.Background(), sess, "the current one", "something new")
		require.Error(t, err, "ChangePassword succeeded although the other sessions may still be open")
	})
}

// A temporary password that outlived its window cannot be spent on a permanent one.
// Otherwise the expiry means nothing to anyone still holding the cookie it issued.
func TestChangePasswordRefusesAnExpiredTemporaryPassword(t *testing.T) {
	user := humanUser("temp@example.com")
	user.MustChangePassword = true
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	expiry := now.Add(-time.Second)

	users := mocks.NewUserRepo(t)
	passwords := mocks.NewPasswordRepo(t)

	users.EXPECT().ByID(mock.Anything, user.ID).Return(user, nil)
	passwords.EXPECT().Get(mock.Anything, user.ID).Return(mustHash(t, "temporary"), &expiry, nil)
	// No Set and no SetMustChangePassword expectation: either call fails the test.

	svc := auth.New(users, passwords, nil, testHasher(), nil, nopAudit{}, fixedClock{now: now})

	err := svc.ChangePassword(context.Background(),
		app.Session{UserID: user.ID, Restricted: true}, "temporary", "a new one")
	require.Same(t, app.ErrInvalidCredentials, err, "want exactly app.ErrInvalidCredentials, unwrapped")
}

// A session outlives the decision to block its owner. The password behind it must not.
func TestChangePasswordRefusesABlockedUser(t *testing.T) {
	user := humanUser("blocked@example.com")
	user.Status = identity.StatusBlocked

	users := mocks.NewUserRepo(t)
	users.EXPECT().ByID(mock.Anything, user.ID).Return(user, nil)

	svc := auth.New(users, nil, nil, testHasher(), nil, nopAudit{}, systemClock{})

	err := svc.ChangePassword(context.Background(),
		app.Session{UserID: user.ID}, "whatever", "a new one")
	require.ErrorIs(t, err, app.ErrForbidden)
}

// An empty password is the absence of one. Accepting it here would silently strip a
// user of their credential while clearing the restriction that protects them.
func TestChangePasswordRefusesTheEmptyPassword(t *testing.T) {
	user := humanUser("person@example.com")
	// Under a temporary password, so the current-password proof is waived and the
	// empty NEW password is the only thing left that can refuse this.
	user.MustChangePassword = true

	users := mocks.NewUserRepo(t)
	passwords := mocks.NewPasswordRepo(t)

	users.EXPECT().ByID(mock.Anything, user.ID).Return(user, nil)
	passwords.EXPECT().Get(mock.Anything, user.ID).Return(mustHash(t, "current"), nil, nil)

	svc := auth.New(users, passwords, nil, testHasher(), nil, nopAudit{}, systemClock{})

	err := svc.ChangePassword(context.Background(),
		app.Session{UserID: user.ID, Restricted: true}, "", "")
	require.ErrorIs(t, err, identity.ErrEmptyPassword)
}

// The waiver of the current-password proof is the one decision where believing the
// caller grants authority. Session.Restricted is a copy the caller supplies; a caller
// claiming Restricted: true for a user who is under no temporary password must not
// skip the proof.
func TestChangePasswordDoesNotTrustASessionThatClaimsToBeRestricted(t *testing.T) {
	user := humanUser("person@example.com")
	user.MustChangePassword = false

	users := mocks.NewUserRepo(t)
	passwords := mocks.NewPasswordRepo(t)

	users.EXPECT().ByID(mock.Anything, user.ID).Return(user, nil)
	passwords.EXPECT().Get(mock.Anything, user.ID).Return(mustHash(t, "the current one"), nil, nil)
	// No Set expectation: a write would fail the test.

	svc := auth.New(users, passwords, nil, testHasher(), nil, nopAudit{}, systemClock{})

	err := svc.ChangePassword(context.Background(),
		app.Session{UserID: user.ID, Restricted: true}, "", "something new")
	require.Same(t, app.ErrInvalidCredentials, err, "want exactly app.ErrInvalidCredentials: a caller-supplied "+
		"restriction was allowed to waive the current-password proof")
}

// A live session with no record of who opened it is worse than no session. If the
// audit write fails, the session goes with it.
func TestSignInDropsTheSessionWhenTheAuditFails(t *testing.T) {
	user := humanUser("person@example.com")

	users := mocks.NewUserRepo(t)
	passwords := mocks.NewPasswordRepo(t)
	sessions := mocks.NewSessionRepo(t)
	audit := mocks.NewAuditSink(t)

	users.EXPECT().ByEmail(mock.Anything, user.Email).Return(user, nil)
	passwords.EXPECT().Get(mock.Anything, user.ID).Return(mustHash(t, "a good password"), nil, nil)

	var created string

	sessions.EXPECT().Create(mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, s app.Session) error {
			created = s.IDHash

			return nil
		})
	audit.EXPECT().Record(mock.Anything, mock.Anything).Return(errors.New("sink down"))

	var deleted string

	sessions.EXPECT().Delete(mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, idHash string) error {
			deleted = idHash

			return nil
		})

	svc := auth.New(users, passwords, clearingThrottle(t, user.Email, systemClock{}), testHasher(),
		sessions, audit, systemClock{})

	got, _, err := svc.SignIn(context.Background(), user.Email, "a good password", app.SessionMeta{})
	require.Error(t, err, "SignIn succeeded although the sign-in was never recorded")
	require.Empty(t, got.ID, "SignIn handed back a session id it had just dropped")
	require.NotEmpty(t, created, "no session was created")
	require.Equal(t, created, deleted, "the deleted session, want the one just created")
}

// The audit most likely fails because the client hung up, which cancels the request
// context. The compensating delete must still run, so it cannot run on that context.
func TestSignInDropsTheSessionEvenWhenTheClientHungUp(t *testing.T) {
	user := humanUser("person@example.com")

	users := mocks.NewUserRepo(t)
	passwords := mocks.NewPasswordRepo(t)
	sessions := mocks.NewSessionRepo(t)
	audit := mocks.NewAuditSink(t)

	users.EXPECT().ByEmail(mock.Anything, user.Email).Return(user, nil)
	passwords.EXPECT().Get(mock.Anything, user.ID).Return(mustHash(t, "a good password"), nil, nil)
	sessions.EXPECT().Create(mock.Anything, mock.Anything).Return(nil)

	ctx, hangUp := context.WithCancel(context.Background())
	defer hangUp()

	audit.EXPECT().Record(mock.Anything, mock.Anything).
		RunAndReturn(func(context.Context, app.AuditEvent) error {
			hangUp()

			return ctx.Err()
		})

	var deleteCtx compensationSeen

	sessions.EXPECT().Delete(mock.Anything, mock.Anything).
		RunAndReturn(func(dctx context.Context, _ string) error {
			deleteCtx = observe(dctx)

			return dctx.Err()
		})

	svc := auth.New(users, passwords, clearingThrottle(t, user.Email, systemClock{}), testHasher(),
		sessions, audit, systemClock{})
	_, _, err := svc.SignIn(ctx, user.Email, "a good password", app.SessionMeta{})
	require.Error(t, err, "SignIn succeeded although the sign-in was never recorded")

	assertCompensationContext(t, deleteCtx)
}

// A password the owner chooses has a floor, counted in characters, not bytes.
func TestChangePasswordRefusesAShortPassword(t *testing.T) {
	for _, tc := range []struct {
		name, plain string
		want        error
	}{
		{"one short", strings.Repeat("a", auth.MinPasswordLength-1), app.ErrWeakPassword},
		// 11 runes in 22 bytes: a byte count would let it through.
		{"multi-byte, one short", strings.Repeat("é", auth.MinPasswordLength-1), app.ErrWeakPassword},
		{"multi-byte at the floor", strings.Repeat("é", auth.MinPasswordLength), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			user := humanUser("person@example.com")
			user.MustChangePassword = true

			users := mocks.NewUserRepo(t)
			passwords := mocks.NewPasswordRepo(t)

			users.EXPECT().ByID(mock.Anything, user.ID).Return(user, nil)
			passwords.EXPECT().Get(mock.Anything, user.ID).Return(mustHash(t, "current"), nil, nil)
			sessions := mocks.NewSessionRepo(t)

			if tc.want == nil {
				passwords.EXPECT().Set(mock.Anything, user.ID, mock.Anything, (*time.Time)(nil)).Return(nil)
				users.EXPECT().SetMustChangePassword(mock.Anything, user.ID, false).Return(nil)
				sessions.EXPECT().DeleteByUserExcept(mock.Anything, user.ID, "").Return(nil)
			}
			// No Set expectation for the refused case: a write fails the test.

			svc := auth.New(users, passwords, nil, testHasher(), sessions, nopAudit{}, systemClock{})

			err := svc.ChangePassword(context.Background(), app.Session{UserID: user.ID}, "", tc.plain)
			require.ErrorIs(t, err, tc.want)
		})
	}
}

// Sign-out removes the session the cookie named and records it, as sign-in does.
func TestSignOutDeletesTheSessionAndRecordsIt(t *testing.T) {
	owner := uuid.New()
	sess := app.Session{IDHash: auth.HashSessionID("the-cookie"), UserID: owner, IP: "192.0.2.1"}

	sessions := mocks.NewSessionRepo(t)
	audit := mocks.NewAuditSink(t)

	sessions.EXPECT().Delete(mock.Anything, sess.IDHash).Return(nil)

	var got app.AuditEvent

	audit.EXPECT().Record(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, e app.AuditEvent) error {
		got = e

		return nil
	})

	svc := auth.New(nil, nil, nil, testHasher(), sessions, audit, systemClock{})
	require.NoError(t, svc.SignOut(context.Background(), sess), "SignOut")
	require.Equal(t, "auth.signout", got.Action, "audit action")
	require.Equal(t, owner, got.ActorID, "audit actor")
	require.Equal(t, "192.0.2.1", got.IP, "audit IP")
}

// A session that could not be deleted is still live, so nothing may record it as
// ended, and a client that hung up does not get to keep it.
func TestSignOutRecordsNothingWhenTheSessionSurvives(t *testing.T) {
	sess := app.Session{IDHash: auth.HashSessionID("the-cookie"), UserID: uuid.New()}
	down := errors.New("database unreachable")

	sessions := mocks.NewSessionRepo(t)
	sessions.EXPECT().Delete(mock.Anything, sess.IDHash).Return(down)

	audit := mocks.NewAuditSink(t) // strict: a Record call fails the test

	svc := auth.New(nil, nil, nil, testHasher(), sessions, audit, systemClock{})
	require.ErrorIs(t, svc.SignOut(context.Background(), sess), down, "want the failed delete")
}

func TestSignOutEndsTheSessionOfAClientThatHungUp(t *testing.T) {
	sess := app.Session{IDHash: auth.HashSessionID("the-cookie"), UserID: uuid.New()}
	ctx, hangUp := context.WithCancel(context.Background())
	hangUp()

	sessions := mocks.NewSessionRepo(t)

	var deleteCtx compensationSeen

	sessions.EXPECT().Delete(mock.Anything, sess.IDHash).RunAndReturn(func(dctx context.Context, _ string) error {
		deleteCtx = observe(dctx)

		return dctx.Err()
	})

	svc := auth.New(nil, nil, nil, testHasher(), sessions, nopAudit{}, systemClock{})
	require.NoError(t, svc.SignOut(ctx, sess), "SignOut on a hung-up request: the session was left open")

	assertCompensationContext(t, deleteCtx)
}

// compensationSeen is what a compensating write's context looked like when the write
// was made. It is captured at the call: the service cancels that context on return.
type compensationSeen struct {
	called      bool
	err         error
	hasDeadline bool
}

func observe(ctx context.Context) compensationSeen {
	_, ok := ctx.Deadline()

	return compensationSeen{called: true, err: ctx.Err(), hasDeadline: ok}
}

// assertCompensationContext requires the compensating write to have run under a context
// that was alive although the request that led to it was cancelled, and bounded by a
// deadline of its own, so a database that hangs cannot hold the compensation forever.
func assertCompensationContext(t *testing.T, seen compensationSeen) {
	t.Helper()

	require.True(t, seen.called, "the compensating write was never made")
	require.NoError(t, seen.err, "the compensating write ran on a dead context: the client's hang-up skipped it")
	require.True(t, seen.hasDeadline, "the compensating write runs with no deadline: a hung database holds it forever")
}
