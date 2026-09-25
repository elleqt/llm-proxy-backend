package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
)

// SessionTTL is how long a browser login lasts. It is written onto the row at sign-in
// and enforced by the store, so shortening it here does not retroactively kill the
// sessions already issued under the old value.
const SessionTTL = 12 * time.Hour

// sessionIDLen is the number of random bytes behind a session id. 32 bytes is 256 bits
// of entropy from crypto/rand: guessing one is not a threat model, which is why the id
// is unauthenticated random rather than a signed token.
const sessionIDLen = 32

// AuthService authenticates people against a local password and owns the browser
// session that results.
//
// It is the only place that turns a plaintext password into a session, and the only
// place that mints a session id. Both secrets leave through the return value and
// through nothing else: no audit detail, no error string, no log line.
type AuthService struct {
	sessionOpener

	users     UserRepo
	passwords PasswordRepo
	throttle  *Throttle
	hasher    *PasswordHasher
}

func NewAuthService(
	users UserRepo, passwords PasswordRepo, throttle *Throttle, hasher *PasswordHasher, sessions SessionRepo, audit AuditSink, clock Clock,
) *AuthService {
	return &AuthService{
		users:     users,
		passwords: passwords,
		throttle:  throttle,
		hasher:    hasher,
		sessions:  sessions, audit: audit, clock: clock,
	}
}

// decoyHash is what SignIn verifies against when there is no real hash to verify
// against: an unknown email, a blocked user, a service account, a person who has no
// password at all. Without it those answers come back in microseconds while a wrong
// password costs an argon2 derivation, and the difference is a user enumeration
// oracle that no amount of returning the same error would close.
//
// It is derived at startup from bytes nobody sees, rather than written down as a
// constant, for two reasons. A constant can be mistyped into something VerifyPassword
// rejects at the parse step — which would cost nothing and silently reopen the oracle
// — and a constant freezes the cost parameters at whatever they were the day it was
// pasted, while this tracks HashPassword.
var decoyHash = mustDecoyHash()

func mustDecoyHash() string {
	buf := make([]byte, sessionIDLen)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("app: read decoy password: %v", err))
	}

	hash, err := identity.HashPassword(base64.RawURLEncoding.EncodeToString(buf))
	if err != nil {
		panic(fmt.Sprintf("app: hash decoy password: %v", err))
	}

	return hash
}

// HashSessionID is the one-way function between the cookie value and the stored row.
// Both SignIn and the transport that resolves an incoming cookie go through it, so
// there is no second definition to drift.
func HashSessionID(id string) string {
	sum := sha256.Sum256([]byte(id))

	return hex.EncodeToString(sum[:])
}

// SignIn verifies a local password and opens a session.
//
// The order is the defence, and each step is there for a reason:
//
//  1. A locked address is refused at once with a *LockedOutError: no lookup, no
//     derivation. A lock is where amplification would otherwise concentrate, and it
//     is not an existence oracle, because step 2 charges every address alike.
//  2. The attempt is charged before anything is learned about the account, keyed by
//     the address as typed, so an unknown address counts exactly like a known one.
//     An attempt over the limit is refused like step 1. The charge is atomic, so a
//     parallel burst gets exactly maxFailures derivations and no more.
//  3. Everything else is one answer: an unknown email, a blocked user, a service
//     account, a user with no password, an expired temporary password and a wrong
//     password all return ErrInvalidCredentials after the same argon2 derivation,
//     so a stopwatch cannot tell them apart either.
//  4. Only success clears the count.
//
// Only an infrastructure failure differs from those answers, and that one is not a
// statement about the account. The returned session carries the plaintext id for the
// caller to put in a cookie. The stored copy does not. The user returned is the one
// the password was checked against, so the caller need not load them again.
func (s *AuthService) SignIn(ctx context.Context, email, password string, meta SessionMeta) (Session, identity.User, error) {
	if err := s.throttle.Check(ctx, email); err != nil {
		return Session{}, identity.User{}, err
	}

	if err := s.throttle.Charge(ctx, email); err != nil {
		return Session{}, identity.User{}, err
	}

	attempt, err := s.resolve(ctx, email)
	if err != nil {
		return Session{}, identity.User{}, err
	}

	ok, err := attempt.verify(ctx, s.hasher, password)
	if err != nil {
		return Session{}, identity.User{}, err
	}

	if !ok {
		return Session{}, identity.User{}, ErrInvalidCredentials
	}

	if err := s.throttle.Reset(ctx, email); err != nil {
		return Session{}, identity.User{}, fmt.Errorf("app: clear sign-in attempts: %w", err)
	}

	sess, err := s.open(ctx, attempt.user, "auth.signin", meta)
	if err != nil {
		return Session{}, identity.User{}, err
	}

	return sess, attempt.user, nil
}

// ResolveSession finds the live session behind the plaintext id a cookie carries,
// and its owner. No session, an expired one (the store applies the window), a
// deleted owner and an owner who can no longer sign in are all ErrNotFound: to the
// caller each is simply no session. Any other error is a failed lookup, not a
// verdict on the request.
//
// The owner is loaded on every call and two facts are read off them, neither of
// which is stored on the session:
//
//   - Restricted is users.must_change_password. Deriving it here is what makes a
//     temporary password issued after sign-in bind the session the person is
//     holding now, instead of the next one they open. This is the only place that
//     sets it.
//   - A user who can no longer sign in has no session. An administrator who blocks
//     someone must not have to wait out a twelve-hour window, and a service account
//     that somehow acquired a cookie is refused by the same predicate that refuses
//     it at sign-in.
//
// The plaintext id is hashed before it is used as a lookup key and is not kept: the
// session returned carries only the hash.
func (s *AuthService) ResolveSession(ctx context.Context, id string) (Session, identity.User, error) {
	sess, err := s.sessions.ByHash(ctx, HashSessionID(id))
	if err != nil {
		return Session{}, identity.User{}, fmt.Errorf("app: resolve session: %w", err)
	}

	user, err := s.users.ByID(ctx, sess.UserID)
	if err != nil {
		return Session{}, identity.User{}, fmt.Errorf("app: resolve session: %w", err)
	}

	if !user.CanSignIn() {
		return Session{}, identity.User{}, ErrNotFound
	}

	sess.Restricted = user.MustChangePassword

	return sess, user, nil
}

// sessionOpener mints browser sessions. Every sign-in method — a local password, an
// OpenID Connect login — ends here, so the id generation, the hashing, the window,
// the audit row and the compensating delete exist exactly once.
type sessionOpener struct {
	sessions SessionRepo
	audit    AuditSink
	clock    Clock
}

// open creates a session for a user the caller has already authenticated and found
// eligible, and records it under action. The returned session carries the plaintext
// id for the caller to put in a cookie; the stored copy does not.
func (o sessionOpener) open(ctx context.Context, user identity.User, action string, meta SessionMeta) (Session, error) {
	now := o.clock.Now()

	id, err := newSessionID()
	if err != nil {
		return Session{}, err
	}

	stored := Session{
		IDHash:    HashSessionID(id),
		UserID:    user.ID,
		IP:        meta.IP,
		UserAgent: meta.UserAgent,
		CreatedAt: now,
		ExpiresAt: now.Add(SessionTTL),
	}
	if err := o.sessions.Create(ctx, stored); err != nil {
		return Session{}, fmt.Errorf("app: open session: %w", err)
	}

	if err := o.audit.Record(ctx, AuditEvent{
		At:      now,
		ActorID: user.ID,
		Action:  action,
		Target:  user.ID.String(),
		// No session id, in plaintext or hashed: an audit row is read by more
		// people than the sessions table is.
		Detail:    map[string]any{"restricted": user.MustChangePassword},
		IP:        meta.IP,
		UserAgent: meta.UserAgent,
	}); err != nil {
		// A session nobody can see in the security log is worse than no session:
		// it is a live credential with no record of who opened it. Drop it. The
		// user retries against a database that is either working or honestly down.
		// Detached: the audit most likely failed because the client hung up, and
		// the request context is cancelled for exactly that reason.
		cctx, cancel := compensationContext(ctx)
		defer cancel()

		if derr := o.sessions.Delete(cctx, stored.IDHash); derr != nil {
			//nolint:errorlint // derr is reported, not wrapped: callers match the sign-in failure alone.
			return Session{}, fmt.Errorf("record sign-in: %w (session left open: %v)", err, derr)
		}

		return Session{}, fmt.Errorf("record sign-in: %w", err)
	}

	stored.ID = id

	return stored, nil
}

// signInAttempt is what SignIn learned before it spent any key derivation.
//
// The point of the type is that eligible is unreadable except through verify, and
// verify always performs exactly one argon2 derivation. A refusal cannot be expressed
// as an early return that skips the work, because expressing a refusal here means
// leaving these fields alone and the zero value still costs a full derivation against
// the decoy. The timing defence is therefore a property of the structure rather than
// a rule the next author has to remember.
type signInAttempt struct {
	user     identity.User
	hash     string
	eligible bool
}

// verify reports whether password opens a session. It costs one derivation on every
// path, including the paths where there was never anything to compare against, and
// every one of those derivations queues on the same hasher. Its error is only ever
// the context's, and it does not depend on anything verify was handed.
func (a signInAttempt) verify(ctx context.Context, hasher *PasswordHasher, password string) (bool, error) {
	hash := a.hash
	if hash == "" {
		hash = decoyHash
	}
	// ok is computed before eligible is read, so no short-circuit can skip the
	// derivation however the operands are later reordered.
	ok, err := hasher.Verify(ctx, hash, password)
	if err != nil {
		return false, err
	}

	return ok && a.eligible, nil
}

// ChangePassword replaces the password of the session's owner.
//
// A user under a temporary password proved it minutes ago at sign-in and can reach
// nothing but this endpoint, so possession of the session is the credential:
// currentPlain is not consulted. Anyone else is a different matter — their session may
// be hours old and may be a stolen cookie, so the current password is required.
// Without that check a stolen cookie rewrites the password and locks the owner out of
// their own account.
//
// The waiver is decided by the user row loaded here, NEVER by sess.Restricted. That
// field is a copy the caller supplies, and this is the one place where believing a
// wrong copy would grant authority rather than withhold it: a caller handing in
// Restricted: true would skip the proof. The session's copy is for the transport to
// route on; the authority question is answered from the source.
//
// A changed password ends every other session of the user: whoever else holds a
// cookie — possibly the reason the password is being changed — is signed out, and
// only the caller's session survives. The password is replaced first, so a sign-in
// with the old one cannot open a session after the others were ended.
//
// Either way the stored password must not have expired. A temporary password whose
// window closed cannot be spent on a permanent one, or the expiry would mean nothing
// to anyone still holding the cookie it issued.
func (s *AuthService) ChangePassword(ctx context.Context, sess Session, currentPlain, newPlain string) error {
	user, err := s.users.ByID(ctx, sess.UserID)
	if err != nil {
		return fmt.Errorf("app: change password: %w", err)
	}

	if !user.CanSignIn() {
		return ErrForbidden
	}

	current, expiresAt, err := s.passwords.Get(ctx, user.ID)
	if err != nil {
		return fmt.Errorf("app: change password: %w", err)
	}

	if expiresAt != nil && !s.clock.Now().Before(*expiresAt) {
		return ErrInvalidCredentials
	}

	if !user.MustChangePassword {
		ok, err := s.hasher.Verify(ctx, current, currentPlain)
		if err != nil {
			return err
		}

		if !ok {
			return ErrInvalidCredentials
		}
	}

	if err := checkNewPassword(newPlain); err != nil {
		return err
	}

	hash, err := s.hasher.Hash(ctx, newPlain)
	if err != nil {
		return err
	}
	// The new password is the user's own, so it carries no expiry: nil clears the
	// one the temporary password left behind.
	if err := s.passwords.Set(ctx, user.ID, hash, nil); err != nil {
		return fmt.Errorf("app: change password: %w", err)
	}
	// Order matters. The flag is cleared only after the password it describes is
	// gone; the other order would leave a user unflagged and still holding an
	// expired temporary password. Clearing it is the whole of lifting the
	// restriction from the session the user is holding right now, because that
	// session reads the flag rather than a copy of it.
	if err := s.users.SetMustChangePassword(ctx, user.ID, false); err != nil {
		return fmt.Errorf("app: change password: %w", err)
	}

	if err := s.sessions.DeleteByUserExcept(ctx, user.ID, sess.IDHash); err != nil {
		return fmt.Errorf("app: end the other sessions: %w", err)
	}

	now := s.clock.Now()
	if err := s.audit.Record(ctx, AuditEvent{
		At:        now,
		ActorID:   user.ID,
		Action:    "auth.password_changed",
		Target:    user.ID.String(),
		Detail:    map[string]any{},
		IP:        sess.IP,
		UserAgent: sess.UserAgent,
	}); err != nil {
		// The password is already changed and cannot be unchanged — the old one is
		// not recoverable from the hash that replaced it. The caller is told the
		// audit failed so an operator learns of the gap; the user's next sign-in
		// uses the new password either way.
		return fmt.Errorf("record password change: %w", err)
	}

	return nil
}

// MinPasswordLength is the fewest characters (runes) a password its owner chooses may
// have. It matches the contract's PasswordChangeRequest.newPassword minLength.
const MinPasswordLength = 12

// checkNewPassword refuses a password nobody should be allowed to choose: the empty
// one is the absence of a password (identity.ErrEmptyPassword), a short one is
// ErrWeakPassword. It runs after the caller is authenticated, so it reveals nothing
// to someone who is not.
func checkNewPassword(plain string) error {
	if plain == "" {
		return identity.ErrEmptyPassword
	}

	if utf8.RuneCountInString(plain) < MinPasswordLength {
		return ErrWeakPassword
	}

	return nil
}

// SignOut ends sess and records that it ended, next to the record of it being opened.
//
// The session is deleted before the audit row is written. The other order could
// record a sign-out for a session that a failed delete left alive — a stolen cookie
// the log says is dead. If the audit fails the session is still gone; the error says
// the record is missing so an operator learns of the gap. The delete runs on a
// detached context: a client that hangs up mid-sign-out must not keep its session.
func (s *AuthService) SignOut(ctx context.Context, sess Session) error {
	dctx, cancel := compensationContext(ctx)
	defer cancel()

	if err := s.sessions.Delete(dctx, sess.IDHash); err != nil {
		return fmt.Errorf("app: end session: %w", err)
	}

	if err := s.audit.Record(dctx, AuditEvent{
		At:        s.clock.Now(),
		ActorID:   sess.UserID,
		Action:    "auth.signout",
		Target:    sess.UserID.String(),
		Detail:    map[string]any{},
		IP:        sess.IP,
		UserAgent: sess.UserAgent,
	}); err != nil {
		return fmt.Errorf("record sign-out: %w", err)
	}

	return nil
}

// resolve looks up whatever exists behind email. Its error return is reserved for
// infrastructure failures — a credential decision is never an error here, it is an
// attempt that verify will refuse, because an error would return before the
// derivation and reopen the timing oracle.
func (s *AuthService) resolve(ctx context.Context, email string) (signInAttempt, error) {
	var attempt signInAttempt

	user, err := s.users.ByEmail(ctx, email)
	switch {
	case errors.Is(err, ErrNotFound):
		// No such address. Nothing to fill in.
		return attempt, nil
	case err != nil:
		return attempt, fmt.Errorf("app: sign in: %w", err)
	case !user.CanSignIn():
		// A service account and a blocked user are refused through the one
		// predicate that owns the rule. Their real hash is deliberately not even
		// read: there is no path on which it could matter.
		return attempt, nil
	}

	attempt.user = user

	hash, expiresAt, err := s.passwords.Get(ctx, user.ID)
	switch {
	case errors.Is(err, ErrNotFound):
		// An IdP-only person has no local password.
		return attempt, nil
	case err != nil:
		return attempt, fmt.Errorf("app: sign in: %w", err)
	case expiresAt != nil && !s.clock.Now().Before(*expiresAt):
		// A temporary password that outlived its window is not a credential.
		return attempt, nil
	}

	attempt.hash = hash
	attempt.eligible = true

	return attempt, nil
}

func newSessionID() (string, error) {
	buf := make([]byte, sessionIDLen)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("app: read session id: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(buf), nil
}
