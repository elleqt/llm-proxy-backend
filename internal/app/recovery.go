package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/google/uuid"
)

// ErrBlocked is what a *BlockedError unwraps to.
var ErrBlocked = errors.New("app: account is blocked")

// BlockedError refuses a recovery for a blocked account: a new password would not let
// it in, and unblocking is an administrator's decision.
type BlockedError struct {
	// CanUnblock reports that the recovery may unblock the account when asked to: it
	// is an administrator and no other active administrator exists who could.
	CanUnblock bool
}

func (e *BlockedError) Error() string { return ErrBlocked.Error() }
func (e *BlockedError) Unwrap() error { return ErrBlocked }

// Recovery is the way back into an installation from the shell of the host it runs
// on, when nobody can sign in to reset a password on the web interface: the sole
// administrator forgot theirs, or never saw the bootstrap one. Access to that shell
// is the authority, so there is no actor: every change is recorded with none and
// {"via": "cli"}.
type Recovery struct {
	users     UserRepo
	passwords PasswordRepo
	sessions  SessionRepo
	attempts  LoginAttemptRepo
	hasher    *PasswordHasher
	audit     AuditSink
	clock     Clock
}

func NewRecovery(
	users UserRepo, passwords PasswordRepo, sessions SessionRepo, attempts LoginAttemptRepo,
	hasher *PasswordHasher, audit AuditSink, clock Clock,
) *Recovery {
	return &Recovery{
		users: users, passwords: passwords, sessions: sessions, attempts: attempts,
		hasher: hasher, audit: audit, clock: clock,
	}
}

// Recovered is the outcome of a recovery: the account and its temporary password,
// shown once.
type Recovered struct {
	User      identity.User
	Password  TemporaryPassword
	Unblocked bool
}

// ResetPassword gives the human account at email, compared case-insensitively as
// sign-in does, the temporary password an administrator's reset would
// (AdminUsers.ResetPassword): it must be changed at the next sign-in, and every
// session of the account ends. It also clears the sign-in lockout of the address, so
// an account locked out by failed attempts can sign in at once. API tokens are left
// alone. Everything is in the database, so a running server honours it from the next
// request.
//
//   - No account at email is ErrNotFound; a service account is ErrNotLocal.
//   - A blocked account is a *BlockedError. With unblock, an administrator is
//     unblocked as well when no other active administrator exists — the one case
//     nobody could unblock it on the web interface. Anyone else stays refused: an
//     active administrator decides.
//
// The unblock and its user.update record are one write, made first: whatever fails
// after it, the unblock is on record, and a retry finds the account active. Any
// failure withholds the password: the caller retries, and a retry issues another.
func (r *Recovery) ResetPassword(ctx context.Context, email string, unblock bool) (Recovered, error) {
	user, err := r.users.ByEmail(ctx, strings.TrimSpace(email))
	if err != nil {
		return Recovered{}, fmt.Errorf("app: recover account: %w", err)
	}

	if user.Kind != identity.KindHuman {
		return Recovered{}, ErrNotLocal
	}

	out := Recovered{User: user}
	if user.Status != identity.StatusActive {
		canUnblock := false

		if user.Role == identity.RoleAdmin {
			other, err := r.otherActiveAdmin(ctx, user.ID)
			if err != nil {
				return Recovered{}, err
			}

			canUnblock = !other
		}

		if !unblock || !canUnblock {
			return Recovered{}, &BlockedError{CanUnblock: canUnblock}
		}

		out.Unblocked = true
	}

	now := r.clock.Now().UTC()

	if out.Unblocked {
		active := identity.StatusActive
		if err := r.users.Unblock(ctx, user.ID, AuditEvent{
			At: now, Action: "user.update", Target: user.ID.String(),
			Detail: map[string]any{"via": "cli", "status": string(active)},
		}); err != nil {
			return Recovered{}, fmt.Errorf("app: unblock %s: %w", user.ID, err)
		}

		out.User.Status = active
	}
	// An old password that signs in between the unblock and the reset gets a session
	// the reset ends; after the reset it no longer signs in.
	out.Password, err = resetPassword(ctx, r.users, r.passwords, r.sessions, r.hasher, user.ID, now)
	if err != nil {
		return Recovered{}, err
	}

	if err := r.attempts.Clear(ctx, user.Email); err != nil {
		return Recovered{}, fmt.Errorf("app: password of %s reset but sign-in lockout not cleared: %w", user.ID, err)
	}

	out.User.MustChangePassword = true

	if err := r.record(ctx, "user.password_reset", user.ID, now,
		map[string]any{"via": "cli", auditExpiresAt: out.Password.ExpiresAt.Format(time.RFC3339)}); err != nil {
		return Recovered{}, err
	}

	return out, nil
}

// otherActiveAdmin reports whether an administrator other than id can sign in.
func (r *Recovery) otherActiveAdmin(ctx context.Context, id uuid.UUID) (bool, error) {
	all, err := r.users.List(ctx)
	if err != nil {
		return false, fmt.Errorf("app: find another administrator: %w", err)
	}

	for _, v := range all {
		if v.User.ID != id && v.User.Role == identity.RoleAdmin && v.User.CanSignIn() {
			return true, nil
		}
	}

	return false, nil
}

// record writes a recovery step to the audit log, with no actor. As for an
// administrator's change, a step that landed unaudited is reported as an error.
func (r *Recovery) record(ctx context.Context, action string, target uuid.UUID, at time.Time, detail map[string]any) error {
	if err := r.audit.Record(ctx, AuditEvent{At: at, Action: action, Target: target.String(), Detail: detail}); err != nil {
		return fmt.Errorf("app: %s on %s applied but not audited: %w", action, target, err)
	}

	return nil
}
