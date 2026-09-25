package app

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// TemporaryPasswordTTL is how long a password an administrator issues stays
// usable. Unclaimed, it lapses and the administrator issues another.
const TemporaryPasswordTTL = 72 * time.Hour

// AuditExpiresAt is the audit detail key for when an issued credential lapses.
const AuditExpiresAt = "expires_at"

// TemporaryPassword is a password shown once, to the administrator who issued it.
type TemporaryPassword struct {
	Password  string
	ExpiresAt time.Time
}

// ResetPassword gives the human account id a temporary password (TemporaryPasswordTTL)
// that must be changed at the next sign-in, and ends every session of the account. It
// is the one reset: an administrator's (adminusers.Service.ResetPassword) and the operator's
// from the shell (recovery.Service.ResetPassword) both go through it, and each records it.
func ResetPassword(
	ctx context.Context, users UserRepo, passwords PasswordRepo, sessions SessionRepo, hasher *PasswordHasher, id uuid.UUID, now time.Time,
) (TemporaryPassword, error) {
	temp, hash, err := DrawTemporaryPassword(ctx, hasher, now)
	if err != nil {
		return TemporaryPassword{}, err
	}
	// The restriction lands before the password. The other order has a window in
	// which the new password opens an unrestricted session.
	if err := users.SetMustChangePassword(ctx, id, true); err != nil {
		return TemporaryPassword{}, fmt.Errorf("app: reset password: %w", err)
	}

	if err := passwords.Set(ctx, id, hash, &temp.ExpiresAt); err != nil {
		return TemporaryPassword{}, fmt.Errorf("app: reset password: %w", err)
	}

	if err := sessions.DeleteByUser(ctx, id); err != nil {
		return TemporaryPassword{}, fmt.Errorf("app: password of %s reset but sessions not ended: %w", id, err)
	}

	return temp, nil
}

// DrawTemporaryPassword draws a password and derives its hash.
func DrawTemporaryPassword(ctx context.Context, hasher *PasswordHasher, now time.Time) (TemporaryPassword, string, error) {
	secret, err := newTemporaryPassword()
	if err != nil {
		return TemporaryPassword{}, "", fmt.Errorf("app: temporary password: %w", err)
	}

	hash, err := hasher.Hash(ctx, secret)
	if err != nil {
		return TemporaryPassword{}, "", fmt.Errorf("app: temporary password: %w", err)
	}

	return TemporaryPassword{Password: secret, ExpiresAt: now.Add(TemporaryPasswordTTL)}, hash, nil
}
