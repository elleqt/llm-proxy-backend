package app

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
)

// temporaryPasswordLen is the number of random bytes behind every password this
// package generates — the bootstrap one and those an administrator issues: 192 bits
// from crypto/rand, rendered as 32 URL-safe characters a person can copy out of a
// terminal or a browser without quoting.
const temporaryPasswordLen = 24

// newTemporaryPassword draws a fresh password. It is the only generator in the
// package, so every issued password has the same strength.
func newTemporaryPassword() (string, error) {
	buf := make([]byte, temporaryPasswordLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// Bootstrap creates the first administrator of an empty installation and returns its
// temporary password. The password is returned exactly once and exists nowhere else
// in plaintext: this package never logs it, and showing it to the operator is the
// composition root's job.
//
// It returns "" when there is nothing to do: email is empty (bootstrap disabled), or
// an administrator already exists, so calling it on every start is safe. The
// administrator must change the password at first sign-in.
//
// The user row and its password are two writes with no transaction between them. A
// start that dies in between leaves an administrator with no password, whom every
// later start would count as "an administrator exists" — an installation nobody can
// sign in to. Bootstrap therefore finishes that half-done job: an administrator at
// email who still has to change a password they were never given gets a new one.
//
// An email that already belongs to an account that is not an administrator is an
// error wrapping ErrConflict. Promoting it would hand the installation to whoever
// holds that account, which may be a federated user nobody vetted for this.
func Bootstrap(ctx context.Context, users UserRepo, passwords PasswordRepo, hasher *PasswordHasher, email string) (string, error) {
	if email == "" {
		return "", nil
	}
	exists, err := users.AdminExists(ctx)
	if err != nil {
		return "", fmt.Errorf("app: bootstrap: %w", err)
	}
	if exists {
		return resumeBootstrap(ctx, users, passwords, hasher, email)
	}

	admin := identity.User{
		ID:                 uuid.New(),
		Kind:               identity.KindHuman,
		Email:              email,
		DisplayName:        "Administrator",
		Role:               identity.RoleAdmin,
		Status:             identity.StatusActive,
		PolicySource:       identity.PolicyLocal,
		MustChangePassword: true,
	}
	if err := users.Create(ctx, admin); err != nil {
		return "", fmt.Errorf("app: bootstrap administrator: %w", err)
	}
	return issueBootstrapPassword(ctx, passwords, hasher, admin.ID)
}

// resumeBootstrap issues a password to a bootstrap administrator whose password
// never landed, and does nothing for anyone else.
func resumeBootstrap(ctx context.Context, users UserRepo, passwords PasswordRepo, hasher *PasswordHasher, email string) (string, error) {
	u, err := users.ByEmail(ctx, email)
	switch {
	case errors.Is(err, ErrNotFound):
		return "", nil
	case err != nil:
		return "", fmt.Errorf("app: bootstrap: %w", err)
	case u.Role != identity.RoleAdmin || !u.MustChangePassword:
		return "", nil
	}
	_, _, err = passwords.Get(ctx, u.ID)
	switch {
	case err == nil:
		return "", nil
	case !errors.Is(err, ErrNotFound):
		return "", fmt.Errorf("app: bootstrap: %w", err)
	}
	return issueBootstrapPassword(ctx, passwords, hasher, u.ID)
}

// issueBootstrapPassword stores a fresh password for id and returns its plaintext.
// It carries no expiry: the administrator is forced to replace it at first sign-in,
// and an expiry would strand an installation whose operator was slower than the
// window, since an existing administrator suppresses every later bootstrap.
func issueBootstrapPassword(ctx context.Context, passwords PasswordRepo, hasher *PasswordHasher, id uuid.UUID) (string, error) {
	secret, err := newTemporaryPassword()
	if err != nil {
		return "", fmt.Errorf("app: bootstrap password: %w", err)
	}
	hash, err := hasher.Hash(ctx, secret)
	if err != nil {
		return "", fmt.Errorf("app: bootstrap password: %w", err)
	}
	if err := passwords.Set(ctx, id, hash, nil); err != nil {
		return "", fmt.Errorf("app: bootstrap password: %w", err)
	}
	return secret, nil
}
