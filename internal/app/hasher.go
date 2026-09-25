package app

import (
	"context"
	"fmt"
)

// PasswordHasher runs every password key derivation — hashing a new password,
// verifying a presented one, verifying against the decoy — under one bounded
// semaphore.
//
// Each derivation holds about 19 MiB for about 20 ms. Unbounded, a spray of sign-ins
// across distinct addresses (which no per-address throttle sees) turns into as many
// concurrent derivations as the listener accepts, and memory runs out before the CPU
// does. Bounded, the same spray queues: sign-ins get slower, the process survives.
//
// The decoy goes through the same gate as a real hash on purpose. If only real hashes
// queued, an unknown address would answer faster under load than a known one, and the
// queue would become the enumeration oracle the decoy exists to close.
type PasswordHasher struct {
	slots  chan struct{}
	hash   func(plain string) (string, error)
	verify func(hash, plain string) bool
}

// NewPasswordHasher bounds derivations to capacity at a time. hash and verify are the
// derivations themselves — identity.HashPassword and identity.VerifyPassword in
// production; they are parameters so a test can count what is in flight without a
// stopwatch. A non-positive capacity panics: it would deadlock every sign-in.
func NewPasswordHasher(capacity int, hash func(plain string) (string, error), verify func(hash, plain string) bool) *PasswordHasher {
	if capacity < 1 {
		panic(fmt.Sprintf("app: password hasher needs a positive capacity, got %d", capacity))
	}

	return &PasswordHasher{slots: make(chan struct{}, capacity), hash: hash, verify: verify}
}

// Hash derives a storable hash of plain. It waits for a slot for as long as ctx
// allows, and returns ctx's error if ctx ends first.
func (h *PasswordHasher) Hash(ctx context.Context, plain string) (string, error) {
	if err := h.acquire(ctx); err != nil {
		return "", err
	}
	defer h.release()

	return h.hash(plain)
}

// Verify reports whether plain is the password behind hash, waiting for a slot as
// Hash does. The error is only ever ctx's: a mismatch is false, never an error.
func (h *PasswordHasher) Verify(ctx context.Context, hash, plain string) (bool, error) {
	if err := h.acquire(ctx); err != nil {
		return false, err
	}
	defer h.release()

	return h.verify(hash, plain), nil
}

func (h *PasswordHasher) acquire(ctx context.Context) error {
	// A caller that has already gone must not take a slot it will never use, even
	// when one is free: select picks at random between ready cases.
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("app: wait for a hashing slot: %w", err)
	}

	select {
	case h.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("app: wait for a hashing slot: %w", ctx.Err())
	}
}

func (h *PasswordHasher) release() { <-h.slots }
