package app

import (
	"context"
	"fmt"
	"time"
)

// Throttle limits password guessing per address: maxFailures attempts per window of
// lockFor, and an address that reaches the limit is locked for lockFor.
//
// Every attempt is charged before any password work is spent on it, and only a
// successful sign-in clears the count. Charging first is what makes the limit hold
// under a parallel burst: the count is taken atomically by the repository, so of k
// concurrent attempts exactly the ones the limit allows reach the derivation.
//
// The limit is per window, not a lifetime total: once a lock lapses, or when the last
// attempt is a window old, the count starts over and the address again gets
// maxFailures attempts. A person who mistyped a few times last week is not one guess
// from a lockout today.
type Throttle struct {
	attempts    LoginAttemptRepo
	maxFailures int
	lockFor     time.Duration
	clock       Clock
}

// NewThrottle panics on a non-positive limit or window: either would lock every
// address forever or never, and both are programming errors in the composition root.
func NewThrottle(attempts LoginAttemptRepo, maxFailures int, lockFor time.Duration, clock Clock) *Throttle {
	if maxFailures < 1 || lockFor <= 0 {
		panic(fmt.Sprintf("app: throttle needs a positive limit and window, got %d and %v", maxFailures, lockFor))
	}

	return &Throttle{attempts: attempts, maxFailures: maxFailures, lockFor: lockFor, clock: clock}
}

// Check returns a *LockedOutError while email is inside a lock window, without
// charging anything. Any other error is an infrastructure failure.
func (t *Throttle) Check(ctx context.Context, email string) error {
	_, until, err := t.attempts.Failures(ctx, email)
	if err != nil {
		return fmt.Errorf("app: sign-in attempts: %w", err)
	}

	if until != nil && t.clock.Now().Before(*until) {
		return &LockedOutError{Until: *until}
	}

	return nil
}

// Charge counts one attempt against email and returns a *LockedOutError when the
// attempt is over the limit. An attempt Charge admits must end in Reset if it
// succeeds; if it fails, the charge already is the failure.
func (t *Throttle) Charge(ctx context.Context, email string) error {
	now := t.clock.Now()

	count, until, err := t.attempts.Charge(ctx, email, t.maxFailures, now, now.Add(t.lockFor))
	if err != nil {
		return fmt.Errorf("app: charge sign-in attempt: %w", err)
	}

	if count <= t.maxFailures {
		return nil
	}
	// Over the limit always comes with a window; fail closed if a repository ever
	// breaks that rather than admit the attempt.
	lapse := now.Add(t.lockFor)
	if until != nil {
		lapse = *until
	}

	return &LockedOutError{Until: lapse}
}

// Reset forgets every attempt of email, including an open lock. Only a successful
// sign-in may call it.
func (t *Throttle) Reset(ctx context.Context, email string) error {
	if err := t.attempts.Clear(ctx, email); err != nil {
		return fmt.Errorf("app: clear sign-in attempts: %w", err)
	}

	return nil
}
