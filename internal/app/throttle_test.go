package app_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/app/mocks"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/pgtest"
)

// Against the real repository: the lock window is computed by the database from the
// instants the throttle hands it and read back by the throttle, so the two have to
// agree on what a stored time means. The clock is the test's, so a window closing is
// a decision here, not a sleep.
func TestThrottle(t *testing.T) {
	ctx := context.Background()
	attempts := postgres.NewLoginAttemptRepo(pgtest.NewTestPool(t))
	const limit, window = 3, time.Minute
	start := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	charge := func(t *testing.T, th *app.Throttle, email string, times int) {
		t.Helper()
		for range times {
			if err := th.Charge(ctx, email); err != nil {
				t.Fatalf("Charge: %v", err)
			}
		}
	}
	wantLockedUntil := func(t *testing.T, err error, until time.Time) {
		t.Helper()
		var locked *app.LockedOutError
		if !errors.As(err, &locked) || !errors.Is(err, app.ErrLockedOut) {
			t.Fatalf("err = %v, want a *app.LockedOutError", err)
		}
		if !locked.Until.Equal(until) {
			t.Fatalf("locked until %v, want %v", locked.Until, until)
		}
	}

	t.Run("LocksAtTheLimitUntilTheWindowCloses", func(t *testing.T) {
		clock := &fixedClock{now: start}
		th := app.NewThrottle(attempts, limit, window, clock)
		const email = "limit@example.com"

		charge(t, th, email, limit-1)
		if err := th.Check(ctx, email); err != nil {
			t.Fatalf("Check under the limit = %v, want nil", err)
		}
		// The limit-th attempt is admitted — it may be the right password — and locks
		// the address behind it.
		charge(t, th, email, 1)
		wantLockedUntil(t, th.Check(ctx, email), start.Add(window))
		wantLockedUntil(t, th.Charge(ctx, email), start.Add(window))

		// Failing while locked does not push the unlock further away.
		clock.now = start.Add(window - time.Second)
		wantLockedUntil(t, th.Check(ctx, email), start.Add(window))
		wantLockedUntil(t, th.Charge(ctx, email), start.Add(window))

		// The window closed: the address has its whole budget back. limit-1 more
		// failures do not relock it; the limit-th does, with a fresh window.
		reopened := start.Add(window)
		clock.now = reopened
		if err := th.Check(ctx, email); err != nil {
			t.Fatalf("Check once the window closed = %v, want nil", err)
		}
		charge(t, th, email, limit-1)
		if err := th.Check(ctx, email); err != nil {
			t.Fatalf("Check after %d failures in the new window = %v, want nil: "+
				"the limit is per window, not a lifetime total", limit-1, err)
		}
		charge(t, th, email, 1)
		wantLockedUntil(t, th.Check(ctx, email), reopened.Add(window))
		wantLockedUntil(t, th.Charge(ctx, email), reopened.Add(window))
	})

	// Failures that never reached the limit expire too: a count whose last attempt is
	// a window old starts over rather than leaving the address one guess from a lock.
	t.Run("OldFailuresDoNotCount", func(t *testing.T) {
		clock := &fixedClock{now: start}
		th := app.NewThrottle(attempts, limit, window, clock)
		const email = "forgetful@example.com"

		charge(t, th, email, limit-1)
		clock.now = start.Add(window)
		charge(t, th, email, limit-1)
		if err := th.Check(ctx, email); err != nil {
			t.Fatalf("Check = %v, want nil: failures a window old still counted", err)
		}
		charge(t, th, email, 1)
		wantLockedUntil(t, th.Check(ctx, email), start.Add(2*window))
	})

	t.Run("ResetClearsTheCount", func(t *testing.T) {
		th := app.NewThrottle(attempts, limit, window, &fixedClock{now: start})
		const email = "cleared@example.com"

		charge(t, th, email, limit-1)
		if err := th.Reset(ctx, email); err != nil {
			t.Fatalf("Reset: %v", err)
		}
		charge(t, th, email, limit)
	})

	t.Run("ResetLiftsALock", func(t *testing.T) {
		th := app.NewThrottle(attempts, limit, window, &fixedClock{now: start})
		const email = "lifted@example.com"

		charge(t, th, email, limit)
		if err := th.Reset(ctx, email); err != nil {
			t.Fatalf("Reset: %v", err)
		}
		if err := th.Check(ctx, email); err != nil {
			t.Fatalf("Check after Reset = %v, want nil", err)
		}
	})
}

// A parallel burst of guesses at one address gets exactly the limit's worth of
// derivations. The charge is taken before the derivation, atomically, so the attempts
// beyond the limit are refused while the admitted ones are still deriving.
//
// Deterministic without a stopwatch: the admitted derivations are held open until the
// refused attempts have all answered. Charge after the derivation instead and nothing
// is charged while the first limit are held, so the next attempt derives too; it
// returns at once rather than blocking, and the count below catches it.
//
// The address has no account: unknown addresses are charged like any other.
func TestSignInBurstGetsExactlyTheLimitOfDerivations(t *testing.T) {
	const burst, limit = 10, 3
	attempts := postgres.NewLoginAttemptRepo(pgtest.NewTestPool(t))
	users := mocks.NewUserRepo(t)
	users.EXPECT().ByEmail(mock.Anything, "target@example.com").Return(identity.User{}, app.ErrNotFound)

	var (
		mu       sync.Mutex
		verified int
	)
	release := make(chan struct{})
	hasher := app.NewPasswordHasher(burst, identity.HashPassword, func(string, string) bool {
		mu.Lock()
		verified++
		hold := verified <= limit
		mu.Unlock()
		if hold {
			<-release
		}
		return false
	})
	svc := app.NewAuthService(users, nil,
		app.NewThrottle(attempts, limit, time.Hour, systemClock{}), hasher, nil, nil, systemClock{})

	results := make(chan error, burst)
	for range burst {
		go func() {
			_, _, err := svc.SignIn(context.Background(), "target@example.com", "a guess", app.SessionMeta{})
			results <- err
		}()
	}

	outcomes := map[string]int{}
	tally := func(err error) {
		switch {
		case errors.Is(err, app.ErrLockedOut):
			outcomes["locked"]++
		case err == app.ErrInvalidCredentials:
			outcomes["invalid"]++
		default:
			t.Errorf("unexpected error %v", err)
		}
	}
	for range burst - limit {
		tally(<-results)
	}
	close(release)
	for range limit {
		tally(<-results)
	}

	mu.Lock()
	defer mu.Unlock()
	if verified != limit || outcomes["locked"] != burst-limit || outcomes["invalid"] != limit {
		t.Fatalf("%d derivations and outcomes %v, want %d derivations, %d invalid and %d locked",
			verified, outcomes, limit, limit, burst-limit)
	}
}
