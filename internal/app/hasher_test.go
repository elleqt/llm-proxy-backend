package app_test

import (
	"context"
	"sync"
	"testing"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/stretchr/testify/require"
)

// The bound is the defence against a spray of sign-ins across distinct addresses,
// which no per-address throttle sees: without it every accepted request holds 19 MiB
// at once. Counted through the derivation seam rather than timed.
//
// capacity derivations are held open; one more caller must wait rather than derive,
// and must give up when its context ends. A derivation that starts beyond the bound
// returns at once instead of blocking, so a missing semaphore fails this test instead
// of hanging it.
func TestPasswordHasherBoundsConcurrentDerivations(t *testing.T) {
	const capacity = 3

	var (
		mu       sync.Mutex
		inFlight int
		peak     int
	)

	entered := make(chan struct{}, capacity+1)
	release := make(chan struct{})
	derive := func() {
		mu.Lock()
		inFlight++
		peak = max(peak, inFlight)
		over := inFlight > capacity
		mu.Unlock()

		entered <- struct{}{}

		if !over {
			<-release
		}

		mu.Lock()
		inFlight--
		mu.Unlock()
	}
	hasher := app.NewPasswordHasher(capacity,
		func(string) (string, error) {
			derive()

			return "hash", nil
		},
		func(string, string) bool {
			derive()

			return true
		})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	results := make(chan error, capacity+1)
	for i := range capacity + 1 {
		go func() {
			// Both entry points share the one bound.
			if i%2 == 0 {
				_, err := hasher.Hash(ctx, "p")
				results <- err

				return
			}

			_, err := hasher.Verify(ctx, "h", "p")
			results <- err
		}()
	}

	for range capacity {
		<-entered
	}
	// capacity are deriving and holding their slots. The last caller is either
	// waiting for a slot or, with no bound, has already derived and returned.
	cancel()

	beyond := <-results

	mu.Lock()
	peakAtCancel := peak
	mu.Unlock()

	require.ErrorIs(t, beyond, context.Canceled,
		"the caller beyond capacity %d must give up without deriving (%d derivations at the peak)",
		capacity, peakAtCancel)

	close(release)

	for range capacity {
		require.NoError(t, <-results, "a caller holding a slot failed")
	}

	require.LessOrEqual(t, peak, capacity, "derivations running at once")
}
