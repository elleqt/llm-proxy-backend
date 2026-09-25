package http

import (
	"sync"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
)

// RateLimit is a per-client token bucket: Burst attempts at once, then one more every
// Every. MaxClients bounds how many clients are remembered.
//
// It complements, and does not replace, the per-address lockout in auth.Throttle. The
// lockout stops guessing at one account from many clients; this stops one client
// spraying many accounts — which the lockout cannot see, since every address it
// tries is fresh — and bounds the argon2 work a single client can make the server do.
type RateLimit struct {
	Burst      int
	Every      time.Duration
	MaxClients int
}

// DefaultSignInRate admits ten sign-in attempts at once and one every six seconds
// after that: ample for a person, and it caps a single client at ten guesses a
// minute across every account.
var DefaultSignInRate = RateLimit{Burst: 10, Every: 6 * time.Second, MaxClients: 10_000}

// limiter holds one bucket per client key.
type limiter struct {
	rate  RateLimit
	clock app.Clock

	mu      sync.Mutex
	buckets map[string]*bucket
}

// bucket is a client's tokens as of last.
type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(rate RateLimit, clock app.Clock) *limiter {
	return &limiter{rate: rate, clock: clock, buckets: make(map[string]*bucket)}
}

// allow takes one token from key's bucket. When there is none it reports how long
// until there is.
func (l *limiter) allow(key string) (bool, time.Duration) {
	now := l.clock.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	entry, ok := l.buckets[key]
	if !ok {
		l.makeRoom(now)
		entry = &bucket{tokens: float64(l.rate.Burst), last: now}
		l.buckets[key] = entry
	}

	entry.tokens = l.refilled(entry, now)

	entry.last = now
	if entry.tokens >= 1 {
		entry.tokens--

		return true, 0
	}

	return false, time.Duration((1 - entry.tokens) * float64(l.rate.Every))
}

// refilled is b's token count at now.
func (l *limiter) refilled(entry *bucket, now time.Time) float64 {
	elapsed := now.Sub(entry.last)
	if elapsed <= 0 {
		return entry.tokens
	}

	return min(float64(l.rate.Burst), entry.tokens+float64(elapsed)/float64(l.rate.Every))
}

// makeRoom keeps the map within MaxClients before a new client is added. A bucket
// that has refilled completely is indistinguishable from a fresh one, so those go
// first and forgetting them changes nothing. Only if every remembered client is still
// being limited is one forgotten for real: the one seen longest ago, whose bucket is
// the closest to full. Refusing the newcomer instead would let anyone who controls
// enough addresses lock every new client out.
func (l *limiter) makeRoom(now time.Time) {
	if len(l.buckets) < l.rate.MaxClients {
		return
	}

	for k, b := range l.buckets {
		if l.refilled(b, now) >= float64(l.rate.Burst) {
			delete(l.buckets, k)
		}
	}

	for len(l.buckets) >= l.rate.MaxClients {
		var (
			oldest string
			at     time.Time
		)
		for k, b := range l.buckets {
			if oldest == "" || b.last.Before(at) {
				oldest, at = k, b.last
			}
		}

		delete(l.buckets, oldest)
	}
}
