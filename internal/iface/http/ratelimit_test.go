package http

import (
	"strconv"
	"testing"
	"time"
)

// A spray of addresses cannot grow the limiter past MaxClients.
func TestLimiterStaysBounded(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)}

	l := newLimiter(RateLimit{Burst: 2, Every: time.Minute, MaxClients: 3}, clock)
	for i := range 100 {
		l.allow("spray-" + strconv.Itoa(i))

		if n := len(l.buckets); n > 3 {
			t.Fatalf("after %d clients the limiter remembers %d, want at most 3", i+1, n)
		}
	}
}

// Making room forgets a client whose bucket is full again — which changes nothing —
// before it forgets one that is still being limited, even an older one: forgetting
// that one would hand it a fresh burst.
func TestLimiterForgetsRecoveredClientsFirst(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)}
	rateLimiter := newLimiter(RateLimit{Burst: 2, Every: time.Minute, MaxClients: 2}, clock)

	rateLimiter.allow("limited") // seen first, so the oldest
	rateLimiter.allow("limited")
	clock.advance(10 * time.Second)
	rateLimiter.allow("recovered")
	clock.advance(time.Minute) // "recovered" is full again; "limited" is not

	rateLimiter.allow("newcomer")

	if _, kept := rateLimiter.buckets["limited"]; !kept {
		t.Fatal("a client still being limited was forgotten while a recovered one could have been")
	}

	if len(rateLimiter.buckets) != 2 {
		t.Fatalf("the limiter remembers %d clients, want 2", len(rateLimiter.buckets))
	}
}
