// Package limits holds the spend-limit rules: what an account may spend per
// window, when a window opens and ends, and whether one more request is
// admitted. Amounts are the usage ledger's cost estimate in US dollars.
//
// A window opens with the first request admitted while it has none (or its last
// one ended), runs for its rule's length and, once spent reaches the amount,
// blocks until it ends. The windows of a set run independently of each other.
package limits

import (
	"cmp"
	"errors"
	"math"
	"slices"
	"strconv"
	"time"
)

const (
	// MaxRules bounds a set, so a request reads at most this many windows.
	MaxRules = 10
	// MinWindow and MaxWindow bound a window, which is whole minutes.
	MinWindow = time.Minute
	MaxWindow = 365 * 24 * time.Hour
	// MaxAmountUSD bounds one rule's amount.
	MaxAmountUSD = 1_000_000
)

// Rule caps what an account spends within one window.
type Rule struct {
	Window    time.Duration
	AmountUSD float64
}

// Set is every rule applying to an account. A window appears at most once: it
// is the rule's identity, and the key its stored window is found by.
type Set []Rule

// Field is what an InvalidError refuses.
type Field uint8

const (
	// FieldCount: the set holds more than MaxRules rules.
	FieldCount Field = iota
	// FieldWindow: a window out of bounds, not whole minutes, or repeated.
	FieldWindow
	// FieldAmount: an amount not above zero, above MaxAmountUSD, or NaN.
	FieldAmount
)

// ErrInvalid is what every *InvalidError unwraps to.
var ErrInvalid = errors.New("limits: invalid spend limits")

// InvalidError names the first thing Validate refuses. Index is the rule's
// position, or -1 for the set as a whole (FieldCount).
type InvalidError struct {
	Index int
	Field Field
}

func (e *InvalidError) Error() string {
	return ErrInvalid.Error() + " at rule " + strconv.Itoa(e.Index)
}
func (e *InvalidError) Unwrap() error { return ErrInvalid }

// Validate accepts a set every rule of which is within bounds, with no window
// repeated, and at most MaxRules rules.
func Validate(set Set) error {
	if len(set) > MaxRules {
		return &InvalidError{Index: -1, Field: FieldCount}
	}

	for index, rule := range set {
		repeated := slices.ContainsFunc(set[:index], func(o Rule) bool { return o.Window == rule.Window })
		if rule.Window < MinWindow || rule.Window > MaxWindow || rule.Window%time.Minute != 0 || repeated {
			return &InvalidError{Index: index, Field: FieldWindow}
		}
		// +Inf is above the cap and -Inf below zero; NaN compares false to both.
		if math.IsNaN(rule.AmountUSD) || rule.AmountUSD <= 0 || rule.AmountUSD > MaxAmountUSD {
			return &InvalidError{Index: index, Field: FieldAmount}
		}
	}

	return nil
}

// Effective is the set in force for an account: its own when custom is set (an
// empty one meaning no limits), else the defaults.
func Effective(custom *Set, defaults Set) Set {
	if custom != nil {
		return *custom
	}

	return defaults
}

// Window is the stored state of one rule's window for one account.
type Window struct {
	Length    time.Duration
	StartedAt time.Time
	SpentUSD  float64
}

// EndsAt is when the window stops counting.
func (w Window) EndsAt() time.Time { return w.StartedAt.Add(w.Length) }

// LiveAt reports whether the window still counts at now.
func (w Window) LiveAt(now time.Time) bool { return now.Before(w.EndsAt()) }

// Decision is Decide's answer.
type Decision struct {
	// Blocked: some live window is exhausted. Rule is the exhausted rule whose
	// window ends last, ResetsAt that end, and Wait the time from now until it.
	Blocked  bool
	Rule     Rule
	ResetsAt time.Time
	Wait     time.Duration
	// Open lists the rules whose window is missing or expired, to open at now
	// when the request is admitted. Nil when Blocked: a refusal opens nothing.
	Open []Rule
	// Orphans are stored windows no rule of the set has, sorted.
	Orphans []time.Duration
}

// Decide says whether an account with set and the stored windows rows may make
// one more request at now.
func Decide(set Set, rows []Window, now time.Time) Decision {
	var decision Decision

	stored := make(map[time.Duration]Window, len(rows))
	for _, w := range rows {
		stored[w.Length] = w
	}

	for _, rule := range set {
		window, ok := stored[rule.Window]
		delete(stored, rule.Window)

		if !ok || !window.LiveAt(now) {
			decision.Open = append(decision.Open, rule)

			continue
		}

		if window.SpentUSD >= rule.AmountUSD && (!decision.Blocked || window.EndsAt().After(decision.ResetsAt)) {
			decision.Blocked, decision.Rule, decision.ResetsAt = true, rule, window.EndsAt()
		}
	}

	for length := range stored {
		decision.Orphans = append(decision.Orphans, length)
	}

	slices.Sort(decision.Orphans)

	if decision.Blocked {
		decision.Open = nil
		decision.Wait = decision.ResetsAt.Sub(now)
	}

	return decision
}

// WindowState is one rule and its live window, as the API shows it. StartedAt
// and ResetsAt are zero, and SpentUSD 0, when no window is live.
type WindowState struct {
	Rule      Rule
	StartedAt time.Time
	ResetsAt  time.Time
	SpentUSD  float64
	Exhausted bool
}

// States is every rule of set with its live window at now, shortest window first.
func States(set Set, rows []Window, now time.Time) []WindowState {
	stored := make(map[time.Duration]Window, len(rows))
	for _, w := range rows {
		stored[w.Length] = w
	}

	ordered := slices.SortedFunc(slices.Values(set), func(a, b Rule) int { return cmp.Compare(a.Window, b.Window) })
	out := make([]WindowState, 0, len(ordered))

	for _, r := range ordered {
		state := WindowState{Rule: r}
		if w, ok := stored[r.Window]; ok && w.LiveAt(now) {
			state.StartedAt, state.ResetsAt, state.SpentUSD = w.StartedAt, w.EndsAt(), w.SpentUSD
			state.Exhausted = w.SpentUSD >= r.AmountUSD
		}

		out = append(out, state)
	}

	return out
}

// Label writes a window as a refusal names it: whole days "7d", else whole hours
// "2h", else minutes "90m".
func Label(window time.Duration) string {
	const day = 24 * time.Hour

	switch {
	case window%day == 0:
		return strconv.FormatInt(int64(window/day), 10) + "d"
	case window%time.Hour == 0:
		return strconv.FormatInt(int64(window/time.Hour), 10) + "h"
	default:
		return strconv.FormatInt(int64(window/time.Minute), 10) + "m"
	}
}
