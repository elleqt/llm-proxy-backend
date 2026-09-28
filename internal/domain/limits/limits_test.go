package limits_test

import (
	"math"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/domain/limits"
	"github.com/stretchr/testify/require"
)

var t0 = time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)

func rule(window time.Duration, amount float64) limits.Rule {
	return limits.Rule{Window: window, AmountUSD: amount}
}

func TestValidateNamesTheFirstRefusal(t *testing.T) {
	eleven := make(limits.Set, 11)
	for i := range eleven {
		eleven[i] = rule(time.Duration(i+1)*time.Hour, 1)
	}

	for name, tc := range map[string]struct {
		set  limits.Set
		want *limits.InvalidError
	}{
		"empty is fine":            {set: limits.Set{}},
		"ten rules are fine":       {set: eleven[:10]},
		"eleven rules":             {set: eleven, want: &limits.InvalidError{Index: -1, Field: limits.FieldCount}},
		"window under a minute":    {set: limits.Set{rule(30*time.Second, 1)}, want: &limits.InvalidError{Index: 0, Field: limits.FieldWindow}},
		"window not whole minutes": {set: limits.Set{rule(90*time.Second, 1)}, want: &limits.InvalidError{Index: 0, Field: limits.FieldWindow}},
		"window over a year":       {set: limits.Set{rule(limits.MaxWindow+time.Minute, 1)}, want: &limits.InvalidError{Index: 0, Field: limits.FieldWindow}},
		"a year is fine":           {set: limits.Set{rule(limits.MaxWindow, 1)}},
		"a minute is fine":         {set: limits.Set{rule(limits.MinWindow, 1)}},
		"the cap is fine":          {set: limits.Set{rule(time.Hour, limits.MaxAmountUSD)}},
		"duplicate window":         {set: limits.Set{rule(2*time.Hour, 10), rule(2*time.Hour, 30)}, want: &limits.InvalidError{Index: 1, Field: limits.FieldWindow}},
		"zero amount":              {set: limits.Set{rule(time.Hour, 0)}, want: &limits.InvalidError{Index: 0, Field: limits.FieldAmount}},
		"negative amount":          {set: limits.Set{rule(time.Hour, -1)}, want: &limits.InvalidError{Index: 0, Field: limits.FieldAmount}},
		"NaN amount":               {set: limits.Set{rule(time.Hour, math.NaN())}, want: &limits.InvalidError{Index: 0, Field: limits.FieldAmount}},
		"infinite amount":          {set: limits.Set{rule(time.Hour, math.Inf(1))}, want: &limits.InvalidError{Index: 0, Field: limits.FieldAmount}},
		"amount over the cap":      {set: limits.Set{rule(time.Hour, limits.MaxAmountUSD+1)}, want: &limits.InvalidError{Index: 0, Field: limits.FieldAmount}},
	} {
		t.Run(name, func(t *testing.T) {
			err := limits.Validate(tc.set)
			if tc.want == nil {
				require.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, limits.ErrInvalid)
			require.Equal(t, tc.want, err)
		})
	}
}

func TestEffectivePrecedence(t *testing.T) {
	defaults := limits.Set{rule(2*time.Hour, 10)}
	custom := limits.Set{rule(time.Hour, 5)}
	none := limits.Set{}

	require.Equal(t, defaults, limits.Effective(nil, defaults), "nil inherits")
	require.Empty(t, limits.Effective(&none, defaults), "empty custom is no limits")
	require.Equal(t, custom, limits.Effective(&custom, defaults), "custom replaces")
}

func TestDecide(t *testing.T) {
	short, long := rule(2*time.Hour, 10), rule(24*time.Hour, 30)
	set := limits.Set{short, long}

	for name, tc := range map[string]struct {
		rows []limits.Window
		now  time.Time
		want limits.Decision
	}{
		"no rows opens every window": {
			now: t0, want: limits.Decision{Open: []limits.Rule{short, long}},
		},
		"below every limit passes": {
			rows: []limits.Window{{Length: 2 * time.Hour, StartedAt: t0, SpentUSD: 9.99}, {Length: 24 * time.Hour, StartedAt: t0, SpentUSD: 9.99}},
			now:  t0.Add(time.Hour), want: limits.Decision{},
		},
		"spent equal to the amount blocks": {
			rows: []limits.Window{{Length: 2 * time.Hour, StartedAt: t0, SpentUSD: 10}, {Length: 24 * time.Hour, StartedAt: t0, SpentUSD: 10}},
			now:  t0.Add(time.Hour),
			want: limits.Decision{Blocked: true, Rule: short, ResetsAt: t0.Add(2 * time.Hour), Wait: time.Hour},
		},
		"a window is expired exactly at its end and reopens": {
			rows: []limits.Window{{Length: 2 * time.Hour, StartedAt: t0, SpentUSD: 10}, {Length: 24 * time.Hour, StartedAt: t0, SpentUSD: 10}},
			now:  t0.Add(2 * time.Hour), want: limits.Decision{Open: []limits.Rule{short}},
		},
		"two exhausted windows block until the later end": {
			rows: []limits.Window{{Length: 2 * time.Hour, StartedAt: t0, SpentUSD: 10}, {Length: 24 * time.Hour, StartedAt: t0, SpentUSD: 30}},
			now:  t0.Add(time.Hour),
			want: limits.Decision{Blocked: true, Rule: long, ResetsAt: t0.Add(24 * time.Hour), Wait: 23 * time.Hour},
		},
		"an exhausted short window with an expired long one opens nothing": {
			rows: []limits.Window{{Length: 2 * time.Hour, StartedAt: t0.Add(24 * time.Hour), SpentUSD: 10}, {Length: 24 * time.Hour, StartedAt: t0, SpentUSD: 30}},
			now:  t0.Add(25 * time.Hour),
			want: limits.Decision{Blocked: true, Rule: short, ResetsAt: t0.Add(26 * time.Hour), Wait: time.Hour},
		},
		"orphan rows are reported and ignored": {
			rows: []limits.Window{{Length: 5 * time.Hour, StartedAt: t0, SpentUSD: 1000}},
			now:  t0, want: limits.Decision{Open: []limits.Rule{short, long}, Orphans: []time.Duration{5 * time.Hour}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.want, limits.Decide(set, tc.rows, tc.now))
		})
	}
}

func TestStatesListEveryRuleInWindowOrder(t *testing.T) {
	short, mid, long := rule(2*time.Hour, 10), rule(5*time.Hour, 10), rule(24*time.Hour, 30)
	rows := []limits.Window{
		{Length: 24 * time.Hour, StartedAt: t0, SpentUSD: 30},
		{Length: 5 * time.Hour, StartedAt: t0, SpentUSD: 9.99},
		{Length: 2 * time.Hour, StartedAt: t0.Add(-3 * time.Hour), SpentUSD: 4}, // expired
	}

	require.Equal(t, []limits.WindowState{
		{Rule: short},
		{Rule: mid, StartedAt: t0, ResetsAt: t0.Add(5 * time.Hour), SpentUSD: 9.99},
		{Rule: long, StartedAt: t0, ResetsAt: t0.Add(24 * time.Hour), SpentUSD: 30, Exhausted: true},
	}, limits.States(limits.Set{long, short, mid}, rows, t0.Add(time.Hour)))
}

// The owner's share never reads 100 before the window refuses, nor below it once
// it does: 99.99% of the amount is 99, the amount or an overshoot is 100.
func TestSpentPercent(t *testing.T) {
	for name, tc := range map[string]struct {
		spent     float64
		exhausted bool
		want      int
	}{
		"none live":              {0, false, 0},
		"float just under 29%":   {0.29, false, 29},
		"a hair under the limit": {0.9999, false, 99},
		"exactly the limit":      {1, true, 100},
		"overshoot":              {1.7, true, 100},
	} {
		t.Run(name, func(t *testing.T) {
			state := limits.WindowState{Rule: rule(time.Hour, 1), SpentUSD: tc.spent, Exhausted: tc.exhausted}
			require.Equal(t, tc.want, state.SpentPercent())
		})
	}
}

func TestLabel(t *testing.T) {
	for window, want := range map[time.Duration]string{
		90 * time.Minute: "90m", 2 * time.Hour: "2h", 24 * time.Hour: "1d", 7 * 24 * time.Hour: "7d", 25 * time.Hour: "25h",
	} {
		require.Equal(t, want, limits.Label(window))
	}
}
