// Package spendlimits applies spend limits: it keeps the global defaults, answers
// the policy gate, and serves the cabinet's and the administrators' views.
package spendlimits

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/elleqt/llm-proxy-backend/internal/domain/limits"
	"github.com/google/uuid"
)

const (
	actionDefaults = "limits.defaults_update"
	actionUser     = "user.limits_update"
	actionReset    = "user.limits_reset"
	targetDefaults = "spend_limits"
)

// Audit detail keys; the audit log's readers key on them.
const (
	detailMode          = "mode"
	detailLimits        = "limits"
	detailWindowMinutes = "window_minutes"
	detailAmountUSD     = "amount_usd"
)

// View is an account's spend limits as the API shows them.
type View struct {
	// Custom is the account's own set; nil when it inherits the defaults.
	Custom  *limits.Set
	Windows []limits.WindowState
}

// Service applies spend limits. It holds the global defaults in memory, so the
// policy gate reads them without a query, and swaps them only after the store
// has the new set: a failed write leaves requests limited by the stored one.
// Every administrator method opens with app.RequireAdmin and touches nothing
// for anyone else.
type Service struct {
	users    app.UserRepo
	settings app.SettingsRepo
	windows  app.SpendWindowRepo
	audit    app.AuditSink
	clock    app.Clock

	// mu serialises SetDefaults, so the stored and the in-memory set cannot come
	// from two different writes, and the stale windows it drops are those of the
	// set it stored.
	mu       sync.Mutex
	defaults atomic.Pointer[limits.Set]
}

var _ app.SpendGate = (*Service)(nil)

// New returns the service with empty defaults (no limits) until Load reads the
// stored ones.
func New(users app.UserRepo, settings app.SettingsRepo, windows app.SpendWindowRepo, audit app.AuditSink, clock app.Clock) *Service {
	s := &Service{users: users, settings: settings, windows: windows, audit: audit, clock: clock}
	s.defaults.Store(&limits.Set{})

	return s
}

// Load reads the stored defaults into memory; boot calls it once before serving.
func (s *Service) Load(ctx context.Context) error {
	set, err := s.settings.SpendLimitDefaults(ctx)
	if err != nil {
		return fmt.Errorf("app: load spend limit defaults: %w", err)
	}

	s.defaults.Store(&set)

	return nil
}

// Effective is the set in force for an account whose own set is custom: custom
// itself when set (an empty set meaning no limits), else the defaults in memory.
func (s *Service) Effective(custom *limits.Set) limits.Set {
	return limits.Effective(custom, *s.defaults.Load())
}

// Admit decides at the clock's now whether userID may make one more request
// under set. An admitted request opens the windows due and deletes the stored
// windows of rules set no longer has, in one write, and only when there is
// either; a refusal writes nothing, so retrying cannot restart a window.
func (s *Service) Admit(ctx context.Context, userID uuid.UUID, set limits.Set) (limits.Decision, error) {
	rows, err := s.windows.Windows(ctx, userID)
	if err != nil {
		return limits.Decision{}, fmt.Errorf("app: read spend windows: %w", err)
	}

	now := s.clock.Now()

	decision := limits.Decide(set, rows, now)
	if decision.Blocked || (len(decision.Open) == 0 && len(decision.Orphans) == 0) {
		return decision, nil
	}

	var open []time.Duration
	if len(decision.Open) > 0 {
		open = make([]time.Duration, 0, len(decision.Open))
		for _, r := range decision.Open {
			open = append(open, r.Window)
		}
	}

	if err := s.windows.Open(ctx, userID, open, decision.Orphans, now); err != nil {
		return limits.Decision{}, fmt.Errorf("app: open spend windows: %w", err)
	}

	return decision, nil
}

// Mine is the caller's own view: the effective set with its live windows.
// user is the session's, loaded this request, so no user read is made.
func (s *Service) Mine(ctx context.Context, user identity.User) (View, error) {
	return s.view(ctx, user)
}

// Defaults is the global set in force, from memory, for an administrator.
func (s *Service) Defaults(actor identity.User) (limits.Set, error) {
	if err := app.RequireAdmin(actor); err != nil {
		return nil, err
	}

	return *s.defaults.Load(), nil
}

// SetDefaults replaces the global set. An invalid set is refused as an
// *app.InvalidInputError before anything is written. The set is stored first
// and swapped into memory only once stored; the change is then audited, and the
// windows of dropped rules are deleted from every inheriting account, which
// Admit would otherwise never do for an account whose set became empty. The
// returned set is never nil.
func (s *Service) SetDefaults(ctx context.Context, actor identity.User, set limits.Set) (limits.Set, error) {
	if err := app.RequireAdmin(actor); err != nil {
		return nil, err
	}

	if err := limits.Validate(set); err != nil {
		return nil, inputError(err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.clock.Now().UTC()
	if err := s.settings.SetSpendLimitDefaults(ctx, set, actor.ID, now); err != nil {
		return nil, fmt.Errorf("app: save spend limit defaults: %w", err)
	}

	stored := slices.Clone(set)
	if stored == nil {
		stored = limits.Set{}
	}

	s.defaults.Store(&stored)

	if err := s.record(ctx, actor, actionDefaults, targetDefaults, now, map[string]any{detailLimits: auditRules(set)}); err != nil {
		return nil, err
	}

	keep := make([]time.Duration, 0, len(stored))
	for _, r := range stored {
		keep = append(keep, r.Window)
	}

	if err := s.windows.DropInherited(ctx, keep); err != nil {
		return nil, fmt.Errorf("app: spend limit defaults applied but stale windows remain: %w", err)
	}

	return stored, nil
}

// ForUser is an account's view for an administrator; an unknown id is the
// repository's app.ErrNotFound, wrapped.
func (s *Service) ForUser(ctx context.Context, actor identity.User, id uuid.UUID) (View, error) {
	if err := app.RequireAdmin(actor); err != nil {
		return View{}, err
	}

	user, err := s.users.ByID(ctx, id)
	if err != nil {
		return View{}, fmt.Errorf("app: spend limits of %s: %w", id, err)
	}

	return s.view(ctx, user)
}

// SetUser gives an account its own set, or with custom nil returns it to the
// defaults. An invalid set is refused before anything is read or written. Once
// the account is updated the change is audited, and then the windows of rules
// its effective set no longer has are deleted, so they stop counting now rather
// than at its next request; a failure there reports the change as made.
func (s *Service) SetUser(ctx context.Context, actor identity.User, id uuid.UUID, custom *limits.Set) (View, error) {
	if err := app.RequireAdmin(actor); err != nil {
		return View{}, err
	}

	detail := map[string]any{detailMode: "default"}

	if custom != nil {
		if err := limits.Validate(*custom); err != nil {
			return View{}, inputError(err)
		}

		detail = map[string]any{detailMode: "custom", detailLimits: auditRules(*custom)}
	}

	user, err := s.users.ByID(ctx, id)
	if err != nil {
		return View{}, fmt.Errorf("app: set spend limits of %s: %w", id, err)
	}

	if err := s.users.UpdateSpendLimits(ctx, id, custom); err != nil {
		return View{}, fmt.Errorf("app: set spend limits of %s: %w", id, err)
	}

	user.SpendLimits = custom

	now := s.clock.Now()
	if err := s.record(ctx, actor, actionUser, id.String(), now.UTC(), detail); err != nil {
		return View{}, err
	}

	rows, err := s.windows.Windows(ctx, id)
	if err != nil {
		return View{}, fmt.Errorf("app: spend limits of %s set but stale windows remain: %w", id, err)
	}

	if orphans := limits.Decide(s.Effective(custom), rows, now).Orphans; len(orphans) > 0 {
		if err := s.windows.Open(ctx, id, nil, orphans, now); err != nil {
			return View{}, fmt.Errorf("app: spend limits of %s set but stale windows remain: %w", id, err)
		}
	}

	return s.view(ctx, user)
}

// Reset deletes an account's window of that length, starting it afresh at the
// next request, or every window of the account when window is nil. A window
// the account's effective set has no rule for is refused as the field
// windowMinutes before anything is written.
func (s *Service) Reset(ctx context.Context, actor identity.User, id uuid.UUID, window *time.Duration) (View, error) {
	if err := app.RequireAdmin(actor); err != nil {
		return View{}, err
	}

	user, err := s.users.ByID(ctx, id)
	if err != nil {
		return View{}, fmt.Errorf("app: reset spend limits of %s: %w", id, err)
	}

	detail := map[string]any{detailWindowMinutes: "all"}

	if window != nil {
		inForce := slices.ContainsFunc(s.Effective(user.SpendLimits), func(r limits.Rule) bool { return r.Window == *window })
		if !inForce {
			return View{}, &app.InvalidInputError{Field: "windowMinutes"}
		}

		detail = map[string]any{detailWindowMinutes: int64(*window / time.Minute)}
	}

	if err := s.windows.Reset(ctx, id, window); err != nil {
		return View{}, fmt.Errorf("app: reset spend limits of %s: %w", id, err)
	}

	if err := s.record(ctx, actor, actionReset, id.String(), s.clock.Now().UTC(), detail); err != nil {
		return View{}, err
	}

	return s.view(ctx, user)
}

// view is user's effective set, shortest window first, each rule with its live
// window at the clock's now, and user's own set as Custom.
func (s *Service) view(ctx context.Context, user identity.User) (View, error) {
	rows, err := s.windows.Windows(ctx, user.ID)
	if err != nil {
		return View{}, fmt.Errorf("app: spend windows of %s: %w", user.ID, err)
	}

	return View{
		Custom:  user.SpendLimits,
		Windows: limits.States(s.Effective(user.SpendLimits), rows, s.clock.Now()),
	}, nil
}

// record is adminusers' audit step: the change is durable already, so a failure
// reports it as applied but not audited.
func (s *Service) record(ctx context.Context, actor identity.User, action, target string, at time.Time, detail map[string]any) error {
	if err := s.audit.Record(ctx, app.AuditEvent{At: at, ActorID: actor.ID, Action: action, Target: target, Detail: detail}); err != nil {
		return fmt.Errorf("app: %s on %s applied but not audited: %w", action, target, err)
	}

	return nil
}

// auditRules writes a set as the audit trail records it: whole minutes and
// dollars, in the set's order, and an empty list rather than null for no rules.
func auditRules(set limits.Set) []map[string]any {
	out := make([]map[string]any, 0, len(set))
	for _, r := range set {
		out = append(out, map[string]any{detailWindowMinutes: int64(r.Window / time.Minute), detailAmountUSD: r.AmountUSD})
	}

	return out
}

// inputError names the refused field as the web API spells it; for SetUser it is
// relative to the body's limits array. Any other error is returned unchanged.
func inputError(err error) error {
	var bad *limits.InvalidError
	if !errors.As(err, &bad) {
		return err
	}

	switch bad.Field {
	case limits.FieldCount:
		return &app.InvalidInputError{Field: "limits"}
	case limits.FieldWindow:
		return &app.InvalidInputError{Field: fmt.Sprintf("[%d].windowMinutes", bad.Index)}
	case limits.FieldAmount:
		return &app.InvalidInputError{Field: fmt.Sprintf("[%d].amountUsd", bad.Index)}
	}

	return err
}
