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

// View is an account's spend limits as the API shows them.
type View struct {
	// Custom is the account's own set; nil when it inherits the defaults.
	Custom  *limits.Set
	Windows []limits.WindowState
}

type Service struct {
	users    app.UserRepo
	settings app.SettingsRepo
	windows  app.SpendWindowRepo
	audit    app.AuditSink
	clock    app.Clock

	// mu serialises SetDefaults, so the stored and the in-memory set cannot come
	// from two different writes.
	mu       sync.Mutex
	defaults atomic.Pointer[limits.Set]
}

var _ app.SpendGate = (*Service)(nil)

func New(users app.UserRepo, settings app.SettingsRepo, windows app.SpendWindowRepo, audit app.AuditSink, clock app.Clock) *Service {
	s := &Service{users: users, settings: settings, windows: windows, audit: audit, clock: clock}
	s.defaults.Store(&limits.Set{})

	return s
}

// Load reads the stored defaults; boot calls it once before serving.
func (s *Service) Load(ctx context.Context) error {
	set, err := s.settings.SpendLimitDefaults(ctx)
	if err != nil {
		return fmt.Errorf("app: load spend limit defaults: %w", err)
	}

	s.defaults.Store(&set)

	return nil
}

func (s *Service) Effective(custom *limits.Set) limits.Set {
	return limits.Effective(custom, *s.defaults.Load())
}

func (s *Service) Admit(ctx context.Context, userID uuid.UUID, set limits.Set) (limits.Decision, error) {
	rows, err := s.windows.Windows(ctx, userID)
	if err != nil {
		return limits.Decision{}, fmt.Errorf("app: read spend windows: %w", err)
	}

	now := s.clock.Now()

	d := limits.Decide(set, rows, now)
	if d.Blocked || (len(d.Open) == 0 && len(d.Orphans) == 0) {
		return d, nil
	}

	var open []time.Duration
	for _, r := range d.Open {
		open = append(open, r.Window)
	}

	if err := s.windows.Open(ctx, userID, open, d.Orphans, now); err != nil {
		return limits.Decision{}, fmt.Errorf("app: open spend windows: %w", err)
	}

	return d, nil
}

// Mine is the caller's own view; user is the session's, loaded this request.
func (s *Service) Mine(ctx context.Context, user identity.User) (View, error) {
	return s.view(ctx, user)
}

func (s *Service) Defaults(actor identity.User) (limits.Set, error) {
	if err := app.RequireAdmin(actor); err != nil {
		return nil, err
	}

	return *s.defaults.Load(), nil
}

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

	if err := s.record(ctx, actor, actionDefaults, targetDefaults, now, map[string]any{"limits": auditRules(set)}); err != nil {
		return nil, err
	}

	return stored, nil
}

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

func (s *Service) SetUser(ctx context.Context, actor identity.User, id uuid.UUID, custom *limits.Set) (View, error) {
	if err := app.RequireAdmin(actor); err != nil {
		return View{}, err
	}

	detail := map[string]any{"mode": "default"}
	if custom != nil {
		if err := limits.Validate(*custom); err != nil {
			return View{}, inputError(err)
		}

		detail = map[string]any{"mode": "custom", "limits": auditRules(*custom)}
	}

	user, err := s.users.ByID(ctx, id)
	if err != nil {
		return View{}, fmt.Errorf("app: set spend limits of %s: %w", id, err)
	}

	if err := s.users.UpdateSpendLimits(ctx, id, custom); err != nil {
		return View{}, fmt.Errorf("app: set spend limits of %s: %w", id, err)
	}

	user.SpendLimits = custom

	// Windows of rules the account no longer has go now, not at its next request.
	rows, err := s.windows.Windows(ctx, id)
	if err != nil {
		return View{}, fmt.Errorf("app: set spend limits of %s: %w", id, err)
	}

	now := s.clock.Now()
	if orphans := limits.Decide(s.Effective(custom), rows, now).Orphans; len(orphans) > 0 {
		if err := s.windows.Open(ctx, id, nil, orphans, now); err != nil {
			return View{}, fmt.Errorf("app: set spend limits of %s: %w", id, err)
		}
	}

	if err := s.record(ctx, actor, actionUser, id.String(), now.UTC(), detail); err != nil {
		return View{}, err
	}

	return s.view(ctx, user)
}

func (s *Service) Reset(ctx context.Context, actor identity.User, id uuid.UUID, window *time.Duration) (View, error) {
	if err := app.RequireAdmin(actor); err != nil {
		return View{}, err
	}

	user, err := s.users.ByID(ctx, id)
	if err != nil {
		return View{}, fmt.Errorf("app: reset spend limits of %s: %w", id, err)
	}

	detail := map[string]any{"window_minutes": "all"}
	if window != nil {
		inForce := slices.ContainsFunc(s.Effective(user.SpendLimits), func(r limits.Rule) bool { return r.Window == *window })
		if !inForce {
			return View{}, &app.InvalidInputError{Field: "windowMinutes"}
		}

		detail = map[string]any{"window_minutes": int64(*window / time.Minute)}
	}

	if err := s.windows.Reset(ctx, id, window); err != nil {
		return View{}, fmt.Errorf("app: reset spend limits of %s: %w", id, err)
	}

	if err := s.record(ctx, actor, actionReset, id.String(), s.clock.Now().UTC(), detail); err != nil {
		return View{}, err
	}

	return s.view(ctx, user)
}

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

func auditRules(set limits.Set) []map[string]any {
	out := make([]map[string]any, 0, len(set))
	for _, r := range set {
		out = append(out, map[string]any{"window_minutes": int64(r.Window / time.Minute), "amount_usd": r.AmountUSD})
	}

	return out
}

// inputError names the refused field as the web API spells it; for SetUser it is
// relative to the body's limits array.
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
	default:
		return &app.InvalidInputError{Field: fmt.Sprintf("[%d].amountUsd", bad.Index)}
	}
}
