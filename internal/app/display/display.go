// Package display keeps the deployment's response-visibility preferences in memory
// and serves their administrator-only updates.
package display

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
)

const (
	actionUpdate = "display.update"
	targetConfig = "display"
	// detailCostsVisible is the audit detail key the audit log's readers key on.
	detailCostsVisible = "costs_visible"
)

// Service holds the display settings. The in-memory copy is swapped only after
// the store has the new one, so a failed write leaves the stored value in force.
// Every administrator method opens with app.RequireAdmin.
type Service struct {
	settings app.SettingsRepo
	audit    app.AuditSink
	clock    app.Clock

	// mu serialises Set, so the stored and the in-memory value come from one write.
	mu      sync.Mutex
	current atomic.Pointer[app.DisplayConfig]
}

var _ app.CostVisibility = (*Service)(nil)

// New hides costs and masks unknown upstream errors until Load reads saved preferences.
func New(settings app.SettingsRepo, audit app.AuditSink, clock app.Clock) *Service {
	s := &Service{settings: settings, audit: audit, clock: clock}
	s.current.Store(&app.DisplayConfig{MaskUnknownErrors: true})

	return s
}

// Load reads the stored settings into memory; boot calls it once before serving.
func (s *Service) Load(ctx context.Context) error {
	cfg, err := s.settings.DisplayConfig(ctx)
	if err != nil {
		return fmt.Errorf("app: load display config: %w", err)
	}

	s.current.Store(&cfg)

	return nil
}

// CostsVisible reports, from memory, whether users are shown their costs in US
// dollars.
func (s *Service) CostsVisible() bool { return s.current.Load().CostsVisible }

// MaskUnknownErrors reports whether unclassified upstream 5xx details are hidden.
func (s *Service) MaskUnknownErrors() bool { return s.current.Load().MaskUnknownErrors }

// CostsVisibleTo is CostsVisible for user: an administrator sees every cost in
// the admin panel anyway, so their own cabinet shows it whatever the setting.
func (s *Service) CostsVisibleTo(user identity.User) bool {
	return user.Role == identity.RoleAdmin || s.CostsVisible()
}

// Get is the settings in force, from memory, for an administrator.
func (s *Service) Get(actor identity.User) (app.DisplayConfig, error) {
	if err := app.RequireAdmin(actor); err != nil {
		return app.DisplayConfig{}, err
	}

	return *s.current.Load(), nil
}

// Patch changes only explicitly supplied preferences.
type Patch struct {
	CostsVisible      *bool
	MaskUnknownErrors *bool
}

// Set persists supplied preferences before publishing them to request handlers.
func (s *Service) Set(ctx context.Context, actor identity.User, patch Patch) (app.DisplayConfig, error) {
	if err := app.RequireAdmin(actor); err != nil {
		return app.DisplayConfig{}, err
	}

	if patch.CostsVisible == nil && patch.MaskUnknownErrors == nil {
		return app.DisplayConfig{}, &app.InvalidInputError{Field: "fields"}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	cfg := *s.current.Load()
	if patch.CostsVisible != nil {
		cfg.CostsVisible = *patch.CostsVisible
	}

	if patch.MaskUnknownErrors != nil {
		cfg.MaskUnknownErrors = *patch.MaskUnknownErrors
	}

	now := s.clock.Now().UTC()
	if err := s.settings.SetDisplayConfig(ctx, cfg, actor.ID, now); err != nil {
		return app.DisplayConfig{}, fmt.Errorf("app: save display config: %w", err)
	}

	stored := cfg
	s.current.Store(&stored)

	if err := s.audit.Record(ctx, app.AuditEvent{
		At: now, ActorID: actor.ID, Action: actionUpdate, Target: targetConfig,
		Detail: map[string]any{detailCostsVisible: cfg.CostsVisible, "mask_unknown_errors": cfg.MaskUnknownErrors},
	}); err != nil {
		return app.DisplayConfig{}, fmt.Errorf("app: %s on %s applied but not audited: %w", actionUpdate, targetConfig, err)
	}

	return cfg, nil
}
