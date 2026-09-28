// Package display keeps what administrators let users see of the deployment
// (app.DisplayConfig): it holds the setting in memory for every request that
// reads it, and serves the administrators' view and edit of it.
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

// New returns the service showing the least (the zero app.DisplayConfig) until
// Load reads the stored settings.
func New(settings app.SettingsRepo, audit app.AuditSink, clock app.Clock) *Service {
	s := &Service{settings: settings, audit: audit, clock: clock}
	s.current.Store(&app.DisplayConfig{})

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

// Set replaces the settings: stored first, then swapped into memory, then
// audited. A failed audit reports the change as applied but not audited.
func (s *Service) Set(ctx context.Context, actor identity.User, cfg app.DisplayConfig) (app.DisplayConfig, error) {
	if err := app.RequireAdmin(actor); err != nil {
		return app.DisplayConfig{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.clock.Now().UTC()
	if err := s.settings.SetDisplayConfig(ctx, cfg, actor.ID, now); err != nil {
		return app.DisplayConfig{}, fmt.Errorf("app: save display config: %w", err)
	}

	stored := cfg
	s.current.Store(&stored)

	if err := s.audit.Record(ctx, app.AuditEvent{
		At: now, ActorID: actor.ID, Action: actionUpdate, Target: targetConfig,
		Detail: map[string]any{detailCostsVisible: cfg.CostsVisible},
	}); err != nil {
		return app.DisplayConfig{}, fmt.Errorf("app: %s on %s applied but not audited: %w", actionUpdate, targetConfig, err)
	}

	return cfg, nil
}
