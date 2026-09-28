// Package settings stores the editable upstream configuration document, the
// global spend-limit defaults and what users are shown (app.SettingsRepo).
package settings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/limits"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// upstreamSettingsKey is the settings row holding the editable upstream document.
// The value is a JSON string: the YAML text verbatim, comments and all.
const upstreamSettingsKey = "upstream"

// spendLimitsKey is the settings row holding the global spend-limit defaults, as
// postgres.EncodeLimits writes them.
const spendLimitsKey = "spend_limits"

// displayKey is the settings row holding app.DisplayConfig as displayRow.
const displayKey = "display"

// displayRow is the stored form of app.DisplayConfig; a field missing from a
// row saved by an older build reads as its zero value, which shows the least.
type displayRow struct {
	CostsVisible bool `json:"costs_visible"`
}

type Repo struct{ pool *pgxpool.Pool }

var _ app.SettingsRepo = (*Repo)(nil)

func New(pool *pgxpool.Pool) *Repo { return &Repo{pool: pool} }

func (r *Repo) UpstreamDocument(ctx context.Context) (string, error) {
	var doc string

	err := r.pool.QueryRow(ctx,
		`SELECT value #>> '{}' FROM settings WHERE key = $1`, upstreamSettingsKey).Scan(&doc)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", app.ErrNotFound
	}

	if err != nil {
		return "", fmt.Errorf("postgres: upstream document: %w", err)
	}

	return doc, nil
}

func (r *Repo) SetUpstreamDocument(ctx context.Context, doc string, by uuid.UUID, at time.Time) error {
	if _, err := r.pool.Exec(ctx,
		`INSERT INTO settings (key, value, updated_at, updated_by)
		 VALUES ($1, to_jsonb($2::text), $3, $4)
		 ON CONFLICT (key) DO UPDATE
		   SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by`,
		upstreamSettingsKey, doc, at.UTC(), postgres.NullUUID(by)); err != nil {
		return fmt.Errorf("postgres: set upstream document: %w", err)
	}

	return nil
}

// SpendLimitDefaults reads a missing row as the empty set: until an administrator
// saves defaults there are none, and that is not an error.
func (r *Repo) SpendLimitDefaults(ctx context.Context) (limits.Set, error) {
	var raw []byte

	err := r.pool.QueryRow(ctx, `SELECT value FROM settings WHERE key = $1`, spendLimitsKey).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return limits.Set{}, nil
	}

	if err != nil {
		return nil, fmt.Errorf("postgres: read spend limit defaults: %w", err)
	}

	return postgres.DecodeLimits(raw)
}

func (r *Repo) SetSpendLimitDefaults(ctx context.Context, set limits.Set, by uuid.UUID, at time.Time) error {
	raw, err := postgres.EncodeLimits(set)
	if err != nil {
		return err
	}

	if _, err := r.pool.Exec(ctx,
		`INSERT INTO settings (key, value, updated_at, updated_by)
		 VALUES ($1, $2::jsonb, $3, $4)
		 ON CONFLICT (key) DO UPDATE
		   SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by`,
		spendLimitsKey, raw, at.UTC(), postgres.NullUUID(by)); err != nil {
		return fmt.Errorf("postgres: save spend limit defaults: %w", err)
	}

	return nil
}

// DisplayConfig reads a missing row as the zero value: until an administrator
// saves it, users are shown nothing extra.
func (r *Repo) DisplayConfig(ctx context.Context) (app.DisplayConfig, error) {
	var raw []byte

	err := r.pool.QueryRow(ctx, `SELECT value FROM settings WHERE key = $1`, displayKey).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.DisplayConfig{}, nil
	}

	if err != nil {
		return app.DisplayConfig{}, fmt.Errorf("postgres: read display config: %w", err)
	}

	var row displayRow
	if err := json.Unmarshal(raw, &row); err != nil {
		return app.DisplayConfig{}, fmt.Errorf("postgres: decode display config: %w", err)
	}

	return app.DisplayConfig(row), nil
}

func (r *Repo) SetDisplayConfig(ctx context.Context, cfg app.DisplayConfig, by uuid.UUID, at time.Time) error {
	raw, err := json.Marshal(displayRow(cfg))
	if err != nil {
		return fmt.Errorf("postgres: encode display config: %w", err)
	}

	if _, err := r.pool.Exec(ctx,
		`INSERT INTO settings (key, value, updated_at, updated_by)
		 VALUES ($1, $2::jsonb, $3, $4)
		 ON CONFLICT (key) DO UPDATE
		   SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by`,
		displayKey, raw, at.UTC(), postgres.NullUUID(by)); err != nil {
		return fmt.Errorf("postgres: save display config: %w", err)
	}

	return nil
}
