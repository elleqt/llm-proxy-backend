// Package settings stores the editable upstream configuration document and the
// global spend-limit defaults (app.SettingsRepo).
package settings

import (
	"context"
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
