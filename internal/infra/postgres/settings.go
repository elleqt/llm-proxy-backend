package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// upstreamSettingsKey is the settings row holding the editable upstream document.
// The value is a JSON string: the YAML text verbatim, comments and all.
const upstreamSettingsKey = "upstream"

type SettingsRepo struct{ pool *pgxpool.Pool }

var _ app.SettingsRepo = (*SettingsRepo)(nil)

func NewSettingsRepo(pool *pgxpool.Pool) *SettingsRepo { return &SettingsRepo{pool: pool} }

func (r *SettingsRepo) UpstreamDocument(ctx context.Context) (string, error) {
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

func (r *SettingsRepo) SetUpstreamDocument(ctx context.Context, doc string, by uuid.UUID, at time.Time) error {
	if _, err := r.pool.Exec(ctx,
		`INSERT INTO settings (key, value, updated_at, updated_by)
		 VALUES ($1, to_jsonb($2::text), $3, $4)
		 ON CONFLICT (key) DO UPDATE
		   SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by`,
		upstreamSettingsKey, doc, at.UTC(), nullUUID(by)); err != nil {
		return fmt.Errorf("postgres: set upstream document: %w", err)
	}

	return nil
}
