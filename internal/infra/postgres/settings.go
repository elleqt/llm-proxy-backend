package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/elleqt/llm-proxy-backend/internal/app"
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
	return doc, err
}

func (r *SettingsRepo) SetUpstreamDocument(ctx context.Context, doc string, by uuid.UUID, at time.Time) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO settings (key, value, updated_at, updated_by)
		 VALUES ($1, to_jsonb($2::text), $3, $4)
		 ON CONFLICT (key) DO UPDATE
		   SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by`,
		upstreamSettingsKey, doc, at.UTC(), nullUUID(by))
	return err
}

type PriceRepo struct{ pool *pgxpool.Pool }

var _ app.PriceRepo = (*PriceRepo)(nil)

func NewPriceRepo(pool *pgxpool.Pool) *PriceRepo { return &PriceRepo{pool: pool} }

func (r *PriceRepo) List(ctx context.Context) ([]app.ModelPrice, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT provider, model, input, output, cache_read, cache_write, updated_at
		   FROM model_prices ORDER BY provider, model`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (app.ModelPrice, error) {
		var p app.ModelPrice
		err := row.Scan(&p.Provider, &p.Model, &p.Input, &p.Output, &p.CacheRead, &p.CacheWrite, &p.UpdatedAt)
		return p, err
	})
}

// Replace upserts every price and deletes the rows not in prices, in one
// transaction. updated_at moves only for a row whose rates changed. A duplicate
// (provider, model) in prices fails the statement (ON CONFLICT cannot touch a row
// twice), so nothing is written.
func (r *PriceRepo) Replace(ctx context.Context, prices []app.ModelPrice, at time.Time) error {
	n := len(prices)
	providers, models := make([]string, n), make([]string, n)
	input, output, cacheRead, cacheWrite := make([]float64, n), make([]float64, n), make([]float64, n), make([]float64, n)
	for i, p := range prices {
		providers[i], models[i] = p.Provider, p.Model
		input[i], output[i], cacheRead[i], cacheWrite[i] = p.Input, p.Output, p.CacheRead, p.CacheWrite
	}
	return pgx.BeginFunc(ctx, r.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`DELETE FROM model_prices m
			  WHERE NOT EXISTS (SELECT 1 FROM unnest($1::text[], $2::text[]) AS k(provider, model)
			                     WHERE k.provider = m.provider AND k.model = m.model)`,
			providers, models); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO model_prices AS m (provider, model, input, output, cache_read, cache_write, updated_at)
			 SELECT provider, model, input, output, cache_read, cache_write, $7
			   FROM unnest($1::text[], $2::text[], $3::float8[], $4::float8[], $5::float8[], $6::float8[])
			     AS p(provider, model, input, output, cache_read, cache_write)
			 ON CONFLICT (provider, model) DO UPDATE
			   SET input = EXCLUDED.input, output = EXCLUDED.output,
			       cache_read = EXCLUDED.cache_read, cache_write = EXCLUDED.cache_write,
			       updated_at = CASE
			         WHEN (m.input, m.output, m.cache_read, m.cache_write)
			              IS DISTINCT FROM (EXCLUDED.input, EXCLUDED.output, EXCLUDED.cache_read, EXCLUDED.cache_write)
			         THEN EXCLUDED.updated_at ELSE m.updated_at END`,
			providers, models, input, output, cacheRead, cacheWrite, at.UTC())
		return err
	})
}
