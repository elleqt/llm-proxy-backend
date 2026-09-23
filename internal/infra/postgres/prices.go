package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/elleqt/llm-proxy-backend/internal/app"
)

// Two tables hold prices, with one shape and one replacement rule: model_prices
// (the administrator's overrides, PriceRepo) and catalog_prices (the catalog's,
// PriceCatalogRepo). The table name is always one of these constants.
const (
	manualPrices  = "model_prices"
	catalogPrices = "catalog_prices"
)

type PriceRepo struct{ pool *pgxpool.Pool }

var _ app.PriceRepo = (*PriceRepo)(nil)

func NewPriceRepo(pool *pgxpool.Pool) *PriceRepo { return &PriceRepo{pool: pool} }

func (r *PriceRepo) List(ctx context.Context) ([]app.ModelPrice, error) {
	return listPrices(ctx, r.pool, manualPrices)
}

// Replace upserts every price and deletes the rows not in prices, in one
// transaction. updated_at moves only for a row whose rates changed. A duplicate
// (provider, model) in prices fails the statement (ON CONFLICT cannot touch a row
// twice), so nothing is written.
func (r *PriceRepo) Replace(ctx context.Context, prices []app.ModelPrice, at time.Time) error {
	return pgx.BeginFunc(ctx, r.pool, func(tx pgx.Tx) error {
		return replacePrices(ctx, tx, manualPrices, prices, at)
	})
}

type PriceCatalogRepo struct{ pool *pgxpool.Pool }

var _ app.PriceCatalogRepo = (*PriceCatalogRepo)(nil)

func NewPriceCatalogRepo(pool *pgxpool.Pool) *PriceCatalogRepo { return &PriceCatalogRepo{pool: pool} }

func (r *PriceCatalogRepo) List(ctx context.Context) ([]app.ModelPrice, error) {
	return listPrices(ctx, r.pool, catalogPrices)
}

func (r *PriceCatalogRepo) State(ctx context.Context) (app.CatalogState, error) {
	var (
		s                    app.CatalogState
		checkedAt, changedAt *time.Time
		lastError            *string
	)
	err := r.pool.QueryRow(ctx,
		`SELECT etag, last_modified, fingerprint, checked_at, changed_at, last_error FROM catalog_state`).
		Scan(&s.Validators.ETag, &s.Validators.LastModified, &s.Fingerprint, &checkedAt, &changedAt, &lastError)
	if err != nil {
		return app.CatalogState{}, err
	}
	if checkedAt != nil {
		s.CheckedAt = checkedAt.UTC()
	}
	if changedAt != nil {
		s.ChangedAt = changedAt.UTC()
	}
	if lastError != nil {
		s.LastError = *lastError
	}
	return s, nil
}

// Replace replaces the catalog's prices as PriceRepo.Replace does the manual ones,
// and records state, in one transaction.
func (r *PriceCatalogRepo) Replace(ctx context.Context, prices []app.ModelPrice, state app.CatalogState, at time.Time) error {
	return pgx.BeginFunc(ctx, r.pool, func(tx pgx.Tx) error {
		if err := replacePrices(ctx, tx, catalogPrices, prices, at); err != nil {
			return err
		}
		return setCatalogState(ctx, tx, state)
	})
}

func (r *PriceCatalogRepo) SetState(ctx context.Context, state app.CatalogState) error {
	return setCatalogState(ctx, r.pool, state)
}

func setCatalogState(ctx context.Context, db execer, s app.CatalogState) error {
	_, err := db.Exec(ctx,
		`UPDATE catalog_state
		    SET etag = $1, last_modified = $2, fingerprint = $3, checked_at = $4, changed_at = $5, last_error = $6`,
		s.Validators.ETag, s.Validators.LastModified, s.Fingerprint, nullTime(s.CheckedAt), nullTime(s.ChangedAt),
		nullString(s.LastError))
	return err
}

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	t = t.UTC()
	return &t
}

func listPrices(ctx context.Context, pool *pgxpool.Pool, table string) ([]app.ModelPrice, error) {
	rows, err := pool.Query(ctx,
		`SELECT provider, model, input, output, cache_read, cache_write, updated_at
		   FROM `+table+` ORDER BY provider, model`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (app.ModelPrice, error) {
		var p app.ModelPrice
		err := row.Scan(&p.Provider, &p.Model, &p.Input, &p.Output, &p.CacheRead, &p.CacheWrite, &p.UpdatedAt)
		return p, err
	})
}

// replacePrices makes prices the whole content of table: upserts every price and
// deletes the rows not in prices. updated_at moves only for a row whose rates
// changed. The caller owns the transaction.
func replacePrices(ctx context.Context, tx pgx.Tx, table string, prices []app.ModelPrice, at time.Time) error {
	n := len(prices)
	providers, models := make([]string, n), make([]string, n)
	input, output, cacheRead, cacheWrite := make([]float64, n), make([]float64, n), make([]float64, n), make([]float64, n)
	for i, p := range prices {
		providers[i], models[i] = p.Provider, p.Model
		input[i], output[i], cacheRead[i], cacheWrite[i] = p.Input, p.Output, p.CacheRead, p.CacheWrite
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM `+table+` m
		  WHERE NOT EXISTS (SELECT 1 FROM unnest($1::text[], $2::text[]) AS k(provider, model)
		                     WHERE k.provider = m.provider AND k.model = m.model)`,
		providers, models); err != nil {
		return err
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO `+table+` AS m (provider, model, input, output, cache_read, cache_write, updated_at)
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
}
