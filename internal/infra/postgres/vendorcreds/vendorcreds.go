// Package vendorcreds stores the vendor accounts' sealed OAuth credentials
// (app.VendorCredentialRepo). It never sees a plaintext credential: the gateway's
// credential store seals before writing and opens after reading.
package vendorcreds

import (
	"context"
	"fmt"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// listRows orders by id so a listing is stable from one call to the next.
	listRows = `SELECT id, provider, sealed, created_at, updated_at FROM vendor_credentials ORDER BY id`

	// upsertRow keeps created_at on overwrite: the conflict branch never sets it, so
	// a re-login of an account leaves the age of its first sign-in.
	upsertRow = `INSERT INTO vendor_credentials (id, provider, sealed, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (id) DO UPDATE
		  SET provider = EXCLUDED.provider, sealed = EXCLUDED.sealed, updated_at = EXCLUDED.updated_at`

	// updateRow writes only a row that exists; created_at is never touched.
	updateRow = `UPDATE vendor_credentials SET provider = $2, sealed = $3, updated_at = $4 WHERE id = $1`

	deleteRow = `DELETE FROM vendor_credentials WHERE id = $1`
)

type Repo struct{ pool *pgxpool.Pool }

var _ app.VendorCredentialRepo = (*Repo)(nil)

func New(pool *pgxpool.Pool) *Repo { return &Repo{pool: pool} }

func (r *Repo) List(ctx context.Context) ([]app.VendorCredential, error) {
	rows, err := r.pool.Query(ctx, listRows)
	if err != nil {
		return nil, fmt.Errorf("postgres: list vendor credentials: %w", err)
	}

	scanned, err := pgx.CollectRows(rows, pgx.RowToStructByName[credentialRow])
	if err != nil {
		return nil, fmt.Errorf("postgres: list vendor credentials: %w", err)
	}

	out := make([]app.VendorCredential, len(scanned))
	for i, row := range scanned {
		out[i] = row.credential()
	}

	return out, nil
}

func (r *Repo) Upsert(ctx context.Context, cred app.VendorCredential) error {
	if _, err := r.pool.Exec(ctx, upsertRow,
		cred.ID, cred.Provider, cred.Sealed, cred.CreatedAt.UTC(), cred.UpdatedAt.UTC()); err != nil {
		return fmt.Errorf("postgres: upsert vendor credential: %w", err)
	}

	return nil
}

func (r *Repo) Update(ctx context.Context, cred app.VendorCredential) error {
	tag, err := r.pool.Exec(ctx, updateRow, cred.ID, cred.Provider, cred.Sealed, cred.UpdatedAt.UTC())
	if err != nil {
		return fmt.Errorf("postgres: update vendor credential: %w", err)
	}

	if tag.RowsAffected() == 0 {
		return app.ErrNotFound
	}

	return nil
}

func (r *Repo) Delete(ctx context.Context, id string) error {
	if _, err := r.pool.Exec(ctx, deleteRow, id); err != nil {
		return fmt.Errorf("postgres: delete vendor credential: %w", err)
	}

	return nil
}

// credentialRow is one vendor_credentials row, scanned by column name.
type credentialRow struct {
	ID        string    `db:"id"`
	Provider  string    `db:"provider"`
	Sealed    []byte    `db:"sealed"`
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

// credential returns the row with UTC timestamps: pgx decodes timestamptz in the
// process's local zone, and callers compare times written through app.Clock.
func (row credentialRow) credential() app.VendorCredential {
	return app.VendorCredential{
		ID:        row.ID,
		Provider:  row.Provider,
		Sealed:    row.Sealed,
		CreatedAt: row.CreatedAt.UTC(),
		UpdatedAt: row.UpdatedAt.UTC(),
	}
}
