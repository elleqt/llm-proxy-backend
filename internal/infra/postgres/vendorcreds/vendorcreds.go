// Package vendorcreds stores the vendor accounts' sealed OAuth credentials
// (app.VendorCredentialRepo). It never sees a plaintext credential: the gateway's
// credential store seals before writing and opens after reading.
package vendorcreds

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres"
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

// COMPAT(credentials-import): the import marker and insertRow exist only for the one-shot import; remove next release (RELEASING.md).
const (
	// importMarkerKey is the settings row that records the one-shot import of the
	// credential files: once it exists the files are never read again.
	importMarkerKey = "vendor_credentials_import"

	importMarkerExists = `SELECT EXISTS (SELECT 1 FROM settings WHERE key = $1)`

	// insertImportMarker writes {"count": N} with no actor: the system imports, no
	// administrator does; the column default records when. DO NOTHING on an
	// existing marker is how Import tells a second run from the first: it affects
	// no row.
	insertImportMarker = `INSERT INTO settings (key, value, updated_by)
		VALUES ($1, jsonb_build_object('count', $2::integer), NULL)
		ON CONFLICT (key) DO NOTHING`

	// insertRow is a plain insert: the table is empty before the import, so an
	// existing id is an error and rolls the whole import back.
	insertRow = `INSERT INTO vendor_credentials (id, provider, sealed, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5)`
)

// errAlreadyImported rolls Import's transaction back when the marker is already set;
// it never leaves this package.
var errAlreadyImported = errors.New("postgres: vendor credentials already imported")

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

// ImportDone reports whether the import marker is set.
//
// COMPAT(credentials-import): ImportDone exists only for the one-shot import; remove next release (RELEASING.md).
func (r *Repo) ImportDone(ctx context.Context) (bool, error) {
	var done bool

	if err := r.pool.QueryRow(ctx, importMarkerExists, importMarkerKey).Scan(&done); err != nil {
		return false, fmt.Errorf("postgres: read vendor credentials import marker: %w", err)
	}

	return done, nil
}

// Import writes the marker first: when it already exists nothing else runs and the
// transaction is rolled back. A row whose id is already stored is app.ErrConflict and
// rolls back the marker with every row.
//
// COMPAT(credentials-import): Import exists only for the one-shot import; remove next release (RELEASING.md).
func (r *Repo) Import(ctx context.Context, rows []app.VendorCredential) (bool, error) {
	err := pgx.BeginFunc(ctx, r.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, insertImportMarker, importMarkerKey, len(rows))
		if err != nil {
			return fmt.Errorf("postgres: set vendor credentials import marker: %w", err)
		}

		if tag.RowsAffected() == 0 {
			return errAlreadyImported
		}

		batch := &pgx.Batch{}
		for _, cred := range rows {
			batch.Queue(insertRow, cred.ID, cred.Provider, cred.Sealed, cred.CreatedAt.UTC(), cred.UpdatedAt.UTC())
		}

		if err := tx.SendBatch(ctx, batch).Close(); err != nil {
			return fmt.Errorf("postgres: insert %d vendor credentials: %w", len(rows), postgres.AsConflict(err))
		}

		return nil
	})
	if errors.Is(err, errAlreadyImported) {
		return false, nil
	}

	if err != nil {
		return false, fmt.Errorf("postgres: import vendor credentials: %w", err)
	}

	return true, nil
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
