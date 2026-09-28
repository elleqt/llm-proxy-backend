// Package limitwindows stores the spend-limit windows accounts have opened.
package limitwindows

import (
	"context"
	"fmt"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/limits"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Repo stores the spend-limit windows accounts have opened. The usage ledger
// charges the same rows (usage.Repo.AppendBatch), so both lock them in one order.
type Repo struct{ pool *pgxpool.Pool }

var _ app.SpendWindowRepo = (*Repo)(nil)

// New returns the window store on pool.
func New(pool *pgxpool.Pool) *Repo { return &Repo{pool: pool} }

type windowRow struct {
	WindowMinutes int32     `db:"window_minutes"`
	StartedAt     time.Time `db:"started_at"`
	SpentUSD      float64   `db:"spent_usd"`
}

// Windows returns every stored window of userID, expired ones included: the
// caller decides which are live.
func (r *Repo) Windows(ctx context.Context, userID uuid.UUID) ([]limits.Window, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT window_minutes, started_at, spent_usd FROM limit_windows WHERE user_id = $1`, userID)
	if err != nil {
		return nil, fmt.Errorf("postgres: read spend windows: %w", err)
	}

	stored, err := pgx.CollectRows(rows, pgx.RowToStructByName[windowRow])
	if err != nil {
		return nil, fmt.Errorf("postgres: read spend windows: %w", err)
	}

	out := make([]limits.Window, 0, len(stored))
	for _, w := range stored {
		out = append(out, limits.Window{
			Length: time.Duration(w.WindowMinutes) * time.Minute, StartedAt: w.StartedAt, SpentUSD: w.SpentUSD,
		})
	}

	return out, nil
}

// lockWindows locks userID's window rows by window_minutes before a statement
// changes them. An upsert or delete locks rows in whatever order its plan visits
// them; the usage ledger's charge, running at the same time, locks the same rows
// by (user_id, window_minutes). Taking them first in that fixed order makes the
// two queue instead of deadlocking, which would lose the ledger's whole batch.
const lockWindows = `SELECT 1 FROM limit_windows WHERE user_id = $1 ORDER BY window_minutes FOR UPDATE`

// openWindows inserts each window, or restarts a stored one only when it had
// expired by the new start: of two requests opening the same window at once,
// the second finds it live and leaves it.
const openWindows = `INSERT INTO limit_windows (user_id, window_minutes, started_at, spent_usd)
SELECT $1, m, $3, 0 FROM unnest($2::int[]) AS m ORDER BY m
ON CONFLICT (user_id, window_minutes) DO UPDATE
   SET started_at = EXCLUDED.started_at, spent_usd = 0
 WHERE limit_windows.started_at + make_interval(mins => limit_windows.window_minutes) <= EXCLUDED.started_at`

const dropWindows = `DELETE FROM limit_windows WHERE user_id = $1 AND window_minutes = ANY($2::int[])`

const resetWindows = `DELETE FROM limit_windows WHERE user_id = $1 AND ($2::int IS NULL OR window_minutes = $2)`

// Open starts at at, with nothing spent, each window in open that userID has no
// row for or whose row had expired by at, and deletes the windows in drop, all
// in one transaction.
func (r *Repo) Open(ctx context.Context, userID uuid.UUID, open, drop []time.Duration, at time.Time) error {
	if len(open) == 0 && len(drop) == 0 {
		return nil
	}

	batch := &pgx.Batch{}
	batch.Queue(lockWindows, userID)

	if len(open) > 0 {
		batch.Queue(openWindows, userID, minutes(open), at.UTC())
	}

	if len(drop) > 0 {
		batch.Queue(dropWindows, userID, minutes(drop))
	}
	// One batch is one implicit transaction: the locks hold until it ends.
	if err := r.pool.SendBatch(ctx, batch).Close(); err != nil {
		return fmt.Errorf("postgres: open spend windows: %w", err)
	}

	return nil
}

// Reset deletes userID's window of that length, or every window of userID when
// window is nil. A window that is not stored is no error.
func (r *Repo) Reset(ctx context.Context, userID uuid.UUID, window *time.Duration) error {
	var length *int32
	if window != nil {
		m := int32(*window / time.Minute) //nolint:gosec // bounded by limits.MaxWindow
		length = &m
	}

	batch := &pgx.Batch{}
	batch.Queue(lockWindows, userID)
	batch.Queue(resetWindows, userID, length)

	if err := r.pool.SendBatch(ctx, batch).Close(); err != nil {
		return fmt.Errorf("postgres: reset spend windows: %w", err)
	}

	return nil
}

func minutes(ds []time.Duration) []int32 {
	out := make([]int32, len(ds))
	for i, d := range ds {
		out[i] = int32(d / time.Minute) //nolint:gosec // bounded by limits.MaxWindow
	}

	return out
}
