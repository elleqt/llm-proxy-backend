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

type Repo struct{ pool *pgxpool.Pool }

var _ app.SpendWindowRepo = (*Repo)(nil)

func New(pool *pgxpool.Pool) *Repo { return &Repo{pool: pool} }

type windowRow struct {
	WindowMinutes int32     `db:"window_minutes"`
	StartedAt     time.Time `db:"started_at"`
	SpentUSD      float64   `db:"spent_usd"`
}

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

// openWindows inserts each window, or restarts a stored one only when it had
// expired by the new start: of two requests opening the same window at once,
// the second finds it live and leaves it.
const openWindows = `INSERT INTO limit_windows (user_id, window_minutes, started_at, spent_usd)
SELECT $1, m, $3, 0 FROM unnest($2::int[]) AS m
ON CONFLICT (user_id, window_minutes) DO UPDATE
   SET started_at = EXCLUDED.started_at, spent_usd = 0
 WHERE limit_windows.started_at + make_interval(mins => limit_windows.window_minutes) <= EXCLUDED.started_at`

const dropWindows = `DELETE FROM limit_windows WHERE user_id = $1 AND window_minutes = ANY($2::int[])`

func (r *Repo) Open(ctx context.Context, userID uuid.UUID, open, drop []time.Duration, at time.Time) error {
	batch := &pgx.Batch{}
	if len(open) > 0 {
		batch.Queue(openWindows, userID, minutes(open), at.UTC())
	}

	if len(drop) > 0 {
		batch.Queue(dropWindows, userID, minutes(drop))
	}

	if batch.Len() == 0 {
		return nil
	}
	// One batch is one implicit transaction.
	if err := r.pool.SendBatch(ctx, batch).Close(); err != nil {
		return fmt.Errorf("postgres: open spend windows: %w", err)
	}

	return nil
}

func (r *Repo) Reset(ctx context.Context, userID uuid.UUID, window *time.Duration) error {
	var length *int32
	if window != nil {
		m := int32(*window / time.Minute) //nolint:gosec // bounded by limits.MaxWindow
		length = &m
	}

	if _, err := r.pool.Exec(ctx,
		`DELETE FROM limit_windows WHERE user_id = $1 AND ($2::int IS NULL OR window_minutes = $2)`,
		userID, length); err != nil {
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
