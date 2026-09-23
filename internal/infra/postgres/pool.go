package postgres

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// NewPool dials the database at dsn and returns a pool that has answered a ping.
func NewPool(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	// Unlike sql.Open, pgxpool.New parses the DSN eagerly, so a malformed connection
	// string surfaces here as *pgconn.ParseConfigError — the one error in this package
	// that can carry a password. Same hazard as Migrate, same classification.
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, report("pool", err)
	}
	if err := pool.Ping(ctx); err != nil {
		// pgxpool.New always yields a live pool with a background goroutine and
		// possibly an open connection; returning without Close leaks both.
		pool.Close()
		// The DSN is already parsed by this point, so a dial failure arrives as
		// *pgconn.ConnectError, whose text is "failed to connect to `user=%s
		// database=%s`" plus the cause — no password. Routed through report anyway so
		// there is one classification in this package rather than two.
		return nil, report("ping", err)
	}
	return pool, nil
}
