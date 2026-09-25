// Package pgtest provides a disposable Postgres for tests.
//
// Separate package on purpose: this file links the whole testcontainers and Docker
// client stack, and anything importing it drags that into its binary. Keeping it out
// of package postgres keeps cmd/gateway free of it. Import only from _test.go files.
package pgtest

import (
	"context"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// NewTestPool starts a disposable Postgres container, applies migrations and returns
// a pool bound to it. Isolation is per-container: every call gets its own database
// server, so tests never see each other's rows and order never matters. The cost is
// roughly two seconds per call, which is why callers should not create more pools
// than they need.
func NewTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	// A stalled image pull must fail this test, not hang until the package deadline
	// and take every other test in the package down with a goroutine dump.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)

	container, err := tcpostgres.Run(ctx, "postgres:17-alpine",
		tcpostgres.WithDatabase("test"),
		tcpostgres.WithUsername("test"),
		tcpostgres.WithPassword("test"),
		// The image's entrypoint runs initdb against a temporary server that
		// listens and logs "ready" too, then restarts it: only the second
		// "ready" is the server the tests use. The port alone can answer
		// "the database system is starting up" (57P03) on a slow runner.
		testcontainers.WithWaitStrategy(wait.ForAll(
			wait.ForLog("database system is ready to accept connections").WithOccurrence(2),
			wait.ForListeningPort("5432/tcp"),
		)),
	)
	// Run can return a live container alongside an error; register cleanup before
	// the error check or a started-but-unhealthy container leaks until session end.
	testcontainers.CleanupContainer(t, container)

	require.NoError(t, err, "start postgres")

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err, "connection string")

	err = postgres.Migrate(ctx, dsn)
	require.NoError(t, err, "migrate")

	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err, "pool")

	t.Cleanup(pool.Close)

	return pool
}
