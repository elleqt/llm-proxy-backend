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

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres"
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
		testcontainers.WithWaitStrategy(wait.ForListeningPort("5432/tcp")),
	)
	// Run can return a live container alongside an error; register cleanup before
	// the error check or a started-but-unhealthy container leaks until session end.
	testcontainers.CleanupContainer(t, container)
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}
	if err := postgres.Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}
