package postgres_test

import (
	"context"
	"testing"

	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres"
	"github.com/stretchr/testify/require"
)

// TestNewPoolDoesNotLeakPasswordFromMalformedDSN is the NewPool half of the same
// hazard TestMigrateDoesNotLeakPasswordFromMalformedDSN pins. pgxpool.New parses the
// DSN eagerly, so a malformed one fails right there as *pgconn.ParseConfigError,
// whose best-effort redaction leaves the tail of an unquoted password containing a
// space. NewPool is production code, so that tail would reach a startup log.
//
// Hermetic on purpose: parsing fails before any dial, so this needs no container.
func TestNewPoolDoesNotLeakPasswordFromMalformedDSN(t *testing.T) {
	const (
		dsn      = "host=h port=notaport user=u password=hun ter2 dbname=d"
		leftover = "ter2"
	)

	pool, err := postgres.NewPool(context.Background(), dsn)
	if err == nil {
		pool.Close()
	}

	require.Error(t, err, "NewPool with a malformed DSN returned nil error")
	require.NotContains(t, err.Error(), leftover, "error leaks part of the password")
}
