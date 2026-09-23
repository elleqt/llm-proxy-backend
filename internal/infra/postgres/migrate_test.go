package postgres_test // external: pgtest imports postgres, so an in-package test would cycle

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/pgtest"
)

// expectedTables is every table 0001_init.sql is required to create. Spelled out
// rather than counted so a renamed or dropped table names itself in the failure.
var expectedTables = []string{
	"api_tokens",
	"audit_events",
	"login_attempts",
	"model_prices",
	"pending_identities",
	"sessions",
	"settings",
	"user_identities",
	"user_passwords",
	"users",
	"usage_events",
}

// expectedIndexes are the lookup paths the read-heavy queries depend on. Losing one
// is invisible until a table is large enough for the sequential scan to hurt.
var expectedIndexes = []string{
	"audit_events_actor_at_idx",
	"audit_events_owner_at_idx",
	"audit_events_target_at_idx",
	"pending_identities_issuer_email_lower_key",
	"usage_events_at_idx",
	"usage_events_user_at_idx",
}

const (
	codeCheckViolation  = "23514"
	codeUniqueViolation = "23505"
)

// TestMigrations exercises the whole schema against a single container: starting one
// costs roughly two seconds, so every assertion shares this pool.
func TestMigrations(t *testing.T) {
	pool := pgtest.NewTestPool(t)
	ctx := context.Background()

	t.Run("creates every expected table", func(t *testing.T) {
		for _, table := range expectedTables {
			if !tableExists(t, ctx, pool, table) {
				t.Errorf("table %q was not created", table)
			}
		}
	})

	t.Run("creates every expected index", func(t *testing.T) {
		for _, index := range expectedIndexes {
			var exists bool
			err := pool.QueryRow(ctx,
				`SELECT EXISTS (SELECT 1 FROM pg_indexes
				                WHERE schemaname = 'public' AND indexname = $1)`,
				index).Scan(&exists)
			if err != nil {
				t.Fatalf("query index %q: %v", index, err)
			}
			if !exists {
				t.Errorf("index %q was not created", index)
			}
		}
	})

	t.Run("users.kind rejects an unlisted value", func(t *testing.T) {
		_, err := pool.Exec(ctx,
			`INSERT INTO users (id, kind, email, role, status, policy_managed_by)
			 VALUES (gen_random_uuid(), 'robot', $1, 'user', 'active', 'local')`,
			uniqueEmail(t))
		requirePgError(t, err, codeCheckViolation)
	})

	t.Run("users.policy_managed_by rejects an unlisted value", func(t *testing.T) {
		_, err := pool.Exec(ctx,
			`INSERT INTO users (id, kind, email, role, status, policy_managed_by)
			 VALUES (gen_random_uuid(), 'human', $1, 'user', 'active', 'ldap')`,
			uniqueEmail(t))
		requirePgError(t, err, codeCheckViolation)
	})

	t.Run("users.role rejects an unlisted value", func(t *testing.T) {
		_, err := pool.Exec(ctx,
			`INSERT INTO users (id, kind, email, role, status, policy_managed_by)
			 VALUES (gen_random_uuid(), 'human', $1, 'superuser', 'active', 'local')`,
			uniqueEmail(t))
		requirePgError(t, err, codeCheckViolation)
	})

	t.Run("users.status rejects an unlisted value", func(t *testing.T) {
		_, err := pool.Exec(ctx,
			`INSERT INTO users (id, kind, email, role, status, policy_managed_by)
			 VALUES (gen_random_uuid(), 'human', $1, 'user', 'suspended', 'local')`,
			uniqueEmail(t))
		requirePgError(t, err, codeCheckViolation)
	})

	t.Run("users.email rejects a duplicate", func(t *testing.T) {
		email := uniqueEmail(t)
		if _, err := pool.Exec(ctx,
			`INSERT INTO users (id, kind, email, role, status, policy_managed_by)
			 VALUES (gen_random_uuid(), 'human', $1, 'user', 'active', 'local')`,
			email); err != nil {
			t.Fatalf("insert first user: %v", err)
		}
		// Two accounts sharing an address would make login ambiguous.
		_, err := pool.Exec(ctx,
			`INSERT INTO users (id, kind, email, role, status, policy_managed_by)
			 VALUES (gen_random_uuid(), 'human', $1, 'user', 'active', 'local')`,
			email)
		requirePgError(t, err, codeUniqueViolation)
	})

	t.Run("pending_identities rejects an address differing only in case", func(t *testing.T) {
		first := insertUser(t, ctx, pool)
		second := insertUser(t, ctx, pool)
		const invite = `INSERT INTO pending_identities (user_id, issuer, expected_email, expires_at)
		                VALUES ($1, 'issuer-a', $2, now() + interval '1 hour')`
		if _, err := pool.Exec(ctx, invite, first, "Invitee@Example.com"); err != nil {
			t.Fatalf("insert first invitation: %v", err)
		}
		// PendingByEmail folds case: two such rows would make it answer with either.
		_, err := pool.Exec(ctx, invite, second, "invitee@example.com")
		requirePgError(t, err, codeUniqueViolation)
	})

	t.Run("api_tokens.hash rejects a duplicate", func(t *testing.T) {
		user := insertUser(t, ctx, pool)
		const hash = "duplicate-token-hash"
		if _, err := pool.Exec(ctx,
			`INSERT INTO api_tokens (id, user_id, label, hash, prefix)
			 VALUES (gen_random_uuid(), $1, 'first', $2, 'pfx')`, user, hash); err != nil {
			t.Fatalf("insert first token: %v", err)
		}
		_, err := pool.Exec(ctx,
			`INSERT INTO api_tokens (id, user_id, label, hash, prefix)
			 VALUES (gen_random_uuid(), $1, 'second', $2, 'pfx')`, user, hash)
		requirePgError(t, err, codeUniqueViolation)
	})

	t.Run("user_identities rejects a duplicate issuer and subject", func(t *testing.T) {
		first := insertUser(t, ctx, pool)
		second := insertUser(t, ctx, pool)
		const issuer, subject = "issuer-a", "subject-a"
		if _, err := pool.Exec(ctx,
			`INSERT INTO user_identities (user_id, issuer, subject) VALUES ($1, $2, $3)`,
			first, issuer, subject); err != nil {
			t.Fatalf("link first identity: %v", err)
		}
		// The same external identity must not be claimable by a second account.
		_, err := pool.Exec(ctx,
			`INSERT INTO user_identities (user_id, issuer, subject) VALUES ($1, $2, $3)`,
			second, issuer, subject)
		requirePgError(t, err, codeUniqueViolation)
	})

	// Migrate must own its goose configuration rather than write package globals,
	// otherwise two callers racing on startup trip the race detector.
	t.Run("concurrent migrate calls do not race", func(t *testing.T) {
		dsn := pool.Config().ConnString()
		errs := make(chan error, 2)
		for range 2 {
			go func() { errs <- postgres.Migrate(ctx, dsn) }()
		}
		for range 2 {
			if err := <-errs; err != nil {
				t.Errorf("concurrent migrate: %v", err)
			}
		}
	})

	// Runs last: it empties and rebuilds the schema the subtests above rely on.
	t.Run("down then up restores the schema", func(t *testing.T) {
		dsn := pool.Config().ConnString()
		if err := postgres.MigrateDown(ctx, dsn); err != nil {
			t.Fatalf("migrate down: %v", err)
		}
		for _, table := range expectedTables {
			if tableExists(t, ctx, pool, table) {
				t.Errorf("table %q survived the down migration", table)
			}
		}
		if err := postgres.Migrate(ctx, dsn); err != nil {
			t.Fatalf("migrate up again: %v", err)
		}
		for _, table := range expectedTables {
			if !tableExists(t, ctx, pool, table) {
				t.Errorf("table %q was not recreated after rollback", table)
			}
		}
	})
}

// TestMigrateDoesNotLeakPasswordFromMalformedDSN pins the one migration failure that
// carries the connection string. pgx parses lazily, so a malformed DSN surfaces from
// inside provider.Up as *pgconn.ParseConfigError, whose Error() interpolates the DSN
// with redaction its own documentation calls best effort — an unquoted password
// containing a space defeats it, leaking the tail. Migrate must replace that error
// rather than wrap it, or the leftover lands in the startup log.
//
// Hermetic on purpose: parsing fails before any connection, so this needs no container.
func TestMigrateDoesNotLeakPasswordFromMalformedDSN(t *testing.T) {
	const (
		dsn      = "host=h port=notaport user=u password=hun ter2 dbname=d"
		leftover = "ter2"
	)
	err := postgres.Migrate(context.Background(), dsn)
	if err == nil {
		t.Fatal("Migrate with a malformed DSN returned nil error")
	}
	if strings.Contains(err.Error(), leftover) {
		t.Fatalf("error leaks part of the password: %v", err)
	}
}

func tableExists(t *testing.T, ctx context.Context, pool *pgxpool.Pool, table string) bool {
	t.Helper()
	var exists bool
	err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables
		                WHERE table_schema = 'public' AND table_name = $1)`,
		table).Scan(&exists)
	if err != nil {
		t.Fatalf("query table %q: %v", table, err)
	}
	return exists
}

func insertUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool) string {
	t.Helper()
	var id string
	err := pool.QueryRow(ctx,
		`INSERT INTO users (id, kind, email, role, status, policy_managed_by)
		 VALUES (gen_random_uuid(), 'human', $1, 'user', 'active', 'local')
		 RETURNING id`, uniqueEmail(t)).Scan(&id)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	return id
}

var emailSeq atomic.Int64

// uniqueEmail keeps inserts from colliding on the users.email unique constraint.
func uniqueEmail(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("user-%d@example.test", emailSeq.Add(1))
}

func requirePgError(t *testing.T, err error, code string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Fatalf("got error %v, want a postgres error with SQLSTATE %s", err, code)
	}
	if pgErr.Code != code {
		t.Fatalf("got SQLSTATE %s (%s), want %s", pgErr.Code, pgErr.Message, code)
	}
}
