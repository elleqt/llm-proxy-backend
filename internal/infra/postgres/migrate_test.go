package postgres_test // external: pgtest imports postgres, so an in-package test would cycle

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/pgtest"
	pgprices "github.com/elleqt/llm-proxy-backend/internal/infra/postgres/prices"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// expectedTables is every table the migrations are required to create. Spelled out
// rather than counted so a renamed or dropped table names itself in the failure.
var expectedTables = []string{
	"api_tokens",
	"audit_events",
	"catalog_prices",
	"catalog_state",
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
			assert.True(t, tableExists(ctx, t, pool, table), "table %q was not created", table)
		}
	})

	t.Run("creates every expected index", func(t *testing.T) {
		for _, index := range expectedIndexes {
			var exists bool

			err := pool.QueryRow(ctx,
				`SELECT EXISTS (SELECT 1 FROM pg_indexes
				                WHERE schemaname = 'public' AND indexname = $1)`,
				index).Scan(&exists)
			require.NoError(t, err, "query index %q", index)
			assert.True(t, exists, "index %q was not created", index)
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
		_, err := pool.Exec(ctx,
			`INSERT INTO users (id, kind, email, role, status, policy_managed_by)
			 VALUES (gen_random_uuid(), 'human', $1, 'user', 'active', 'local')`,
			email)
		require.NoError(t, err, "insert first user")
		// Two accounts sharing an address would make login ambiguous.
		_, err = pool.Exec(ctx,
			`INSERT INTO users (id, kind, email, role, status, policy_managed_by)
			 VALUES (gen_random_uuid(), 'human', $1, 'user', 'active', 'local')`,
			email)
		requirePgError(t, err, codeUniqueViolation)
	})

	t.Run("pending_identities rejects an address differing only in case", func(t *testing.T) {
		first := insertUser(ctx, t, pool)
		second := insertUser(ctx, t, pool)

		const invite = `INSERT INTO pending_identities (user_id, issuer, expected_email, expires_at)
		                VALUES ($1, 'issuer-a', $2, now() + interval '1 hour')`

		_, err := pool.Exec(ctx, invite, first, "Invitee@Example.com")
		require.NoError(t, err, "insert first invitation")
		// PendingByEmail folds case: two such rows would make it answer with either.
		_, err = pool.Exec(ctx, invite, second, "invitee@example.com")
		requirePgError(t, err, codeUniqueViolation)
	})

	t.Run("api_tokens.hash rejects a duplicate", func(t *testing.T) {
		user := insertUser(ctx, t, pool)

		const hash = "duplicate-token-hash"

		_, err := pool.Exec(ctx,
			`INSERT INTO api_tokens (id, user_id, label, hash, prefix)
			 VALUES (gen_random_uuid(), $1, 'first', $2, 'pfx')`, user, hash)
		require.NoError(t, err, "insert first token")

		_, err = pool.Exec(ctx,
			`INSERT INTO api_tokens (id, user_id, label, hash, prefix)
			 VALUES (gen_random_uuid(), $1, 'second', $2, 'pfx')`, user, hash)
		requirePgError(t, err, codeUniqueViolation)
	})

	t.Run("user_identities rejects a duplicate issuer and subject", func(t *testing.T) {
		first := insertUser(ctx, t, pool)
		second := insertUser(ctx, t, pool)

		const issuer, subject = "issuer-a", "subject-a"

		_, err := pool.Exec(ctx,
			`INSERT INTO user_identities (user_id, issuer, subject) VALUES ($1, $2, $3)`,
			first, issuer, subject)
		require.NoError(t, err, "link first identity")
		// The same external identity must not be claimable by a second account.
		_, err = pool.Exec(ctx,
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
			assert.NoError(t, <-errs, "concurrent migrate")
		}
	})

	// gateway reset-password refuses a schema the server has not migrated: a fresh
	// database, and one a newer build would still migrate further. Rebuilds the
	// schema, so it runs after the subtests that use it.
	t.Run("Migrated tells a migrated schema from one still to migrate", func(t *testing.T) {
		dsn := pool.Config().ConnString()
		migrated := func(want bool, state string) {
			t.Helper()

			got, err := postgres.Migrated(ctx, dsn)
			require.NoError(t, err, "%s: Migrated", state)
			require.Equal(t, want, got, "%s: Migrated", state)
		}
		migrated(true, "migrated")
		require.NoError(t, postgres.MigrateDown(ctx, dsn), "MigrateDown")

		_, err := pool.Exec(ctx, `DROP TABLE goose_db_version`)
		require.NoError(t, err, "drop goose_db_version")

		migrated(false, "never migrated")
		// Asking wrote nothing: the database is as fresh as it was.
		require.False(t, tableExists(ctx, t, pool, "goose_db_version"),
			"Migrated created goose's version table in a fresh database")
		require.NoError(t, postgres.MigrateTo(ctx, dsn, 1), "MigrateTo 1")

		migrated(false, "partly migrated")
		require.NoError(t, postgres.Migrate(ctx, dsn), "Migrate")

		migrated(true, "migrated again")
	})

	// Runs last: it empties and rebuilds the schema the subtests above rely on.
	t.Run("down then up restores the schema", func(t *testing.T) {
		dsn := pool.Config().ConnString()
		require.NoError(t, postgres.MigrateDown(ctx, dsn), "migrate down")

		for _, table := range expectedTables {
			assert.False(t, tableExists(ctx, t, pool, table), "table %q survived the down migration", table)
		}

		require.NoError(t, postgres.Migrate(ctx, dsn), "migrate up again")

		for _, table := range expectedTables {
			assert.True(t, tableExists(ctx, t, pool, table), "table %q was not recreated after rollback", table)
		}
	})

	// An installation that already priced models by hand upgrades to the price
	// catalog without losing them: they stay the manual prices, and the catalog
	// starts empty with a state row to update. Runs after the rebuild above.
	t.Run("0002 applies on a database with manual prices", func(t *testing.T) {
		dsn := pool.Config().ConnString()
		require.NoError(t, postgres.MigrateDown(ctx, dsn), "migrate down")
		require.NoError(t, postgres.MigrateTo(ctx, dsn, 1), "migrate to 1")

		_, err := pool.Exec(ctx,
			`INSERT INTO model_prices (provider, model, input, output, cache_read, cache_write, updated_at)
			 VALUES ('claude', 'claude-sonnet-5', 3, 15, 0.3, 3.75, '2026-09-01T00:00:00Z')`)
		require.NoError(t, err, "insert a manual price")
		require.NoError(t, postgres.Migrate(ctx, dsn), "migrate up")

		manual, err := pgprices.New(pool).List(ctx)
		require.NoError(t, err, "manual prices after the upgrade")
		require.Len(t, manual, 1, "manual prices after the upgrade: want the row kept")
		require.Equal(t, "claude-sonnet-5", manual[0].Model, "manual price model")
		require.Equal(t, 3.75, manual[0].CacheWrite, "manual price cache write")

		catalog := pgprices.NewCatalogRepo(pool)
		prices, err := catalog.List(ctx)
		require.NoError(t, err, "catalog prices")
		require.Empty(t, prices, "catalog prices: want none")

		state, err := catalog.State(ctx)
		require.NoError(t, err, "catalog state")
		require.Zero(t, state, "catalog state: want a never-checked row")
	})

	// The rows recorded before cost was stored are priced by 0003 at the price in
	// force (a manual price over the catalog's) with app.PriceUsage's arithmetic.
	// Runs after the rebuild above.
	t.Run("0003 backfills the cost of existing usage", func(t *testing.T) {
		dsn := pool.Config().ConnString()
		require.NoError(t, postgres.MigrateDown(ctx, dsn), "migrate down")
		require.NoError(t, postgres.MigrateTo(ctx, dsn, 2), "migrate to 2")

		manual := app.ModelPrice{Provider: "claude", Model: "sonnet", Input: 3, Output: 15, CacheRead: 0.3, CacheWrite: 3.75}
		catalogOnly := app.ModelPrice{Provider: "chatgpt", Model: "gpt-6", Input: 1.25, Output: 10, CacheRead: 0.125}

		_, err := pool.Exec(ctx, `
			INSERT INTO model_prices (provider, model, input, output, cache_read, cache_write)
			VALUES ('claude', 'sonnet', 3, 15, 0.3, 3.75);
			INSERT INTO catalog_prices (provider, model, input, output, cache_read, cache_write)
			VALUES ('claude', 'sonnet', 100, 100, 100, 100), ('chatgpt', 'gpt-6', 1.25, 10, 0.125, 0)`)
		require.NoError(t, err, "insert prices")

		rows := []struct {
			ev    app.UsageEvent
			price app.ModelPrice
			ok    bool
		}{
			// Manual price, with 100 unclassified tokens and cache writes outweighing reads.
			{app.UsageEvent{
				Provider: "claude", Model: "sonnet", TokensInput: 1000, TokensOutput: 200, TokensReasoning: 100,
				TokensCacheRead: 200, TokensCacheWrite: 4000, TokensTotal: 5600,
			}, manual, true},
			// No cache-write rate: writes cost the input rate.
			{app.UsageEvent{
				Provider: "chatgpt", Model: "gpt-6", TokensInput: 600, TokensOutput: 50, TokensCacheRead: 400,
				TokensCacheWrite: 300, TokensTotal: 1350,
			}, catalogOnly, true},
			// A total only: nothing classified, so nothing priced.
			{app.UsageEvent{Provider: "claude", Model: "sonnet", TokensTotal: 500}, manual, true},
			// No price at all.
			{app.UsageEvent{Provider: "claude", Model: "unknown", TokensInput: 10, TokensOutput: 5, TokensTotal: 20}, app.ModelPrice{}, false},
			// No price, and kinds above the total: every classified token is unpriced.
			{app.UsageEvent{Provider: "claude", Model: "unknown", TokensInput: 50, TokensOutput: 30, TokensTotal: 40}, app.ModelPrice{}, false},
		}
		for idx, row := range rows {
			e := row.ev
			_, err := pool.Exec(ctx, `INSERT INTO usage_events (id, at, provider, model, tokens_input, tokens_output,
				tokens_reasoning, tokens_cache_read, tokens_cache_write, tokens_total) VALUES ($1, now(), $2, $3, $4, $5, $6, $7, $8, $9)`,
				idx+1, e.Provider, e.Model, e.TokensInput, e.TokensOutput, e.TokensReasoning, e.TokensCacheRead,
				e.TokensCacheWrite, e.TokensTotal)
			require.NoError(t, err, "insert usage %d", idx)
		}

		require.NoError(t, postgres.Migrate(ctx, dsn), "migrate up")

		for idx, row := range rows {
			var got app.UsageCost

			err := pool.QueryRow(ctx, `SELECT cost_input_usd, cost_output_usd, cost_cache_read_usd, cost_cache_write_usd,
				cache_savings_usd, unpriced_tokens, priced FROM usage_events WHERE id = $1`, idx+1).Scan(
				&got.InputUSD, &got.OutputUSD, &got.CacheReadUSD, &got.CacheWriteUSD, &got.CacheSavingsUSD,
				&got.UnpricedTokens, &got.Priced)
			require.NoError(t, err, "read row %d", idx)
			assert.Equal(t, app.PriceUsage(row.ev, row.price, row.ok), got,
				"row %d (%s/%s) backfilled", idx, row.ev.Provider, row.ev.Model)
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
	require.Error(t, err, "Migrate with a malformed DSN returned nil error")
	require.NotContains(t, err.Error(), leftover, "error leaks part of the password")
}

func tableExists(ctx context.Context, t *testing.T, pool *pgxpool.Pool, table string) bool {
	t.Helper()

	var exists bool

	err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables
		                WHERE table_schema = 'public' AND table_name = $1)`,
		table).Scan(&exists)
	require.NoError(t, err, "query table %q", table)

	return exists
}

func insertUser(ctx context.Context, t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()

	var id string

	err := pool.QueryRow(ctx,
		`INSERT INTO users (id, kind, email, role, status, policy_managed_by)
		 VALUES (gen_random_uuid(), 'human', $1, 'user', 'active', 'local')
		 RETURNING id`, uniqueEmail(t)).Scan(&id)
	require.NoError(t, err, "insert user")

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
	require.ErrorAs(t, err, &pgErr, "want a postgres error with SQLSTATE %s", code)
	require.Equal(t, code, pgErr.Code, "SQLSTATE (%s)", pgErr.Message)
}
