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

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/pgtest"
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

	// An installation that already priced models by hand upgrades to the price
	// catalog without losing them: they stay the manual prices, and the catalog
	// starts empty with a state row to update. Runs after the rebuild above.
	t.Run("0002 applies on a database with manual prices", func(t *testing.T) {
		dsn := pool.Config().ConnString()
		if err := postgres.MigrateDown(ctx, dsn); err != nil {
			t.Fatalf("migrate down: %v", err)
		}
		if err := postgres.MigrateTo(ctx, dsn, 1); err != nil {
			t.Fatalf("migrate to 1: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO model_prices (provider, model, input, output, cache_read, cache_write, updated_at)
			 VALUES ('claude', 'claude-sonnet-5', 3, 15, 0.3, 3.75, '2026-09-01T00:00:00Z')`); err != nil {
			t.Fatalf("insert a manual price: %v", err)
		}
		if err := postgres.Migrate(ctx, dsn); err != nil {
			t.Fatalf("migrate up: %v", err)
		}
		manual, err := postgres.NewPriceRepo(pool).List(ctx)
		if err != nil || len(manual) != 1 || manual[0].Model != "claude-sonnet-5" || manual[0].CacheWrite != 3.75 {
			t.Fatalf("manual prices after the upgrade = %+v, %v; want the row kept", manual, err)
		}
		catalog := postgres.NewPriceCatalogRepo(pool)
		if prices, err := catalog.List(ctx); err != nil || len(prices) != 0 {
			t.Fatalf("catalog prices = %+v, %v; want none", prices, err)
		}
		if state, err := catalog.State(ctx); err != nil || state != (app.CatalogState{}) {
			t.Fatalf("catalog state = %+v, %v; want a never-checked row", state, err)
		}
	})

	// The rows recorded before cost was stored are priced by 0003 at the price in
	// force (a manual price over the catalog's) with app.PriceUsage's arithmetic.
	// Runs after the rebuild above.
	t.Run("0003 backfills the cost of existing usage", func(t *testing.T) {
		dsn := pool.Config().ConnString()
		if err := postgres.MigrateDown(ctx, dsn); err != nil {
			t.Fatalf("migrate down: %v", err)
		}
		if err := postgres.MigrateTo(ctx, dsn, 2); err != nil {
			t.Fatalf("migrate to 2: %v", err)
		}
		manual := app.ModelPrice{Provider: "claude", Model: "sonnet", Input: 3, Output: 15, CacheRead: 0.3, CacheWrite: 3.75}
		catalogOnly := app.ModelPrice{Provider: "chatgpt", Model: "gpt-6", Input: 1.25, Output: 10, CacheRead: 0.125}
		if _, err := pool.Exec(ctx, `
			INSERT INTO model_prices (provider, model, input, output, cache_read, cache_write)
			VALUES ('claude', 'sonnet', 3, 15, 0.3, 3.75);
			INSERT INTO catalog_prices (provider, model, input, output, cache_read, cache_write)
			VALUES ('claude', 'sonnet', 100, 100, 100, 100), ('chatgpt', 'gpt-6', 1.25, 10, 0.125, 0)`); err != nil {
			t.Fatalf("insert prices: %v", err)
		}
		rows := []struct {
			ev    app.UsageEvent
			price app.ModelPrice
			ok    bool
		}{
			// Manual price, with 100 unclassified tokens and cache writes outweighing reads.
			{app.UsageEvent{Provider: "claude", Model: "sonnet", TokensInput: 1000, TokensOutput: 200, TokensReasoning: 100,
				TokensCacheRead: 200, TokensCacheWrite: 4000, TokensTotal: 5600}, manual, true},
			{app.UsageEvent{Provider: "chatgpt", Model: "gpt-6", TokensInput: 600, TokensOutput: 50, TokensCacheRead: 400,
				TokensTotal: 1050}, catalogOnly, true},
			// A total only: nothing classified, so nothing priced.
			{app.UsageEvent{Provider: "claude", Model: "sonnet", TokensTotal: 500}, manual, true},
			// No price at all.
			{app.UsageEvent{Provider: "claude", Model: "unknown", TokensInput: 10, TokensOutput: 5, TokensTotal: 20}, app.ModelPrice{}, false},
		}
		for i, r := range rows {
			e := r.ev
			if _, err := pool.Exec(ctx, `INSERT INTO usage_events (id, at, provider, model, tokens_input, tokens_output,
				tokens_reasoning, tokens_cache_read, tokens_cache_write, tokens_total) VALUES ($1, now(), $2, $3, $4, $5, $6, $7, $8, $9)`,
				i+1, e.Provider, e.Model, e.TokensInput, e.TokensOutput, e.TokensReasoning, e.TokensCacheRead,
				e.TokensCacheWrite, e.TokensTotal); err != nil {
				t.Fatalf("insert usage %d: %v", i, err)
			}
		}
		if err := postgres.Migrate(ctx, dsn); err != nil {
			t.Fatalf("migrate up: %v", err)
		}
		for i, r := range rows {
			var got app.UsageCost
			if err := pool.QueryRow(ctx, `SELECT cost_input_usd, cost_output_usd, cost_cache_read_usd, cost_cache_write_usd,
				cache_savings_usd, unpriced_tokens, priced FROM usage_events WHERE id = $1`, i+1).Scan(
				&got.InputUSD, &got.OutputUSD, &got.CacheReadUSD, &got.CacheWriteUSD, &got.CacheSavingsUSD,
				&got.UnpricedTokens, &got.Priced); err != nil {
				t.Fatalf("read row %d: %v", i, err)
			}
			if want := app.PriceUsage(r.ev, r.price, r.ok); got != want {
				t.Errorf("row %d (%s/%s) backfilled as %+v\nwant                %+v", i, r.ev.Provider, r.ev.Model, got, want)
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
