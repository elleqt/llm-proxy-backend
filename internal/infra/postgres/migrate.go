package postgres

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/elleqt/llm-proxy-backend/internal/app"
)

//go:embed migrations/*.sql
var migrations embed.FS

// withProvider opens dsn and hands a goose provider to fn.
//
// It holds no goose package state: NewProvider takes the filesystem and dialect as
// arguments, so two concurrent callers cannot race on shared globals the way
// goose.SetBaseFS and goose.SetDialect do.
func withProvider(dsn string, fn func(*goose.Provider) error) error {
	// pgx parses the DSN lazily, inside Connect — sql.Open only fails on an
	// unregistered driver name, which the blank import rules out. So there is no
	// point guarding here; the leak, if any, surfaces from the provider below.
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("postgres: open: %w", err)
	}
	defer func() { _ = db.Close() }()

	// The provider globs migration files at the root of the fs it is given, so hand
	// it the subtree rather than the embed root.
	dir, err := fs.Sub(migrations, "migrations")
	if err != nil {
		return fmt.Errorf("postgres: migrations fs: %w", err)
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, db, dir)
	if err != nil {
		return fmt.Errorf("postgres: provider: %w", err)
	}
	return fn(provider)
}

// report is this package's single rule for turning a failure into something safe to
// log. Every exported function here routes through it.
//
// A malformed DSN reaches us as *pgconn.ParseConfigError, whose own redaction is
// documented best-effort and cannot guarantee the password is masked when the string
// is too ambiguous to parse, so that one is replaced wholesale. Everything else —
// goose, SQL, a failed dial — carries SQLSTATE, the failing statement or the
// user/database pair and no password, which is exactly what an operator needs.
func report(op string, err error) error {
	var parseErr *pgconn.ParseConfigError
	if errors.As(err, &parseErr) {
		return errors.New("postgres: " + op + ": invalid connection string")
	}
	return fmt.Errorf("postgres: %s: %w", op, err)
}

// uniqueViolation is SQLSTATE 23505.
const uniqueViolation = "23505"

// asConflict maps a unique-constraint violation onto app.ErrConflict, the same way
// pgx.ErrNoRows is mapped onto app.ErrNotFound: the application layer must be able to
// tell "that row already exists" from "the database is unreachable" without importing
// a driver package. Everything else is returned unchanged.
//
// The original error is wrapped, not discarded, so the constraint name survives for
// the operator while errors.Is still answers the caller's question.
func asConflict(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
		return fmt.Errorf("%w: %s", app.ErrConflict, pgErr.ConstraintName)
	}
	return err
}

// Migrate applies every pending migration to the database at dsn.
func Migrate(ctx context.Context, dsn string) error {
	return withProvider(dsn, func(p *goose.Provider) error {
		if _, err := p.Up(ctx); err != nil {
			return report("migrate", err)
		}
		return nil
	})
}

// migrateDown rolls every applied migration back, dropping every table and the data
// in it. Unexported on purpose — nothing in production may reach it; the test binary
// gets at it through export_test.go.
func migrateDown(ctx context.Context, dsn string) error {
	return withProvider(dsn, func(p *goose.Provider) error {
		if _, err := p.DownTo(ctx, 0); err != nil {
			return report("migrate down", err)
		}
		return nil
	})
}
