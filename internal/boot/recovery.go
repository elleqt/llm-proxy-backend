package boot

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	apprecovery "github.com/elleqt/llm-proxy-backend/internal/app/recovery"
	"github.com/elleqt/llm-proxy-backend/internal/config"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres"
	pgaudit "github.com/elleqt/llm-proxy-backend/internal/infra/postgres/audit"
	pgloginattempts "github.com/elleqt/llm-proxy-backend/internal/infra/postgres/loginattempts"
	pgpasswords "github.com/elleqt/llm-proxy-backend/internal/infra/postgres/passwords"
	pgsessions "github.com/elleqt/llm-proxy-backend/internal/infra/postgres/sessions"
	pgusers "github.com/elleqt/llm-proxy-backend/internal/infra/postgres/users"
)

// Refusals ResetPassword explains to the operator. Each is the whole message, or
// its part after or before the email address it names.
var (
	errSchemaOutdated = errors.New("the database schema is not up to date: start the server once, which migrates it, then run this again")
	errNoAccount      = errors.New("no account signs in with")
	errServiceAccount = errors.New("is a service account, which has no password")
	errBlockedAdmin   = errors.New("is blocked, and no other administrator is active to unblock it: " +
		"run this again with --unblock to unblock it too")
	errBlocked = errors.New("is blocked: an administrator must unblock it on the web interface first " +
		"(--unblock only applies to an administrator when no other administrator is active)")
)

// ResetPasswordOptions is what `gateway reset-password` was asked for.
type ResetPasswordOptions struct {
	// Email is the account's sign-in address, in any case.
	Email string
	// Unblock also unblocks a blocked administrator when no other active
	// administrator exists (apprecovery.Service.ResetPassword).
	Unblock bool
	// Output receives the temporary password banner, and nothing else. The command
	// passes os.Stdout. Required.
	Output io.Writer
	// Warnings receives what the operator must know but is no failure: the command
	// passes os.Stderr. Required.
	Warnings io.Writer
}

// ResetPassword is `gateway reset-password`: the way back in when nobody can sign in
// to reset a password on the web interface. It reads the database settings the
// server reads (config.LoadDatabase) and touches nothing but the database — no
// listener, no gateway, no migration: a schema the server has not migrated yet is
// refused, since the server migrates as it starts. It can run beside a running
// server, which sees the change on the next request. On success the account's
// temporary password is printed once to opts.Output; an error says what to do and
// never carries a secret.
func ResetPassword(ctx context.Context, opts ResetPasswordOptions) error {
	cfg, err := config.LoadDatabase()
	if err != nil {
		return err //nolint:wrapcheck // config errors name their package, and the operator-facing text is pinned by CI
	}
	// Neither error carries the DSN (see postgres.report).
	migrated, err := postgres.Migrated(ctx, cfg.URL)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}

	if !migrated {
		return errSchemaOutdated
	}

	pool, err := postgres.NewPool(ctx, cfg.URL)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer pool.Close()

	recovery := apprecovery.New(pgusers.New(pool), pgpasswords.New(pool),
		pgsessions.New(pool), pgloginattempts.New(pool),
		app.NewPasswordHasher(cfg.PasswordHashConcurrency, identity.HashPassword, identity.VerifyPassword),
		pgaudit.New(pool), systemClock{})
	out, err := recovery.ResetPassword(ctx, opts.Email, opts.Unblock)

	var blocked *app.BlockedError
	switch {
	case errors.Is(err, app.ErrNotFound):
		return fmt.Errorf("%w %s", errNoAccount, opts.Email)
	case errors.Is(err, app.ErrNotLocal):
		return fmt.Errorf("%s %w", opts.Email, errServiceAccount)
	case errors.As(err, &blocked) && blocked.CanUnblock:
		return fmt.Errorf("%s %w", opts.Email, errBlockedAdmin)
	case errors.As(err, &blocked):
		return fmt.Errorf("%s %w", opts.Email, errBlocked)
	case err != nil:
		return fmt.Errorf("recovery: %w", err)
	}

	printResetPassword(opts.Output, out)

	if !cfg.LocalLogin {
		// As boot.Run warns for the bootstrap password.
		_, _ = fmt.Fprintln(opts.Warnings, "warning: the server takes no password sign-in (LLMPROXY_LOCAL_LOGIN is false "+
			"or LLMPROXY_WEB_ADDR is off): the temporary password cannot be used until local sign-in is enabled — "+
			"set LLMPROXY_LOCAL_LOGIN=true and restart the server")
	}

	return nil
}

// printResetPassword shows the temporary password once, in the bootstrap banner's
// style (printBootstrapPassword).
func printResetPassword(out io.Writer, recovered apprecovery.Recovered) {
	unblocked := ""
	if recovered.Unblocked {
		unblocked = "  The account was blocked and is now unblocked.\n"
	}

	_, _ = fmt.Fprintf(out, "\n"+
		"======================= llm-proxy: password reset ========================\n"+
		"  account:            %s\n"+
		"  temporary password: %s\n"+
		"  expires:            %s\n"+
		"%s"+
		"  Shown this once. Sign in on the web interface and choose a new password.\n"+
		"===========================================================================\n\n",
		recovered.User.Email, recovered.Password.Password, recovered.Password.ExpiresAt.UTC().Format(time.RFC3339), unblocked)
}
