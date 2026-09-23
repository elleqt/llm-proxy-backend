package boot

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/config"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres"
)

// ResetPasswordOptions is what `gateway reset-password` was asked for.
type ResetPasswordOptions struct {
	// Email is the account's sign-in address, in any case.
	Email string
	// Unblock also unblocks a blocked administrator when no other active
	// administrator exists (app.Recovery.ResetPassword).
	Unblock bool
	// Output receives the temporary password banner, and nothing else. The command
	// passes os.Stdout. Required.
	Output io.Writer
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
		return err
	}
	// Neither error carries the DSN (see postgres.report).
	migrated, err := postgres.Migrated(ctx, cfg.URL)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	if !migrated {
		return errors.New("the database schema is not up to date: start the server once, which migrates it, then run this again")
	}
	pool, err := postgres.NewPool(ctx, cfg.URL)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer pool.Close()

	recovery := app.NewRecovery(postgres.NewUserRepo(pool), postgres.NewPasswordRepo(pool),
		postgres.NewSessionRepo(pool), postgres.NewLoginAttemptRepo(pool),
		app.NewPasswordHasher(cfg.PasswordHashConcurrency, identity.HashPassword, identity.VerifyPassword),
		postgres.NewAuditSink(pool), systemClock{})
	out, err := recovery.ResetPassword(ctx, opts.Email, opts.Unblock)
	var blocked *app.BlockedError
	switch {
	case errors.Is(err, app.ErrNotFound):
		return fmt.Errorf("no account signs in with %s", opts.Email)
	case errors.Is(err, app.ErrNotLocal):
		return fmt.Errorf("%s is a service account, which has no password", opts.Email)
	case errors.As(err, &blocked) && blocked.CanUnblock:
		return fmt.Errorf("%s is blocked, and no other administrator is active to unblock it: "+
			"run this again with --unblock to unblock it too", opts.Email)
	case errors.As(err, &blocked):
		return fmt.Errorf("%s is blocked: an administrator must unblock it on the web interface first "+
			"(--unblock only applies to an administrator when no other administrator is active)", opts.Email)
	case err != nil:
		return err
	}
	printResetPassword(opts.Output, out)
	return nil
}

// printResetPassword shows the temporary password once, in the bootstrap banner's
// style (printBootstrapPassword).
func printResetPassword(w io.Writer, r app.Recovered) {
	unblocked := ""
	if r.Unblocked {
		unblocked = "  The account was blocked and is now unblocked.\n"
	}
	_, _ = fmt.Fprintf(w, "\n"+
		"======================= llm-proxy: password reset ========================\n"+
		"  account:            %s\n"+
		"  temporary password: %s\n"+
		"  expires:            %s\n"+
		"%s"+
		"  Shown this once. Sign in on the web interface and choose a new password.\n"+
		"===========================================================================\n\n",
		r.User.Email, r.Password.Password, r.Password.ExpiresAt.UTC().Format(time.RFC3339), unblocked)
}
