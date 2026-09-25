// Command gateway runs llm-proxy: the proxied LLM API, the web API and metrics,
// each on its own listener. With a subcommand it does one administrative job
// instead and exits. The composition lives in internal/boot.
package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/elleqt/llm-proxy-backend/internal/boot"
)

// version is set at build time: -ldflags "-X main.version=...".
var version string

const usage = `usage:
  gateway                                      serve (the default)
  gateway reset-password [--unblock] <email>   issue a temporary password

reset-password gives the local account that signs in with <email> a temporary
password, printed once, that must be changed at the next sign-in. It works for
any person's account, not only an administrator's, ends the account's sessions,
clears its sign-in lockout and keeps its API keys. It reads the same database
settings as the server (LLMPROXY_DATABASE_URL) and can run while the server runs.
A blocked account is refused; --unblock also unblocks an administrator when no
other administrator is active.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is the command with its arguments, and returns the exit status: 0 done, 1
// failed, 2 not understood.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		if err := boot.Run(context.Background(), boot.Options{Output: stderr, Version: version}); err != nil {
			_, _ = fmt.Fprintf(stderr, "gateway: %v\n", err)

			return 1
		}

		return 0
	}

	if args[0] != "reset-password" {
		_, _ = fmt.Fprint(stderr, usage)

		return 2
	}

	opts := boot.ResetPasswordOptions{Output: stdout, Warnings: stderr}

	for _, a := range args[1:] {
		switch {
		case a == "--unblock":
			opts.Unblock = true
		case opts.Email == "" && a != "" && a[0] != '-':
			opts.Email = a
		default:
			_, _ = fmt.Fprint(stderr, usage)

			return 2
		}
	}

	if opts.Email == "" {
		_, _ = fmt.Fprint(stderr, usage)

		return 2
	}

	if err := boot.ResetPassword(context.Background(), opts); err != nil {
		_, _ = fmt.Fprintf(stderr, "gateway reset-password: %v\n", err)

		return 1
	}

	return 0
}
