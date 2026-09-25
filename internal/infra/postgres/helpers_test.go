// Package postgres_test exercises the repositories against a real Postgres: the
// tests here cover several repositories at once, each repository's own tests
// live beside it.
//
// External test package on purpose: the container harness lives in pgtest, which
// imports postgres, so an internal test file here would be an import cycle.
package postgres_test

import (
	"testing"

	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/stretchr/testify/require"
)

func mustPolicy(t *testing.T, rules ...string) access.Policy {
	t.Helper()

	policy := make(access.Policy, 0, len(rules))
	for _, raw := range rules {
		r, err := access.ParseRule(raw)
		require.NoError(t, err, "ParseRule(%q)", raw)

		policy = append(policy, r)
	}

	return policy
}
