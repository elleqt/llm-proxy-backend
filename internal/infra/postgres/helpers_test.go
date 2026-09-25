package postgres_test

import (
	"testing"

	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/stretchr/testify/require"
)

// Helpers shared by this package's tests, as in internal/infra/postgres's own tests.

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
