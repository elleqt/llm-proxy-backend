package models_test

import (
	"testing"

	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/stretchr/testify/require"
)

// Doubles and helpers shared by this package's tests, as in internal/app's own
// tests: trivial no-op implementations; anything a test asserts against is a
// generated mock instead.

func mustPolicy(t *testing.T, rules ...string) access.Policy {
	t.Helper()

	policy := make(access.Policy, 0, len(rules))

	for _, raw := range rules {
		rule, err := access.ParseRule(raw)
		require.NoError(t, err, "ParseRule(%q)", raw)

		policy = append(policy, rule)
	}

	return policy
}
