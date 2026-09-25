package access

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPolicyAllows(t *testing.T) {
	cases := []struct {
		name     string
		rules    []string
		provider string
		model    string
		want     bool
	}{
		{"provider wildcard covers any model", []string{"chatgpt:*"}, "chatgpt", "gpt-5.6", true},
		{"provider wildcard does not cross providers", []string{"chatgpt:*"}, "claude", "claude-sonnet-5", false},
		{
			"wildcard covers a model that did not exist at grant time",
			[]string{"chatgpt:*"},
			"chatgpt", "gpt-9-released-tomorrow", true,
		},
		{"exact model only", []string{"claude:claude-sonnet-5"}, "claude", "claude-opus-5", false},
		{"exact model matches", []string{"claude:claude-sonnet-5"}, "claude", "claude-sonnet-5", true},
		{"prefix glob", []string{"claude:claude-sonnet-*"}, "claude", "claude-sonnet-5-20260101", true},
		{"mixed rules", []string{"chatgpt:*", "claude:claude-sonnet-5"}, "claude", "claude-sonnet-5", true},
		{"mixed rules reject uncovered", []string{"chatgpt:*", "claude:claude-sonnet-5"}, "claude", "claude-opus-5", false},
		{"everything", []string{"*:*"}, "anything", "any-model", true},
		{"empty policy allows nothing", nil, "chatgpt", "gpt-5.6", false},
		{"provider match is case-insensitive", []string{"ChatGPT:*"}, "chatgpt", "gpt-5.6", true},
		// Model identifiers carrying the separators that broke the first grammar.
		{"colon inside the model id", []string{"ollama:llama3:70b"}, "ollama", "llama3:70b", true},
		{"colon id is not over-granted", []string{"ollama:llama3:70b"}, "ollama", "llama3:8b", false},
		{
			"glob over a colon-versioned id",
			[]string{"bedrock:anthropic.claude-3-opus-*"},
			"bedrock", "anthropic.claude-3-opus-20240229-v1:0", true,
		},
		{"slash inside the model id", []string{"openrouter:openai/gpt-4o"}, "openrouter", "openai/gpt-4o", true},
		{
			"glob crosses a slash",
			[]string{"openrouter:*claude*"},
			"openrouter", "anthropic/claude-sonnet-4.6", true,
		},
		{"leading star is not dropped", []string{"openrouter:*gpt-4o"}, "openrouter", "openai/gpt-4o", true},
		{
			"question mark matches exactly one character",
			[]string{"claude:claude-sonnet-?"},
			"claude", "claude-sonnet-5", true,
		},
		{
			"question mark does not match two",
			[]string{"claude:claude-sonnet-?"},
			"claude", "claude-sonnet-55", false,
		},
		{
			"pattern is anchored at both ends",
			[]string{"claude:sonnet"},
			"claude", "claude-sonnet-5", false,
		},
		{
			"metacharacters are literal, not regexp",
			[]string{"claude:claude.sonnet"},
			"claude", "claudexsonnet", false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var policy Policy

			for _, raw := range tc.rules {
				r, err := ParseRule(raw)
				require.NoError(t, err, "ParseRule(%q)", raw)

				policy = append(policy, r)
			}

			require.Equal(t, tc.want, policy.Allows(tc.provider, tc.model), "Allows(%q, %q)", tc.provider, tc.model)
		})
	}
}

func TestParseRuleRejectsMalformed(t *testing.T) {
	// "a:b:c" is deliberately absent: splitting on the first colon only makes it a
	// valid rule for provider "a", pattern "b:c" — which is what a versioned or
	// tagged model identifier needs.
	for _, raw := range []string{"", "chatgpt", ":model", "chatgpt:", "   ", ":"} {
		_, err := ParseRule(raw)
		require.Error(t, err, "ParseRule(%q)", raw)
	}
}

// String is what an operator sees in the admin UI and in an audit entry, so it
// must render the normalised rule, not the raw input.
func TestRuleStringRendersNormalisedRule(t *testing.T) {
	r, err := ParseRule(" ChatGPT : Claude-Sonnet-* ")
	require.NoError(t, err, "ParseRule")
	require.Equal(t, "chatgpt:claude-sonnet-*", r.String(), "String()")
}

// A Rule built by hand rather than by ParseRule has no compiled pattern; matches
// must compile on demand instead of refusing everything.
func TestHandBuiltRuleMatchesWithoutPrecompiledPattern(t *testing.T) {
	p := Policy{{Provider: "openrouter", ModelPattern: "*claude*"}}
	require.True(t, p.Allows("openrouter", "anthropic/claude-sonnet-4.6"),
		"hand-built rule must match; compiled pattern should be built on demand")
	require.False(t, p.Allows("openrouter", "openai/gpt-4o"), "hand-built rule must not over-grant")
}

// A model is covered only on every provider serving it, and a model nobody serves is
// not covered at all: both halves fail closed.
func TestCoversRequiresEveryServingProvider(t *testing.T) {
	onlyAlpha := Policy{mustRule(t, "alpha:*")}
	both := Policy{mustRule(t, "alpha:*"), mustRule(t, "beta:shared-*")}

	require.False(t, onlyAlpha.Covers("shared-model", []string{"alpha", "beta"}),
		"covered with one of two serving providers denied")
	require.True(t, both.Covers("shared-model", []string{"alpha", "beta"}),
		"not covered although every serving provider is allowed")
	require.False(t, both.Covers("shared-model", nil), "a model no provider serves was covered")
}

func mustRule(t *testing.T, s string) Rule {
	t.Helper()

	r, err := ParseRule(s)
	require.NoError(t, err, "ParseRule(%q)", s)

	return r
}
