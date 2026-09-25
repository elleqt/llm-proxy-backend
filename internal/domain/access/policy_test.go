package access

import "testing"

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
				if err != nil {
					t.Fatalf("ParseRule(%q): %v", raw, err)
				}

				policy = append(policy, r)
			}

			if got := policy.Allows(tc.provider, tc.model); got != tc.want {
				t.Fatalf("Allows(%q, %q) = %v, want %v", tc.provider, tc.model, got, tc.want)
			}
		})
	}
}

func TestParseRuleRejectsMalformed(t *testing.T) {
	// "a:b:c" is deliberately absent: splitting on the first colon only makes it a
	// valid rule for provider "a", pattern "b:c" — which is what a versioned or
	// tagged model identifier needs.
	for _, raw := range []string{"", "chatgpt", ":model", "chatgpt:", "   ", ":"} {
		if _, err := ParseRule(raw); err == nil {
			t.Fatalf("ParseRule(%q) = nil error, want error", raw)
		}
	}
}

// String is what an operator sees in the admin UI and in an audit entry, so it
// must render the normalised rule, not the raw input.
func TestRuleStringRendersNormalisedRule(t *testing.T) {
	r, err := ParseRule(" ChatGPT : Claude-Sonnet-* ")
	if err != nil {
		t.Fatalf("ParseRule: %v", err)
	}

	if got := r.String(); got != "chatgpt:claude-sonnet-*" {
		t.Fatalf("String() = %q, want %q", got, "chatgpt:claude-sonnet-*")
	}
}

// A Rule built by hand rather than by ParseRule has no compiled pattern; matches
// must compile on demand instead of refusing everything.
func TestHandBuiltRuleMatchesWithoutPrecompiledPattern(t *testing.T) {
	p := Policy{{Provider: "openrouter", ModelPattern: "*claude*"}}
	if !p.Allows("openrouter", "anthropic/claude-sonnet-4.6") {
		t.Fatal("hand-built rule must match; compiled pattern should be built on demand")
	}

	if p.Allows("openrouter", "openai/gpt-4o") {
		t.Fatal("hand-built rule must not over-grant")
	}
}

// A model is covered only on every provider serving it, and a model nobody serves is
// not covered at all: both halves fail closed.
func TestCoversRequiresEveryServingProvider(t *testing.T) {
	onlyAlpha := Policy{mustRule(t, "alpha:*")}
	both := Policy{mustRule(t, "alpha:*"), mustRule(t, "beta:shared-*")}

	if onlyAlpha.Covers("shared-model", []string{"alpha", "beta"}) {
		t.Fatal("covered with one of two serving providers denied")
	}

	if !both.Covers("shared-model", []string{"alpha", "beta"}) {
		t.Fatal("not covered although every serving provider is allowed")
	}

	if both.Covers("shared-model", nil) {
		t.Fatal("a model no provider serves was covered")
	}
}

func mustRule(t *testing.T, s string) Rule {
	t.Helper()

	r, err := ParseRule(s)
	if err != nil {
		t.Fatalf("ParseRule(%q): %v", s, err)
	}

	return r
}
