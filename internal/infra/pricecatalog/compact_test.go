package pricecatalog_test

import (
	"strings"
	"testing"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/infra/pricecatalog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Compact v1 uses [node index] references and alternating key indexes and values
// in object nodes. Unrelated arrays and compatibility data are not price inputs.
const compactDoc = `{
  "version": 1,
  "keys": ["cost", "input", "output", "cacheRead", "cacheWrite", "name", "enabled"],
  "booleanShapes": [[], [6]],
  "nodes": [
    [0, [], 0, []],
    [0, [1, 3, 2, 15, 3, 0.3, 4, 3.75], 0, []],
    [0, [0, [1], 5, "Sonnet"], 1, [1]],
    [0, [1, 5, 2, 30, 3, 0.5, 4, 6.25], 0, []],
    [0, [0, [3]], 0, []],
    [0, [1, 99, 2, 99], 0, []],
    [0, [0, [5]], 0, []],
    [0, [1, 2, 2, 8], 0, []],
    [0, [0, [7]], 0, []],
    [0, [1, -1, 2, 4], 0, []],
    [0, [0, [9]], 0, []],
    [0, [1, 0, 2, 0], 0, []],
    [0, [0, [11]], 0, []]
  ],
  "compat": [],
  "providers": [
    ["openai", [0], [["gpt-shared", [6]], ["gpt-fallback", [8]], ["gpt-missing", [8]]]],
    ["anthropic", [0], [["claude-sonnet", [2]], ["claude-free", [12]], ["claude-negative", [10]], ["   ", [2]]]],
    ["openai-codex", [0], [["gpt-shared", [4]], ["gpt-missing", [0]]]],
    ["unmapped", [99999], [["ignored", [99999]]]]
  ]
}`

func TestParseCompactCatalog(t *testing.T) {
	got, err := pricecatalog.Parse([]byte(compactDoc))
	require.NoError(t, err)
	assert.Equal(t, []app.ModelPrice{
		{Provider: "chatgpt", Model: "gpt-fallback", Input: 2, Output: 8},
		{Provider: "chatgpt", Model: "gpt-missing", Input: 2, Output: 8},
		{Provider: "chatgpt", Model: "gpt-shared", Input: 5, Output: 30, CacheRead: 0.5, CacheWrite: 6.25},
		{Provider: "claude", Model: "claude-free"},
		{Provider: "claude", Model: "claude-sonnet", Input: 3, Output: 15, CacheRead: 0.3, CacheWrite: 6},
	}, got)
}

func TestParseRejectsBrokenCompactCatalog(t *testing.T) {
	for name, doc := range map[string]string{
		"unsupported version":    strings.Replace(compactDoc, `"version": 1`, `"version": 2`, 1),
		"missing nodes":          `{"version":1,"keys":[],"providers":[]}`,
		"invalid providers":      `{"version":1,"keys":[],"booleanShapes":[],"nodes":[],"providers":{}}`,
		"invalid reference":      strings.Replace(compactDoc, `"claude-sonnet", [2]`, `"claude-sonnet", [99999]`, 1),
		"undefined model":        strings.Replace(compactDoc, `"claude-sonnet", [2]`, `"claude-sonnet", [-1]`, 1),
		"null reference":         strings.Replace(compactDoc, `"claude-sonnet", [2]`, `"claude-sonnet", [null]`, 1),
		"string reference":       strings.Replace(compactDoc, `"claude-sonnet", [2]`, `"claude-sonnet", ["2"]`, 1),
		"invalid cost reference": strings.Replace(compactDoc, `[0, [1], 5, "Sonnet"]`, `[0, [99999], 5, "Sonnet"]`, 1),
		"invalid key":            strings.Replace(compactDoc, `[1, 3, 2, 15`, `[99999, 3, 2, 15`, 1),
		"odd properties":         strings.Replace(compactDoc, `[0, [3]]`, `[0]`, 1),
		"array model":            strings.Replace(compactDoc, `[0, [0, [3]], 0, []]`, `[1, []]`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := pricecatalog.Parse([]byte(doc))
			require.Error(t, err)
			assert.Empty(t, got, "a damaged catalog must not partially replace the stored prices")
		})
	}
}

func TestCompactInvalidRatesAreNotFreePrices(t *testing.T) {
	for name, replacement := range map[string]string{
		"missing input":      `[2, 15, 3, 0.3, 4, 3.75], 0, []`,
		"missing output":     `[1, 3, 3, 0.3, 4, 3.75], 0, []`,
		"string rate":        `[1, "three", 2, 15, 3, 0.3, 4, 3.75], 0, []`,
		"boolean cache rate": `[1, 3, 2, 15, 4, 3.75], 2, [1]`,
	} {
		t.Run(name, func(t *testing.T) {
			doc := strings.Replace(compactDoc, `[1, 3, 2, 15, 3, 0.3, 4, 3.75], 0, []`, replacement, 1)
			doc = strings.Replace(doc, `"booleanShapes": [[], [6]]`, `"booleanShapes": [[], [6], [3]]`, 1)
			got, err := pricecatalog.Parse([]byte(doc))
			require.NoError(t, err)

			for _, price := range got {
				assert.NotEqual(t, "claude-sonnet", price.Model)
			}
		})
	}
}
