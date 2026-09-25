package gateway

import (
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy"
	cliproxyconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

// modelList is one listing format: how to ask for it and how to read the
// names it tells a client to request models by.
type modelList struct {
	name   string
	path   string
	header http.Header
	// names reads the listed names; it fails the test on a body not of the
	// format.
	names func(t *testing.T, body string) []string
}

// arrayNames reads field of every entry of the array at key, through decode.
func arrayNames(key, field string, decode func(string) string) func(*testing.T, string) []string {
	return func(t *testing.T, body string) []string {
		t.Helper()

		list := gjson.Get(body, key)
		require.True(t, list.IsArray(), "response %s has no %q array", body, key)

		entries := list.Array()

		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, decode(entry.Get(field).String()))
		}

		return names
	}
}

func same(s string) string { return s }

// modelLists are every format upstream serves a model list in.
var modelLists = []modelList{
	{"openai", "/v1/models", nil, arrayNames("data", "id", same)},
	{"anthropic", "/v1/models", http.Header{"Anthropic-Version": {"2023-06-01"}}, arrayNames("data", "id", decodeClaudeModelID)},
	{"claude-cli", "/v1/models", http.Header{"User-Agent": {"claude-cli/2.0"}}, arrayNames("data", "id", decodeClaudeModelID)},
	{"codex", "/v1/models?client_version=0.99.0", nil, arrayNames("models", "slug", same)},
	{"grok", "/v1/models", http.Header{"User-Agent": {"grok-shell/1.0"}}, arrayNames("data", "model", same)},
	{"gemini", "/v1beta/models", nil, arrayNames("models", "name", geminiModelName)},
}

// getAs sends GET path with a valid token and header, and returns the status
// and body.
func (r *running) getAs(t *testing.T, path string, header http.Header) (int, string) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, r.baseURL+path, http.NoBody)
	require.NoError(t, err, "build GET %s", path)

	maps.Copy(req.Header, header)

	req.Header.Set("Authorization", "Bearer "+wireSecret)

	resp, err := noRedirects.Do(req)
	require.NoError(t, err, "GET %s", path)

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "read GET %s", path)

	return resp.StatusCode, string(body)
}

// TestListingsShowOnlyWhatThePolicyAdmits: in every format upstream lists
// models in, a user sees a model exactly when the gate would admit a request
// for it — every provider serving it allowed — and an empty policy sees an
// empty list.
func TestListingsShowOnlyWhatThePolicyAdmits(t *testing.T) {
	policy := &switchableResolver{}
	srv := startWith(t, Params{Config: &cliproxyconfig.Config{}, Resolver: policy})

	seq := strconv.FormatInt(wireSeq.Add(1), 10)
	claudeOnly, codexOnly, shared := "list-claude-"+seq, "list-codex-"+seq, "list-shared-"+seq
	registerClient(t, "list-client-claude-"+seq, "claude", claudeOnly, shared)
	registerClient(t, "list-client-codex-"+seq, "codex", codexOnly, shared)
	ours := []string{claudeOnly, codexOnly, shared}

	for _, tc := range []struct {
		rules []string
		want  []string
	}{
		{[]string{"claude:*"}, []string{claudeOnly}},
		{[]string{"chatgpt:*"}, []string{codexOnly}},
		{[]string{"claude:*", "chatgpt:list-*"}, []string{claudeOnly, codexOnly, shared}},
		{nil, nil},
	} {
		policy.set(tc.rules...)

		for _, list := range modelLists {
			code, body := srv.getAs(t, list.path, list.header)
			require.Equal(t, http.StatusOK, code, "%s list for %v: %s", list.name, tc.rules, body)

			names := list.names(t, body)

			var got []string

			for _, n := range names {
				if slices.Contains(ours, n) {
					got = append(got, n)
				}
			}

			slices.Sort(got)

			want := slices.Clone(tc.want)
			slices.Sort(want)

			assert.Equal(t, want, got, "%s list for policy %v shows these of this test's models", list.name, tc.rules)

			if tc.rules == nil {
				assert.Empty(t, names, "%s list for an empty policy", list.name)
			}
		}
	}
}

// TestAnthropicListingBoundsFollowTheFilter: an Anthropic list names its
// first and last model; they must be the first and last models the user may
// see, and empty when there are none — never a model the filter removed.
func TestAnthropicListingBoundsFollowTheFilter(t *testing.T) {
	policy := &switchableResolver{}
	srv := startWith(t, Params{Config: &cliproxyconfig.Config{}, Resolver: policy})
	seq := strconv.FormatInt(wireSeq.Add(1), 10)
	registerClient(t, "bounds-client-allowed-"+seq, "claude", "bounds-a-"+seq, "bounds-b-"+seq)
	registerClient(t, "bounds-client-denied-"+seq, "codex", "bounds-denied-"+seq)

	for _, tc := range []struct {
		rules []string
		want  int
	}{{[]string{"claude:bounds-*"}, 2}, {nil, 0}} {
		policy.set(tc.rules...)

		for _, header := range []http.Header{{"Anthropic-Version": {"2023-06-01"}}, {"User-Agent": {"claude-cli/2.0"}}} {
			_, body := srv.getAs(t, "/v1/models", header)

			ids := gjson.Get(body, "data.#.id").Array()
			require.Len(t, ids, tc.want, "Anthropic list for %v = %s", tc.rules, body)

			first, last := "", ""
			if len(ids) > 0 {
				first, last = ids[0].String(), ids[len(ids)-1].String()
			}

			got := [2]string{gjson.Get(body, "first_id").String(), gjson.Get(body, "last_id").String()}
			assert.Equal(t, [2]string{first, last}, got, "Anthropic list for %v: first_id, last_id", tc.rules)
		}
	}
}

// TestSingleGeminiModelIsHiddenLikeAnUnknownOne: a model the policy does not
// admit is answered exactly as one that does not exist, so it cannot be
// found by asking — under either name upstream serves it by. The model is
// registered the way Gemini models are, named "models/<id>".
func TestSingleGeminiModelIsHiddenLikeAnUnknownOne(t *testing.T) {
	policy := &switchableResolver{}
	srv := startWith(t, Params{Config: &cliproxyconfig.Config{}, Resolver: policy})
	seq := strconv.FormatInt(wireSeq.Add(1), 10)
	model := "single-" + seq
	cliproxy.GlobalModelRegistry().RegisterClient("single-client-"+seq, "gemini",
		[]*cliproxy.ModelInfo{{ID: model, Name: "models/" + model}})
	t.Cleanup(func() { cliproxy.GlobalModelRegistry().UnregisterClient("single-client-" + seq) })

	paths := []string{"/v1beta/models/" + model, "/v1beta/models/models/" + model}

	policy.set("gemini:*")

	for _, path := range paths {
		code, body := srv.getAs(t, path, nil)
		require.Equal(t, http.StatusOK, code, "GET %s allowed: %s", path, body)
		require.Equal(t, "models/"+model, gjson.Get(body, "name").String(), "GET %s allowed: %s", path, body)
	}

	policy.set("claude:*")

	unknownCode, unknownBody := srv.getAs(t, "/v1beta/models/no-such-model-"+seq, nil)
	for _, path := range paths {
		code, body := srv.getAs(t, path, nil)
		require.Equal(t, http.StatusNotFound, code, "GET %s denied: %s", path, body)
		require.Equal(t, unknownCode, code, "GET %s denied, status of an unknown model", path)
		require.Equal(t, unknownBody, body, "GET %s denied, body of an unknown model", path)
	}
}

// TestListingsOfAnUnexpectedShapeAreNotSent: the filter knows each listing
// route's format; a list in any other shape — upstream changed its format, or
// picks it by another rule — or one too large to hold is answered 502, and
// none of what the handler wrote reaches the client.
func TestListingsOfAnUnexpectedShapeAreNotSent(t *testing.T) {
	catalog := fixedCatalog(map[string][]string{"secret-model": {"chatgpt"}})

	const unavailable = `{"error":{"message":"model list unavailable","type":"server_error"}}`

	for _, tc := range []struct {
		what, path string
		write      func(c *gin.Context)
	}{
		{"a Codex list to a plain request", "/v1/models", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"models": []gin.H{{"slug": "secret-model"}}})
		}},
		{"a bare array", "/v1/models", func(c *gin.Context) {
			c.JSON(http.StatusOK, []gin.H{{"id": "secret-model"}})
		}},
		{"an OpenAI list where Gemini's is expected", "/v1beta/models", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"data": []gin.H{{"id": "secret-model"}}})
		}},
		{"not JSON", "/v1/models", func(c *gin.Context) {
			c.String(http.StatusOK, "secret-model")
		}},
		{"a list over the size limit", "/v1/models", func(c *gin.Context) {
			c.Status(http.StatusOK)
			_, _ = c.Writer.WriteString(`{"object":"list","data":[{"id":"secret-model"}],"pad":"`)
			_, _ = c.Writer.WriteString(strings.Repeat("x", maxListingBody))
			_, _ = c.Writer.WriteString(`"}`)
		}},
	} {
		engine := gateEngine(staticResolver(gateSecret, gatePrincipal, "*:*"), catalog)
		engine.GET(strings.TrimSuffix(tc.path, "/"), tc.write)
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, tc.path, http.NoBody)
		req.Header.Set("Authorization", "Bearer "+gateSecret)

		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadGateway, rec.Code, tc.what)
		assert.JSONEq(t, unavailable, rec.Body.String(), tc.what)
	}
}

// TestListingThroughTheWire: with two vendors declared at boot, a user
// allowed one of them is listed that vendor's model and not the other's, nor
// the model both serve.
func TestListingThroughTheWire(t *testing.T) {
	pair := startVendorPair(t)

	code, body := pair.getAs(t, "/v1/models", nil)
	require.Equal(t, http.StatusOK, code, "GET /v1/models: %s", body)

	ids := arrayNames("data", "id", same)(t, body)
	require.Contains(t, ids, pair.allowedAlias, "GET /v1/models")
	require.NotContains(t, ids, pair.otherAlias, "GET /v1/models")
	require.NotContains(t, ids, pair.sharedAlias, "GET /v1/models")
}

// TestCabinetListsWhatTheListingLists: the cabinet's list of a user's models
// (app.ModelsService over this gateway's catalogue) holds exactly the models
// GET /v1/models lists to the same user's key, each under every provider
// serving it. One model is only reachable through upstream's thinking-suffix
// resolution: "<think>(high)" is registered for chatgpt, but a request for it
// routes to "<think>", which only claude serves — so a side that judged it by
// its own providers instead of the gate's routing would disagree.
func TestCabinetListsWhatTheListingLists(t *testing.T) {
	policy := &switchableResolver{}
	srv := startWith(t, Params{Config: &cliproxyconfig.Config{}, Resolver: policy})
	cabinet := app.NewModelsService(srv.gateway.Catalog())

	seq := strconv.FormatInt(wireSeq.Add(1), 10)
	claudeOnly, codexOnly, shared := "cab-claude-"+seq, "cab-codex-"+seq, "cab-shared-"+seq
	think := "cab-think-" + seq
	thinkHigh := think + "(high)"
	registerClient(t, "cab-client-claude-"+seq, "claude", claudeOnly, shared, think)
	registerClient(t, "cab-client-codex-"+seq, "codex", codexOnly, shared, thinkHigh)

	for _, tc := range []struct {
		rules []string
		want  map[string][]string // this test's models the cabinet lists, by provider
	}{
		{[]string{"claude:*"}, map[string][]string{"claude": {claudeOnly, think}, "chatgpt": {thinkHigh}}},
		{[]string{"chatgpt:*"}, map[string][]string{"chatgpt": {codexOnly}}},
		{[]string{"claude:*", "chatgpt:cab-*"}, map[string][]string{
			"claude": {claudeOnly, shared, think}, "chatgpt": {codexOnly, shared, thinkHigh},
		}},
		{nil, map[string][]string{}},
	} {
		policy.set(tc.rules...)

		code, body := srv.getAs(t, "/v1/models", nil)
		require.Equal(t, http.StatusOK, code, "GET /v1/models for %v: %s", tc.rules, body)

		listed := arrayNames("data", "id", same)(t, body)
		slices.Sort(listed)
		listed = slices.Compact(listed)

		providers := cabinet.Allowed(identity.User{Policy: mustPolicy(tc.rules...)})

		var cabinetModels []string

		ours := map[string][]string{}

		for _, p := range providers {
			cabinetModels = append(cabinetModels, p.Models...)
			for _, m := range p.Models {
				if strings.HasPrefix(m, "cab-") {
					ours[p.Name] = append(ours[p.Name], m)
				}
			}
		}

		slices.Sort(cabinetModels)
		cabinetModels = slices.Compact(cabinetModels)

		assert.True(t, slices.Equal(cabinetModels, listed), "policy %v: the cabinet lists %v, GET /v1/models lists %v", tc.rules, cabinetModels, listed)
		assert.Equal(t, tc.want, ours, "policy %v: the cabinet lists this test's models", tc.rules)
	}
}
