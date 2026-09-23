package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy"
	cliproxyconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
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
		if !list.IsArray() {
			t.Fatalf("response %s has no %q array", body, key)
		}
		var names []string
		for _, entry := range list.Array() {
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
	req, err := http.NewRequest(http.MethodGet, r.baseURL+path, nil)
	if err != nil {
		t.Fatalf("build GET %s: %v", path, err)
	}
	for k, v := range header {
		req.Header[k] = v
	}
	req.Header.Set("Authorization", "Bearer "+wireSecret)
	resp, err := noRedirects.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read GET %s: %v", path, err)
	}
	return resp.StatusCode, string(body)
}

// TestListingsShowOnlyWhatThePolicyAdmits: in every format upstream lists
// models in, a user sees a model exactly when the gate would admit a request
// for it — every provider serving it allowed — and an empty policy sees an
// empty list.
func TestListingsShowOnlyWhatThePolicyAdmits(t *testing.T) {
	policy := &switchableResolver{}
	r := startWith(t, Params{Config: &cliproxyconfig.Config{}, Resolver: policy})

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
			code, body := r.getAs(t, list.path, list.header)
			if code != http.StatusOK {
				t.Fatalf("%s list for %v = %d %s, want 200", list.name, tc.rules, code, body)
			}
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
			if !slices.Equal(got, want) {
				t.Errorf("%s list for policy %v shows %v of this test's models, want %v", list.name, tc.rules, got, want)
			}
			if tc.rules == nil && len(names) != 0 {
				t.Errorf("%s list for an empty policy = %v, want none", list.name, names)
			}
		}
	}
}

// TestAnthropicListingBoundsFollowTheFilter: an Anthropic list names its
// first and last model; they must be the first and last models the user may
// see, and empty when there are none — never a model the filter removed.
func TestAnthropicListingBoundsFollowTheFilter(t *testing.T) {
	policy := &switchableResolver{}
	r := startWith(t, Params{Config: &cliproxyconfig.Config{}, Resolver: policy})
	seq := strconv.FormatInt(wireSeq.Add(1), 10)
	registerClient(t, "bounds-client-allowed-"+seq, "claude", "bounds-a-"+seq, "bounds-b-"+seq)
	registerClient(t, "bounds-client-denied-"+seq, "codex", "bounds-denied-"+seq)

	for _, tc := range []struct {
		rules []string
		want  int
	}{{[]string{"claude:bounds-*"}, 2}, {nil, 0}} {
		policy.set(tc.rules...)
		for _, header := range []http.Header{{"Anthropic-Version": {"2023-06-01"}}, {"User-Agent": {"claude-cli/2.0"}}} {
			_, body := r.getAs(t, "/v1/models", header)
			ids := gjson.Get(body, "data.#.id").Array()
			if len(ids) != tc.want {
				t.Fatalf("Anthropic list for %v = %s, want %d models", tc.rules, body, tc.want)
			}
			first, last := "", ""
			if len(ids) > 0 {
				first, last = ids[0].String(), ids[len(ids)-1].String()
			}
			if got := [2]string{gjson.Get(body, "first_id").String(), gjson.Get(body, "last_id").String()}; got != [2]string{first, last} {
				t.Errorf("Anthropic list for %v has first_id, last_id %q, want %q", tc.rules, got, [2]string{first, last})
			}
		}
	}
}

// TestSingleGeminiModelIsHiddenLikeAnUnknownOne: a model the policy does not
// admit is answered exactly as one that does not exist, so it cannot be
// found by asking — under either name upstream serves it by. The model is
// registered the way Gemini models are, named "models/<id>".
func TestSingleGeminiModelIsHiddenLikeAnUnknownOne(t *testing.T) {
	policy := &switchableResolver{}
	r := startWith(t, Params{Config: &cliproxyconfig.Config{}, Resolver: policy})
	seq := strconv.FormatInt(wireSeq.Add(1), 10)
	model := "single-" + seq
	cliproxy.GlobalModelRegistry().RegisterClient("single-client-"+seq, "gemini",
		[]*cliproxy.ModelInfo{{ID: model, Name: "models/" + model}})
	t.Cleanup(func() { cliproxy.GlobalModelRegistry().UnregisterClient("single-client-" + seq) })
	paths := []string{"/v1beta/models/" + model, "/v1beta/models/models/" + model}

	policy.set("gemini:*")
	for _, path := range paths {
		if code, body := r.getAs(t, path, nil); code != http.StatusOK || gjson.Get(body, "name").String() != "models/"+model {
			t.Fatalf("GET %s allowed = %d %s, want 200 naming it", path, code, body)
		}
	}
	policy.set("claude:*")
	unknownCode, unknownBody := r.getAs(t, "/v1beta/models/no-such-model-"+seq, nil)
	for _, path := range paths {
		code, body := r.getAs(t, path, nil)
		if code != http.StatusNotFound || code != unknownCode || body != unknownBody {
			t.Fatalf("GET %s denied = %d %s, want what an unknown model gets: %d %s", path, code, body, unknownCode, unknownBody)
		}
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
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		req.Header.Set("Authorization", "Bearer "+gateSecret)
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadGateway || rec.Body.String() != unavailable {
			t.Errorf("%s = %d %.200s, want 502 %s", tc.what, rec.Code, rec.Body, unavailable)
		}
	}
}

// TestListingThroughTheWire: with two vendors declared at boot, a user
// allowed one of them is listed that vendor's model and not the other's, nor
// the model both serve.
func TestListingThroughTheWire(t *testing.T) {
	v := startVendorPair(t)
	code, body := v.getAs(t, "/v1/models", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /v1/models = %d %s", code, body)
	}
	ids := arrayNames("data", "id", same)(t, body)
	if !slices.Contains(ids, v.allowedAlias) || slices.Contains(ids, v.otherAlias) || slices.Contains(ids, v.sharedAlias) {
		t.Fatalf("GET /v1/models = %v, want %s and neither %s nor %s", ids, v.allowedAlias, v.otherAlias, v.sharedAlias)
	}
}
