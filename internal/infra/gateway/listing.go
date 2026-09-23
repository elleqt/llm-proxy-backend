package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/api/handlers"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// listing cuts the response upstream wrote for a model-listing route down to
// the entries admitted reports true for, keeping the response's shape. It
// returns the status and body to send. A successful response that is not of
// the shape the route's handler writes is an error: nothing unfiltered is
// passed on. An unsuccessful one names no models and passes through.
//
// admitted is asked about the name an entry tells the client to request the
// model by, so a listed model is one the policy gate would admit a request
// for (see allows).
type listing func(c *gin.Context, status int, body []byte, admitted func(model string) bool) (int, []byte, error)

// errListingShape reports a model list that is not of the shape expected.
var errListingShape = errors.New("gateway: model list is not of the expected shape")

// maxListingBody caps the model list the gate buffers to filter. Upstream's
// lists run to tens of kilobytes; a larger one is refused, not passed on.
const maxListingBody = 16 << 20

// v1Models filters GET /v1/models, which serves four formats. It picks the
// one upstream's handler picks, in its order
// (internal/api/server_routes.go unifiedModelsHandler; home mode, its first
// branch otherwise, is refused by admit):
//   - Grok Shell clients (a User-Agent containing "grok-shell"): "data", by
//     "id" and "model" (grokbuild.BuildResponse);
//   - Codex clients (a client_version query parameter, even empty): "models",
//     by "slug" (codex/models BuildResponseForClient);
//   - Anthropic clients (an Anthropic-Version header, or a User-Agent starting
//     with "claude-cli"): "data", by "id" decoded as upstream routes a cloaked
//     Claude name, with "first_id" and "last_id" following the filtered list
//     (claude/models BuildResponse);
//   - everyone else: "data", by "id" (openai OpenAIModels).
func v1Models(c *gin.Context, status int, body []byte, admitted func(string) bool) (int, []byte, error) {
	if status != http.StatusOK {
		return status, body, nil
	}
	userAgent := c.GetHeader("User-Agent")
	switch {
	case strings.Contains(strings.ToLower(userAgent), "grok-shell"):
		out, _, err := filterArray(body, "data", admitted, func(entry []byte) []string {
			return []string{gjson.GetBytes(entry, "id").String(), gjson.GetBytes(entry, "model").String()}
		})
		return status, out, err
	case hasQuery(c, "client_version"):
		out, _, err := filterArray(body, "models", admitted, field("slug", nil))
		return status, out, err
	case c.GetHeader("Anthropic-Version") != "" || strings.HasPrefix(userAgent, "claude-cli"):
		out, kept, err := filterArray(body, "data", admitted, field("id", decodeClaudeModelID))
		if err != nil {
			return status, nil, err
		}
		first, last := "", ""
		if len(kept) > 0 {
			first, last = kept[0].Get("id").String(), kept[len(kept)-1].Get("id").String()
		}
		if out, err = sjson.SetBytes(out, "first_id", first); err == nil {
			out, err = sjson.SetBytes(out, "last_id", last)
		}
		return status, out, err
	default:
		out, _, err := filterArray(body, "data", admitted, field("id", nil))
		return status, out, err
	}
}

// geminiModels filters GET /v1beta/models: "models", by "name" without its
// "models/" prefix — the name a client puts in the path of
// /v1beta/models/{model}:{method} (gemini GeminiModels).
func geminiModels(_ *gin.Context, status int, body []byte, admitted func(string) bool) (int, []byte, error) {
	if status != http.StatusOK {
		return status, body, nil
	}
	out, _, err := filterArray(body, "models", admitted, field("name", geminiModelName))
	return status, out, err
}

// geminiModel filters GET /v1beta/models/{model}, which upstream answers with
// one model or 404 (gemini GeminiGetHandler). A model that is not admitted
// gets upstream's own 404, so it cannot be told from one that does not exist.
func geminiModel(_ *gin.Context, status int, body []byte, admitted func(string) bool) (int, []byte, error) {
	if status != http.StatusOK {
		return status, body, nil
	}
	name := gjson.GetBytes(body, "name")
	if !gjson.ValidBytes(body) || name.Type != gjson.String {
		return status, nil, errListingShape
	}
	if admitted(geminiModelName(name.String())) {
		return status, body, nil
	}
	return http.StatusNotFound, geminiNotFound, nil
}

// geminiNotFound is the body upstream's GeminiGetHandler answers an unknown
// model with, as gin's c.JSON encodes it.
var geminiNotFound = func() []byte {
	b, err := json.Marshal(handlers.ErrorResponse{Error: handlers.ErrorDetail{Message: "Not Found", Type: "not_found"}})
	if err != nil {
		panic(err)
	}
	return b
}()

// geminiModelName is the model a Gemini list entry's name stands for.
func geminiModelName(name string) string {
	return strings.TrimPrefix(name, "models/")
}

// field reads one string field of a list entry, through decode if given.
func field(key string, decode func(string) string) func([]byte) []string {
	return func(entry []byte) []string {
		v := gjson.GetBytes(entry, key).String()
		if decode != nil {
			v = decode(v)
		}
		return []string{v}
	}
}

// filterArray keeps the entries of the array at key in body whose every name
// (as names reads them) is non-empty and admitted, and returns body with that
// array replaced, and the kept entries in order. A null array lists nothing
// and is kept. body must be a JSON object holding the array.
func filterArray(body []byte, key string, admitted func(string) bool, names func([]byte) []string) ([]byte, []gjson.Result, error) {
	if !gjson.ValidBytes(body) || !gjson.ParseBytes(body).IsObject() {
		return nil, nil, errListingShape
	}
	list := gjson.GetBytes(body, key)
	if list.Type == gjson.Null && list.Exists() {
		return body, nil, nil
	}
	if !list.IsArray() {
		return nil, nil, errListingShape
	}
	var kept bytes.Buffer
	kept.WriteByte('[')
	var entries []gjson.Result
	list.ForEach(func(_, entry gjson.Result) bool {
		for _, n := range names([]byte(entry.Raw)) {
			if n == "" || !admitted(n) {
				return true
			}
		}
		if len(entries) > 0 {
			kept.WriteByte(',')
		}
		kept.WriteString(entry.Raw)
		entries = append(entries, entry)
		return true
	})
	kept.WriteByte(']')
	out, err := sjson.SetRawBytes(body, key, kept.Bytes())
	return out, entries, err
}

// hasQuery reports whether the request's query names key, with any value.
func hasQuery(c *gin.Context, key string) bool {
	_, ok := c.Request.URL.Query()[key]
	return ok
}

// bufferedWriter holds back what a handler writes, so the gate can filter it
// before anything reaches the client. It never flushes, and refuses to hold
// more than limit bytes.
type bufferedWriter struct {
	gin.ResponseWriter
	status   int
	wrote    bool
	body     bytes.Buffer
	limit    int
	overflow bool
}

var errListingTooLarge = errors.New("gateway: model list too large")

func (w *bufferedWriter) WriteHeader(code int) {
	if code > 0 {
		w.status = code
	}
}

func (w *bufferedWriter) WriteHeaderNow() { w.wrote = true }

func (w *bufferedWriter) Write(b []byte) (int, error) {
	w.wrote = true
	if w.body.Len()+len(b) > w.limit {
		w.overflow = true
		return 0, errListingTooLarge
	}
	return w.body.Write(b)
}

func (w *bufferedWriter) WriteString(s string) (int, error) { return w.Write([]byte(s)) }

func (w *bufferedWriter) Status() int { return w.status }

func (w *bufferedWriter) Size() int {
	if !w.wrote {
		return -1
	}
	return w.body.Len()
}

func (w *bufferedWriter) Written() bool { return w.wrote }

func (w *bufferedWriter) Flush() {}
