package gateway

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/require"
)

// extractOn runs source the way the gate does — inside a handler on the route
// pattern it serves, given the whole body, which is put back for the handler
// — and returns what it read.
func extractOn(t *testing.T, source modelSource, pattern string, req *http.Request) (string, bool) {
	t.Helper()

	var (
		model string
		ok    bool
	)

	engine := gin.New()
	engine.Handle(req.Method, pattern, func(ginCtx *gin.Context) {
		raw, err := io.ReadAll(ginCtx.Request.Body)
		require.NoError(t, err, "read body")

		ginCtx.Request.Body = io.NopCloser(bytes.NewReader(raw))
		model, ok = source(ginCtx, raw)
	})
	engine.ServeHTTP(httptest.NewRecorder(), req)

	return model, ok
}

func zstdCompress(t *testing.T, plain string) string {
	t.Helper()

	enc, err := zstd.NewWriter(nil)
	require.NoError(t, err, "zstd writer")

	defer func() { _ = enc.Close() }()

	return string(enc.EncodeAll([]byte(plain), nil))
}

// TestModelIsReadWhereTheHandlerReadsIt: each source names the model upstream
// routes the request by.
func TestModelIsReadWhereTheHandlerReadsIt(t *testing.T) {
	for _, tc := range []struct {
		name        string
		source      modelSource
		pattern     string
		path        string
		body        string
		contentType string
		want        string
	}{
		{
			"chat body", bodyModel, "/v1/chat/completions", "/v1/chat/completions",
			`{"model":"gpt-5.6","messages":[]}`, "", "gpt-5.6",
		},
		{
			"anthropic body", claudeModel, "/v1/messages", "/v1/messages",
			`{"model":"claude-sonnet-5","messages":[]}`, "", "claude-sonnet-5",
		},
		{
			"anthropic cloaked name, routed as the model it encodes", claudeModel, "/v1/messages", "/v1/messages",
			`{"model":"claude-fable-5-dd-6.5-tpg(high)"}`, "", "gpt-5.6(high)",
		},
		{
			"gemini path", geminiActionModel, "/v1beta/models/*action", "/v1beta/models/gemini-3-pro:streamGenerateContent",
			`{"contents":[]}`, "", "gemini-3-pro",
		},
		{
			"interactions resource name", interactionsModel, "/v1beta/interactions", "/v1beta/interactions",
			`{"model":"models/gemini-3-pro","input":"hi"}`, "", "gemini-3-pro",
		},
		{
			"image generation", imageGenerationModel, "/v1/images/generations", "/v1/images/generations",
			`{"model":" gpt-image-2.5 ","prompt":"a cat"}`, "", "gpt-image-2.5",
		},
		{
			"image generation without a model, upstream's default", imageGenerationModel, "/v1/images/generations", "/v1/images/generations",
			`{"prompt":"a cat"}`, "", "gpt-image-2",
		},
		{
			"xAI image model, canonical as upstream routes it", imageGenerationModel, "/v1/images/generations", "/v1/images/generations",
			`{"model":"Grok/Grok-Imagine-Image-Quality","prompt":"a cat"}`, "", "grok-imagine-image-quality",
		},
		{
			"a name that only ends like an xAI model", imageGenerationModel, "/v1/images/generations", "/v1/images/generations",
			`{"model":"acme/grok-imagine-image","prompt":"a cat"}`, "", "acme/grok-imagine-image",
		},
		{
			"image edit as JSON", imageEditModel, "/v1/images/edits", "/v1/images/edits",
			`{"model":"gpt-image-1.5","prompt":"a cat","images":[]}`, "application/json; charset=utf-8", "gpt-image-1.5",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, tc.path, strings.NewReader(tc.body))
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}

			model, ok := extractOn(t, tc.source, tc.pattern, req)
			require.True(t, ok, "no model read; want %q", tc.want)
			require.Equal(t, tc.want, model, "model")
		})
	}
}

// TestUnreadableRequestsNameNoModel: a request whose model cannot be read is
// refused, not passed on and not a panic.
func TestUnreadableRequestsNameNoModel(t *testing.T) {
	for _, tc := range []struct {
		name    string
		source  modelSource
		pattern string
		path    string
		body    string
	}{
		{"malformed JSON", bodyModel, "/v1/chat/completions", "/v1/chat/completions", `{"model":"gpt-5.6"`},
		{"malformed anthropic JSON", claudeModel, "/v1/messages", "/v1/messages", `{"model":"claude-sonnet-5",}`},
		{"no model", bodyModel, "/v1/chat/completions", "/v1/chat/completions", `{"messages":[]}`},
		{"blank model", claudeModel, "/v1/messages", "/v1/messages", `{"model":"  "}`},
		{"not JSON at all", bodyModel, "/v1/responses", "/v1/responses", "\x00\xff"},
		{"empty body", bodyModel, "/v1/responses", "/v1/responses", ""},
		{"repeated model", bodyModel, "/v1/responses", "/v1/responses", `{"model":"a","input":"hi","model":"b"}`},
		{"repeated model, escaped", claudeModel, "/v1/messages", "/v1/messages", `{"model":"a","mod\u0065l":"b"}`},
		{"repeated model, another case", claudeModel, "/v1/messages", "/v1/messages", `{"MODEL":"b","model":"a"}`},
		{"interactions agent", interactionsModel, "/v1beta/interactions", "/v1beta/interactions", `{"agent":"deep-research"}`},
		{"interactions repeated model", interactionsModel, "/v1beta/interactions", "/v1beta/interactions", `{"model":"a","Model":"b"}`},
		{"gemini path without a method", geminiActionModel, "/v1beta/models/*action", "/v1beta/models/gemini-3-pro", ""},
		{"gemini path with two methods", geminiActionModel, "/v1beta/models/*action", "/v1beta/models/a:b:generateContent", ""},
		{"gemini body repeating model", geminiActionModel, "/v1beta/models/*action", "/v1beta/models/a:generateContent", `{"model":"a","model":"b"}`},
		{"image generation, malformed", imageGenerationModel, "/v1/images/generations", "/v1/images/generations", `{"model":`},
		{"image generation repeating model", imageGenerationModel, "/v1/images/generations", "/v1/images/generations", `{"model":"gpt-image-2","prompt":"x","model":"b"}`},
		{"image edit, neither JSON nor a form", imageEditModel, "/v1/images/edits", "/v1/images/edits", `{"model":"gpt-image-2"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, tc.path, strings.NewReader(tc.body))
			if tc.path == "/v1/images/edits" {
				req.Header.Set("Content-Type", "text/plain")
			}

			model, ok := extractOn(t, tc.source, tc.pattern, req)
			require.False(t, ok, "model = %q, want none", model)
		})
	}
}

// imageForm is a multipart image edit naming models as its "model" fields. It
// returns the form body and its content type.
func imageForm(t *testing.T, fields [][2]string) (string, string) {
	t.Helper()

	var buf bytes.Buffer

	mw := multipart.NewWriter(&buf)
	for _, f := range fields {
		require.NoError(t, mw.WriteField(f[0], f[1]), "write field")
	}

	part, err := mw.CreateFormFile("image", "cat.png")
	require.NoError(t, err, "create file")

	_, _ = part.Write([]byte("png bytes"))

	require.NoError(t, mw.Close(), "close form")

	return buf.String(), mw.FormDataContentType()
}

// TestImageEditFormModel: a multipart edit is decided on its "model" field,
// and the handler still gets the whole form; a form naming "model" twice, in
// any letter case, is refused.
func TestImageEditFormModel(t *testing.T) {
	body, contentType := imageForm(t, [][2]string{{"model", "grok-imagine-image"}, {"prompt", "a cat"}})
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/images/edits", strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)

	engine := gin.New()

	var (
		model string
		ok    bool
	)

	engine.POST("/v1/images/edits", func(ginCtx *gin.Context) {
		model, ok = imageEditModel(ginCtx, nil)

		form, err := ginCtx.MultipartForm()
		require.NoError(t, err, "the handler's form after extraction")
		require.Len(t, form.File["image"], 1, "the handler's form after extraction, want the image")
		require.Equal(t, "a cat", ginCtx.PostForm("prompt"), "the handler's form after extraction, want the prompt")
	})
	engine.ServeHTTP(httptest.NewRecorder(), req)

	require.True(t, ok, "no model read; want grok-imagine-image")
	require.Equal(t, "grok-imagine-image", model, "model")

	body, contentType = imageForm(t, [][2]string{{"model", "gpt-image-2"}, {"Model", "grok-imagine-image"}})
	req = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/images/edits", strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)

	model, ok = extractOn(t, imageEditModel, "/v1/images/edits", req)
	require.False(t, ok, "a form naming model twice gave %q, want none", model)
}
