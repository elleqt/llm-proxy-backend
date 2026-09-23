package gateway

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

// modelSource reads the model a request names, from where the upstream handler
// serving its route reads it (upstream v7.3.15, sdk/api/handlers), with the
// rewrites that handler applies before routing. ok is false when the request
// names no model, cannot be read, or names "model" more than once (see
// repeatsModelKey); the request is then refused, never passed on.
//
// raw is the whole body, which the gate has read and put back for the
// handler, byte for byte. It is identity-encoded: the gate refuses an encoded
// body on routes whose handler reads it as sent, and decodes it before any
// source runs on the routes whose handler would decode it (encoding.go).
type modelSource func(c *gin.Context, raw []byte) (model string, ok bool)

// bodyModel is the "model" of a JSON body, read as the handler reads it:
// as sent (c.GetRawData), or through handlers.ReadRequestBody, which returns
// an identity-encoded body as sent (request_body.go).
func bodyModel(_ *gin.Context, raw []byte) (string, bool) {
	return jsonModel(raw)
}

// claudeModel is bodyModel after the rewrite Anthropic handlers route by
// (claude/code_handlers.go rewriteClaudeDDModelInBody): upstream lists a
// non-Claude model to Anthropic clients as "claude-fable-5-dd-" plus its ID
// reversed, and routes such a name to the model it encodes.
func claudeModel(c *gin.Context, raw []byte) (string, bool) {
	model, ok := bodyModel(c, raw)
	if !ok {
		return "", false
	}
	return decodeClaudeModelID(model), true
}

// interactionsModel is the model of a Gemini interactions request
// (gemini/interactions_handlers.go): a "model" with any "models/" prefix
// removed. A request naming an "agent" instead is routed to a fixed provider
// without any model, so it names nothing a policy can decide on.
func interactionsModel(_ *gin.Context, raw []byte) (string, bool) {
	if !gjson.ValidBytes(raw) || repeatsModelKey(raw) {
		return "", false
	}
	root := gjson.ParseBytes(raw)
	if strings.TrimSpace(root.Get("agent").String()) != "" {
		return "", false
	}
	model := strings.TrimSpace(root.Get("model").String())
	if rest, found := strings.CutPrefix(model, "models/"); found && rest != "" {
		model = rest
	}
	return model, model != ""
}

// geminiActionModel is the model of POST /v1beta/models/{model}:{method}
// (gemini/gemini_handlers.go GeminiHandler): the path after /models/, split
// on ":" into exactly two parts, of which the first is the model. The body is
// not read for a model, but a JSON body naming "model" more than once is
// refused like on every other model route.
func geminiActionModel(c *gin.Context, raw []byte) (string, bool) {
	action := strings.Split(strings.TrimPrefix(c.Param("action"), "/"), ":")
	if len(action) != 2 || action[0] == "" {
		return "", false
	}
	if gjson.ValidBytes(raw) && repeatsModelKey(raw) {
		return "", false
	}
	return action[0], true
}

// imageGenerationModel is the model POST /v1/images/generations routes by
// (openai/openai_images_handlers.go ImagesGenerations): the JSON body's
// "model" as imageRouteModel resolves it.
func imageGenerationModel(_ *gin.Context, raw []byte) (string, bool) {
	if !gjson.ValidBytes(raw) || repeatsModelKey(raw) {
		return "", false
	}
	return imageRouteModel(gjson.GetBytes(raw, "model").String()), true
}

// imageEditModel is the model POST /v1/images/edits routes by (ImagesEdits):
// a JSON body is read like a generation; a multipart form, which the handler
// also assumes when there is no Content-Type, gives its "model" field. Gin
// keeps the parsed form on the request, so the handler reads the same one.
func imageEditModel(c *gin.Context, raw []byte) (string, bool) {
	contentType := strings.ToLower(strings.TrimSpace(c.GetHeader("Content-Type")))
	switch {
	case strings.HasPrefix(contentType, "application/json"):
		return imageGenerationModel(c, raw)
	case contentType == "" || strings.HasPrefix(contentType, "multipart/form-data"):
		form, err := c.MultipartForm()
		if err != nil {
			return "", false
		}
		fields := 0
		for key, values := range form.Value {
			if strings.EqualFold(key, "model") {
				fields += len(values)
			}
		}
		if fields > 1 {
			return "", false
		}
		return imageRouteModel(c.PostForm("model")), true
	default:
		return "", false
	}
}

// Image models upstream routes itself (openai_images_handlers.go).
const (
	defaultImageModel    = "gpt-image-2"
	xaiImageModel        = "grok-imagine-image"
	xaiImageQualityModel = "grok-imagine-image-quality"
	xaiImage20Model      = "grok-imagine-image-2.0"
)

// imageRouteModel is the model an image request naming model is routed by:
// gpt-image-2 when it names none; for an xAI image model — its name after the
// last "/" one of xAI's, and before it nothing or an xAI prefix — the
// canonical xAI name upstream sends and routes (canonicalXAIImagesModel);
// otherwise the name as given. Codex tool models, which upstream checks
// first, are never xAI names.
func imageRouteModel(model string) string {
	model = strings.TrimSpace(model)
	if model == "" {
		return defaultImageModel
	}
	prefix, base := "", model
	if i := strings.LastIndex(model, "/"); i >= 0 && i < len(model)-1 {
		prefix, base = strings.TrimSpace(model[:i]), strings.TrimSpace(model[i+1:])
	}
	switch strings.ToLower(prefix) {
	case "", "xai", "x-ai", "grok":
	default:
		return model
	}
	switch strings.ToLower(base) {
	case xaiImageQualityModel:
		return xaiImageQualityModel
	case xaiImage20Model:
		return xaiImage20Model
	case xaiImageModel:
		return xaiImageModel
	default:
		return model
	}
}

// jsonModel is the "model" of a JSON document, read as upstream's handlers
// read it (gjson String). Malformed JSON names no model.
func jsonModel(raw []byte) (string, bool) {
	if !gjson.ValidBytes(raw) || repeatsModelKey(raw) {
		return "", false
	}
	model := gjson.GetBytes(raw, "model").String()
	return model, strings.TrimSpace(model) != ""
}

// repeatsModelKey reports whether the top level of a JSON object has more
// than one key that reads as "model" (unescaped, in any letter case).
// Upstream routes by the first "model" and rewrites only that one, but passes
// the body on otherwise as sent; a vendor whose parser keeps the last
// duplicate, or matches keys regardless of case, would serve another model on
// the credential the first one was admitted for.
func repeatsModelKey(raw []byte) bool {
	n := 0
	gjson.ParseBytes(raw).ForEach(func(key, _ gjson.Result) bool {
		if strings.EqualFold(key.String(), "model") {
			n++
		}
		return n < 2
	})
	return n > 1
}

// claudeDDModelPrefix marks a model ID upstream cloaked for Anthropic clients
// (internal/client/claude/models/models.go).
const claudeDDModelPrefix = "claude-fable-5-dd-"

// decodeClaudeModelID mirrors upstream's ResolveClaudeModelIDPrefix: a
// "claude-fable-5-dd-" ID, with an optional "(suffix)", becomes the reversed
// remainder with the suffix kept.
func decodeClaudeModelID(id string) string {
	base, suffix, hasSuffix := id, "", false
	if open := strings.LastIndex(id, "("); open != -1 && strings.HasSuffix(id, ")") {
		base, suffix, hasSuffix = id[:open], id[open+1:len(id)-1], true
	}
	encoded, found := strings.CutPrefix(base, claudeDDModelPrefix)
	if !found || encoded == "" {
		return id
	}
	runes := []rune(encoded)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	if hasSuffix {
		return string(runes) + "(" + suffix + ")"
	}
	return string(runes)
}
