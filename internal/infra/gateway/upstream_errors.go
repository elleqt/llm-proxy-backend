package gateway

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/gin-gonic/gin"
)

// Only error responses are buffered. Successful responses, including SSE, are
// written directly; an already committed response can never be rewritten.
const maxUpstreamErrorBody = 64 << 10

const upstreamErrorEnvelopeType = "error"

const (
	upstreamAuthUnavailable = "auth_unavailable"
	upstreamAuthNotFound    = "auth_not_found"
)

func maskUnknownUpstreamErrors(visibility app.ErrorVisibility) gin.HandlerFunc {
	return func(ginCtx *gin.Context) {
		if visibility != nil && !visibility.MaskUnknownErrors() {
			ginCtx.Next()

			return
		}

		original := ginCtx.Writer
		writer := &upstreamErrorWriter{ResponseWriter: original}

		ginCtx.Writer = writer
		defer func() { ginCtx.Writer = original }()

		ginCtx.Next()
		writer.finish(ginCtx.FullPath())
	}
}

type upstreamErrorWriter struct {
	gin.ResponseWriter

	body     []byte
	overflow bool
	begun    bool
}

func (w *upstreamErrorWriter) WriteHeader(status int) {
	if !w.begun {
		w.ResponseWriter.WriteHeader(status)
	}
}

func (w *upstreamErrorWriter) WriteHeaderNow() {
	if w.capturing() {
		w.begun = true

		return
	}

	w.ResponseWriter.WriteHeaderNow()
}

//nolint:wrapcheck // Transparent writer forwarding must preserve the underlying I/O error.
func (w *upstreamErrorWriter) Write(body []byte) (int, error) {
	if !w.capturing() {
		return w.ResponseWriter.Write(body)
	}

	w.begun = true

	remaining := maxUpstreamErrorBody - len(w.body)
	if len(body) > remaining {
		w.overflow = true
	}

	w.body = append(w.body, body[:min(len(body), remaining)]...)

	return len(body), nil
}

//nolint:wrapcheck // Transparent writer forwarding must preserve the underlying I/O error.
func (w *upstreamErrorWriter) WriteString(body string) (int, error) {
	if !w.capturing() {
		return w.ResponseWriter.WriteString(body)
	}

	w.begun = true

	remaining := maxUpstreamErrorBody - len(w.body)
	if len(body) > remaining {
		w.overflow = true
	}

	w.body = append(w.body, body[:min(len(body), remaining)]...)

	return len(body), nil
}

func (w *upstreamErrorWriter) Written() bool { return w.begun || w.ResponseWriter.Written() }

func (w *upstreamErrorWriter) Size() int {
	if w.begun {
		return len(w.body)
	}

	return w.ResponseWriter.Size()
}

func (w *upstreamErrorWriter) Flush() {
	if w.capturing() {
		w.begun = true

		return
	}

	w.ResponseWriter.Flush()
}

func (w *upstreamErrorWriter) capturing() bool {
	status := w.Status()

	return status >= http.StatusInternalServerError && status <= 599 && !w.ResponseWriter.Written()
}

func (w *upstreamErrorWriter) finish(path string) {
	if !w.capturing() {
		return
	}

	body, changed := normalizedUpstreamError(w.body, w.Status(), strings.HasPrefix(path, "/v1/messages"), w.overflow)
	if changed {
		headers := w.Header()
		headers.Del("Content-Length")
		headers.Del("Content-Encoding")
		headers.Set("Content-Type", "application/json")
	}

	w.ResponseWriter.WriteHeaderNow()
	_, _ = w.ResponseWriter.Write(body)
}

// Retry metadata is copied as JSON, not interpreted or regenerated. The HTTP
// Retry-After header is never changed by this middleware.
type retryMetadata struct {
	Retryable         json.RawMessage `json:"retryable,omitempty"`
	RetryAfter        json.RawMessage `json:"retry_after,omitempty"`
	RetryAfterMS      json.RawMessage `json:"retry_after_ms,omitempty"`
	RetryAfterCamel   json.RawMessage `json:"retryAfter,omitempty"`
	RetryAfterMSCamel json.RawMessage `json:"retryAfterMs,omitempty"`
}

type upstreamErrorDetail struct {
	retryMetadata

	Code    string `json:"code,omitempty"`
	Type    string `json:"type"`
	Message string `json:"message"`
}

type upstreamErrorEnvelope struct {
	retryMetadata

	Type  string              `json:"type,omitempty"`
	Error upstreamErrorDetail `json:"error"`
}

func normalizedUpstreamError(body []byte, status int, anthropic, overflow bool) ([]byte, bool) {
	var payload upstreamErrorEnvelope

	valid := !overflow && json.Unmarshal(body, &payload) == nil

	selection := ""
	if valid {
		selection = authSelectionErrorCode(payload.Error)
		if selection == "" && recognizedUpstreamError(payload.Error, status) {
			return body, false
		}
	} else {
		payload = upstreamErrorEnvelope{}
	}

	errorType := "server_error"
	if anthropic {
		errorType = "api_error"
		payload.Type = upstreamErrorEnvelopeType
	} else if selection == "" {
		payload.Type = ""
	}

	if selection == "" || payload.Error.Type == "" {
		payload.Error.Type = errorType
	}

	if selection != "" {
		payload.Error.Code = selection
		payload.Error.Message = "No upstream account is currently available."
	} else {
		payload.Error.Code = "upstream_error"
		payload.Error.Message = "Upstream error (HTTP " + strconv.Itoa(status) + ")"
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		return maskedUpstreamError(status, anthropic), true
	}

	return encoded, true
}

// Selection wrappers can contain an unclassified nested cause. Preserve their
// public machine code and retry metadata, but render the known selection reason
// without copying the nested diagnostic. SDK Error.Error uses this exact prefix.
func authSelectionErrorCode(detail upstreamErrorDetail) string {
	if detail.Code == upstreamAuthUnavailable || detail.Code == upstreamAuthNotFound {
		return detail.Code
	}

	if recognizedErrorKind(detail.Code) {
		return ""
	}

	if detail.Type == upstreamAuthUnavailable || detail.Type == upstreamAuthNotFound {
		return detail.Type
	}

	if recognizedErrorKind(detail.Type) {
		return ""
	}

	for _, code := range []string{upstreamAuthUnavailable, upstreamAuthNotFound} {
		if strings.HasPrefix(detail.Message, code+":") {
			return code
		}
	}

	return ""
}

// Generic status-derived types do not prove that upstream classified its body.
// Only exact machine-readable identifiers are considered, never HTML or prose.
func recognizedUpstreamError(detail upstreamErrorDetail, status int) bool {
	if recognizedErrorKind(detail.Code) {
		return true
	}

	if status == http.StatusGatewayTimeout && detail.Type == "timeout_error" ||
		status == 529 && detail.Type == "overloaded_error" {
		return false
	}

	return recognizedErrorKind(detail.Type)
}

func recognizedErrorKind(kind string) bool {
	switch kind {
	case "overloaded_error", "rate_limit_error", "rate_limit_exceeded", "quota_exceeded", "usage_limit_reached", "insufficient_quota",
		"context_length_exceeded", "context_too_large", "invalid_request_error", "authentication_error", "permission_error", "invalid_api_key",
		upstreamAuthUnavailable, upstreamAuthNotFound, "upstream_authentication_required",
		"model_cooldown", "model_not_found", "model_not_supported",
		"request_timeout", "timeout_error", "previous_response_not_found", "thinking_signature_invalid", "thread_not_found",
		"credential_concurrency_exceeded", "request_scoped", "transient_transport", "connection_lifecycle":
		return true
	default:
		return false
	}
}

func maskedUpstreamError(status int, anthropic bool) []byte {
	var body []byte
	if anthropic {
		body = append(body, `{"type":"error","error":{"type":"api_error","code":"upstream_error","message":"Upstream error (HTTP `...)
	} else {
		body = append(body, `{"error":{"type":"server_error","code":"upstream_error","message":"Upstream error (HTTP `...)
	}

	body = strconv.AppendInt(body, int64(status), 10)

	return append(body, `)"}}`...)
}
