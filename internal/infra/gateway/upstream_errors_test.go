package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app/mocks"
	"github.com/elleqt/llm-proxy-backend/internal/infra/gateway/faketest"
	"github.com/gin-gonic/gin"
	cliproxyconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	"github.com/stretchr/testify/require"
)

func TestUnknownUpstreamServerErrorsAreMaskedByDefault(t *testing.T) {
	for _, path := range []string{"/v1/chat/completions", "/v1/messages"} {
		t.Run(path, func(t *testing.T) {
			wire := startOnTheWire(t, &faketest.Vendor{FailStatus: http.StatusGatewayTimeout, FailBody: []byte(`<html>private upstream diagnostics</html>`)})
			status, headers, body := errorProbe(t, wire, path)
			require.Equal(t, http.StatusGatewayTimeout, status)
			require.Contains(t, headers.Get("Content-Type"), "application/json")

			var response struct {
				Error struct {
					Message string `json:"message"`
					Code    string `json:"code"`
				} `json:"error"`
			}
			require.NoError(t, json.Unmarshal(body, &response))
			require.Equal(t, "upstream_error", response.Error.Code)
			require.Equal(t, "Upstream error (HTTP 504)", response.Error.Message)
			require.NotContains(t, string(body), "private upstream")
			require.Empty(t, headers.Get("Retry-After"))
		})
	}
}

func errorProbe(t *testing.T, wire *onTheWire, path string) (int, http.Header, []byte) {
	t.Helper()

	payload := fmt.Sprintf(`{"model":%q,"max_tokens":32,"messages":[{"role":"user","content":"hello"}]}`, wire.alias)
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, wire.baseURL+path, strings.NewReader(payload))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+wireSecret)
	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)

	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)

	return response.StatusCode, response.Header, body
}

func TestSelectionErrorMaskingPreservesRetryMetadata(t *testing.T) {
	for _, code := range []string{"auth_unavailable", "internal_server_error"} {
		t.Run(code, func(t *testing.T) {
			engine := gin.New()
			engine.Use(maskUnknownUpstreamErrors(nil))
			engine.GET("/failure", func(c *gin.Context) {
				c.Header("Retry-After", "39")
				c.JSON(http.StatusServiceUnavailable, map[string]any{
					"retry_after_ms": 39000,
					"error": map[string]any{
						"code": code, "type": "server_error",
						"message":        "auth_unavailable: no auth available; last upstream error: <html>private origin details</html>",
						"retry_after_ms": 39000, "retryable": true,
					},
				})
			})

			response := httptest.NewRecorder()
			engine.ServeHTTP(response, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/failure", http.NoBody))
			require.Equal(t, http.StatusServiceUnavailable, response.Code)
			require.Equal(t, "39", response.Header().Get("Retry-After"))

			var body struct {
				RetryAfterMS int `json:"retry_after_ms"`
				Error        struct {
					Code         string `json:"code"`
					RetryAfterMS int    `json:"retry_after_ms"`
					Retryable    bool   `json:"retryable"`
				} `json:"error"`
			}
			require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
			require.Equal(t, "auth_unavailable", body.Error.Code)
			require.Equal(t, 39000, body.Error.RetryAfterMS)
			require.Equal(t, 39000, body.RetryAfterMS)
			require.True(t, body.Error.Retryable)
			require.NotContains(t, response.Body.String(), "<html>")
			require.NotContains(t, response.Body.String(), "private origin details")
		})
	}
}

func TestMaskingCanBeDisabledForOriginalDiagnostics(t *testing.T) {
	visibility := mocks.NewErrorVisibility(t)
	visibility.EXPECT().MaskUnknownErrors().Return(false).Maybe()
	wire := startOnTheWireWith(t, &faketest.Vendor{FailStatus: http.StatusGatewayTimeout, FailBody: []byte(`<html>original diagnostics</html>`)},
		Params{Config: &cliproxyconfig.Config{}, ErrorVisibility: visibility})
	status, _, body := errorProbe(t, wire, "/v1/chat/completions")
	require.Equal(t, http.StatusGatewayTimeout, status)

	var response struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(body, &response))
	require.Equal(t, `<html>original diagnostics</html>`, response.Error.Message)
}

func TestRecognizedServerErrorRemainsIntactOnTheWire(t *testing.T) {
	original := `{"error":{"type":"overloaded_error","code":"rate_limit_exceeded","message":"Retry after the provider recovers","retry_after_ms":39000,"retryable":true}}`
	wire := startOnTheWire(t, &faketest.Vendor{FailStatus: http.StatusServiceUnavailable, FailBody: []byte(original)})
	status, _, body := errorProbe(t, wire, "/v1/chat/completions")
	require.Equal(t, http.StatusServiceUnavailable, status)
	require.JSONEq(t, original, string(body))
}

func TestMaskingUsesStatusAndMachineCodesNotResponseText(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
		masked bool
	}{
		{name: "successful HTML", status: 200, body: `<html>successful payload</html>`},
		{name: "client error", status: 400, body: `<html>client diagnostics</html>`},
		{name: "rate limit", status: 429, body: `{"error":{"type":"rate_limit_error","message":"request is throttled"}}`},
		{name: "unknown JSON", status: 500, body: `{"error":{"type":"server_error","code":"vendor_failure","message":"private diagnostics","retry_after_ms":39000}}`, masked: true},
		{name: "unknown upper boundary", status: 599, body: "private diagnostics", masked: true},
		{name: "outside server class", status: 600, body: "original diagnostics"},
	} {
		t.Run(test.name, func(t *testing.T) {
			engine := gin.New()
			engine.Use(maskUnknownUpstreamErrors(nil))
			engine.GET("/failure", func(c *gin.Context) { c.Data(test.status, "text/plain", []byte(test.body)) })

			response := httptest.NewRecorder()
			engine.ServeHTTP(response, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/failure", http.NoBody))
			require.Equal(t, test.status, response.Code)

			if !test.masked {
				require.Equal(t, test.body, response.Body.String())

				return
			}

			var body struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
			require.Equal(t, "upstream_error", body.Error.Code)
			require.NotContains(t, response.Body.String(), "private diagnostics")
		})
	}
}

func TestSuccessfulStreamFlushesBeforeCompletionAndIsNeverRewritten(t *testing.T) {
	release := make(chan struct{})

	var once sync.Once

	unblock := func() { once.Do(func() { close(release) }) }
	engine := gin.New()
	engine.Use(maskUnknownUpstreamErrors(nil))
	engine.GET("/stream", func(ginCtx *gin.Context) {
		ginCtx.Header("Content-Type", "text/event-stream")
		ginCtx.Status(http.StatusOK)
		_, _ = ginCtx.Writer.WriteString("data: first\n\n")
		ginCtx.Writer.Flush()
		<-release

		_, _ = ginCtx.Writer.WriteString("data: <html>stream diagnostic</html>\n\n")
	})

	server := httptest.NewServer(engine)
	defer server.Close()
	defer unblock()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/stream", http.NoBody)
	require.NoError(t, err)
	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)

	defer func() { _ = response.Body.Close() }()

	require.Equal(t, http.StatusOK, response.StatusCode)
	reader := bufio.NewReader(response.Body)
	first, err := reader.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "data: first\n", first)
	unblock()

	rest, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.Contains(t, string(rest), "<html>stream diagnostic</html>")
}

func TestOversizedUnclassifiedErrorStaysBoundedAndKeepsRetryHeader(t *testing.T) {
	engine := gin.New()
	engine.Use(maskUnknownUpstreamErrors(nil))
	engine.GET("/failure", func(c *gin.Context) {
		c.Header("Retry-After", "39")
		c.Data(http.StatusBadGateway, "text/html", []byte(strings.Repeat("private diagnostics", maxUpstreamErrorBody)))
	})

	response := httptest.NewRecorder()
	engine.ServeHTTP(response, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/failure", http.NoBody))
	require.Equal(t, http.StatusBadGateway, response.Code)
	require.Equal(t, "39", response.Header().Get("Retry-After"))
	require.JSONEq(t, `{"error":{"type":"server_error","code":"upstream_error","message":"Upstream error (HTTP 502)"}}`, response.Body.String())
}

func TestBufferedErrorStringWriteDoesNotRecurse(t *testing.T) {
	engine := gin.New()
	engine.Use(maskUnknownUpstreamErrors(nil))
	engine.GET("/failure", func(ginCtx *gin.Context) {
		ginCtx.Status(http.StatusGatewayTimeout)
		_, _ = ginCtx.Writer.WriteString("private upstream diagnostics")
	})

	response := httptest.NewRecorder()
	engine.ServeHTTP(response, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/failure", http.NoBody))
	require.Equal(t, http.StatusGatewayTimeout, response.Code)
	require.JSONEq(t, `{"error":{"type":"server_error","code":"upstream_error","message":"Upstream error (HTTP 504)"}}`, response.Body.String())
}

func TestConcreteAuthenticationFailureOutranksSelectionPrefix(t *testing.T) {
	original := `{"error":{"type":"authentication_error","code":"upstream_authentication_required","message":"auth_unavailable: credentials need renewal","retryable":false}}`
	engine := gin.New()
	engine.Use(maskUnknownUpstreamErrors(nil))
	engine.GET("/failure", func(ginCtx *gin.Context) {
		ginCtx.Data(http.StatusServiceUnavailable, "application/json", []byte(original))
	})

	response := httptest.NewRecorder()
	engine.ServeHTTP(response, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/failure", http.NoBody))
	require.Equal(t, http.StatusServiceUnavailable, response.Code)
	require.JSONEq(t, original, response.Body.String())
}

func TestSelectionTypeDoesNotLeakNestedDiagnostics(t *testing.T) {
	engine := gin.New()
	engine.Use(maskUnknownUpstreamErrors(nil))
	engine.GET("/failure", func(ginCtx *gin.Context) {
		ginCtx.Header("Retry-After", "39")
		ginCtx.Data(http.StatusServiceUnavailable, "application/json",
			[]byte(`{"error":{"type":"auth_unavailable","message":"private nested diagnostics","retry_after_ms":39000}}`))
	})

	response := httptest.NewRecorder()
	engine.ServeHTTP(response, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/failure", http.NoBody))
	require.Equal(t, "39", response.Header().Get("Retry-After"))
	require.NotContains(t, response.Body.String(), "private nested diagnostics")
	require.JSONEq(t, `{"error":{"type":"auth_unavailable","code":"auth_unavailable","message":"No upstream account is currently available.","retry_after_ms":39000}}`, response.Body.String())
}
