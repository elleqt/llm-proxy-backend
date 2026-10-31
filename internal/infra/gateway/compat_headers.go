package gateway

import (
	"net/http"
	"strings"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// compatHeadersFor never carries saved header secrets to an edited destination.
// A non-nil input is an explicit replacement, including an empty map.
func compatHeadersFor(held *coreauth.Auth, baseURL string, headers map[string]string) (map[string]string, error) {
	if headers != nil || held == nil {
		return headers, nil
	}

	headers = coreauth.ExtractCustomHeadersFromMetadata(held.Metadata)

	storedURL, _ := held.Metadata[compatMetaBaseURL].(string)
	if len(headers) > 0 && strings.TrimRight(storedURL, "/") != strings.TrimRight(baseURL, "/") {
		return nil, &app.InvalidInputError{Field: "headers"}
	}

	return headers, nil
}

// applyDiscoveryHeaders omits unresolved variables: discovery has no conversation.
// Inference expansion remains exclusively owned by the upstream executor.
func applyDiscoveryHeaders(req *http.Request, apiKey string, headers map[string]string) {
	req.Header.Set("Accept", "application/json")

	for name, value := range headers {
		if strings.HasPrefix(value, "$") || strings.Contains(strings.ToUpper(value), "$CPA-SESSION-ID") {
			continue
		}

		req.Header.Set(name, value)
	}

	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
}
