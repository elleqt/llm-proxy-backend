package http

import (
	"net/http"

	"github.com/elleqt/llm-proxy-backend/internal/iface/http/api"
)

// getConnectInfo tells the cabinet where the proxied API is, so its connection
// instructions (the client holds the per-tool templates) name the right address.
func (rt *router) getConnectInfo(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, api.ConnectInfo{ApiBaseURL: rt.PublicAPIURL})
}
