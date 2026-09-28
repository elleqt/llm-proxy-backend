package http

import (
	"net/http"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/iface/http/api"
)

// getConfig tells the cabinet the deployment's settings it is rendered with:
// where the proxied API is, for the connection instructions (the client holds the
// per-tool templates), and whether the caller is shown costs in US dollars.
func (rt *router) getConfig(rw http.ResponseWriter, req *http.Request) {
	actor, _ := callerFrom(req.Context())
	writeJSON(rw, http.StatusOK, api.Config{ApiBaseURL: rt.PublicAPIURL, CostsVisible: rt.Display.CostsVisibleTo(actor.user)})
}

func (rt *router) getAdminConfig(rw http.ResponseWriter, req *http.Request) {
	actor, _ := callerFrom(req.Context())

	cfg, err := rt.Display.Get(actor.user)
	if err != nil {
		rt.adminFailure(rw, req, err)

		return
	}

	writeJSON(rw, http.StatusOK, api.AdminConfig{CostsVisible: cfg.CostsVisible})
}

func (rt *router) replaceAdminConfig(rw http.ResponseWriter, req *http.Request) {
	actor, _ := callerFrom(req.Context())

	var body api.AdminConfig
	if !decodeJSON(rw, req, &body) {
		return
	}

	cfg, err := rt.Display.Set(req.Context(), actor.user, app.DisplayConfig{CostsVisible: body.CostsVisible})
	if err != nil {
		rt.adminFailure(rw, req, err)

		return
	}

	writeJSON(rw, http.StatusOK, api.AdminConfig{CostsVisible: cfg.CostsVisible})
}
