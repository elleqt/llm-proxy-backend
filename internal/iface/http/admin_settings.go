package http

import (
	"net/http"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/iface/http/api"
)

func (rt *router) registerAdminSettings(routes map[string]http.HandlerFunc) {
	routes["GET /api/admin/settings"] = rt.getSettings
	routes["PUT /api/admin/settings"] = rt.updateSettings
	routes["GET /api/admin/prices"] = rt.getPrices
	routes["PUT /api/admin/prices"] = rt.replacePrices
}

// getSettings answers the stored document as it is, credentials included: it is the
// administrator's to edit, and a redacted copy sent back whole would overwrite them.
func (rt *router) getSettings(w http.ResponseWriter, r *http.Request) {
	c, _ := callerFrom(r.Context())
	v, err := rt.Settings.Get(r.Context(), c.user)
	if err != nil {
		rt.adminFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, settingsOf(v))
}

func (rt *router) updateSettings(w http.ResponseWriter, r *http.Request) {
	c, _ := callerFrom(r.Context())
	var body api.SettingsUpdateRequest
	if !decodeJSON(w, r, &body) {
		return
	}
	req := app.SettingsUpdate{YAML: body.Yaml, DryRun: body.DryRun != nil && *body.DryRun}
	if f := body.Fields; f != nil {
		req.Fields = &app.SettingsPatch{ProxyURL: f.ProxyURL, RequestRetry: f.RequestRetry, MaxRetryInterval: f.MaxRetryInterval}
	}
	res, err := rt.Settings.Update(r.Context(), c.user, req)
	if err != nil {
		rt.adminFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, api.SettingsUpdateResult{Applied: res.Applied, Diff: res.Diff, Settings: settingsOf(res.Settings)})
}

func settingsOf(v app.SettingsView) api.Settings {
	f := v.Fields
	out := api.Settings{Yaml: v.YAML}
	out.Fields.ProxyURL = &f.ProxyURL
	out.Fields.RequestRetry = &f.RequestRetry
	out.Fields.MaxRetryInterval = &f.MaxRetryInterval
	return out
}

func (rt *router) getPrices(w http.ResponseWriter, r *http.Request) {
	c, _ := callerFrom(r.Context())
	list, err := rt.Prices.Get(r.Context(), c.user)
	if err != nil {
		rt.adminFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, pricesOf(list))
}

// replacePrices makes the body the whole price list. A body of null is not a list:
// clearing every price takes an explicit [].
func (rt *router) replacePrices(w http.ResponseWriter, r *http.Request) {
	c, _ := callerFrom(r.Context())
	var body api.ReplacePricesJSONRequestBody
	if !decodeJSON(w, r, &body) {
		return
	}
	if body == nil {
		writeError(w, http.StatusUnprocessableEntity, codeInvalidInput, "the price list must be an array")
		return
	}
	list := make([]app.ModelPrice, 0, len(body))
	for _, p := range body {
		list = append(list, app.ModelPrice{
			Provider: p.Provider, Model: p.Model,
			Input: p.Input, Output: p.Output, CacheRead: p.CacheRead, CacheWrite: p.CacheWrite,
		})
	}
	stored, err := rt.Prices.Replace(r.Context(), c.user, list)
	if err != nil {
		rt.adminFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, pricesOf(stored))
}

func pricesOf(list []app.ModelPrice) []api.ModelPrice {
	out := make([]api.ModelPrice, 0, len(list))
	for _, p := range list {
		out = append(out, api.ModelPrice{
			Provider: p.Provider, Model: p.Model,
			Input: p.Input, Output: p.Output, CacheRead: p.CacheRead, CacheWrite: p.CacheWrite,
		})
	}
	return out
}
