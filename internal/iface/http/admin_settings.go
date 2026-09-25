package http

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/app/settings"
	"github.com/elleqt/llm-proxy-backend/internal/iface/http/api"
)

func (rt *router) registerAdminSettings(routes map[string]http.HandlerFunc) {
	routes["GET /api/admin/settings"] = rt.getSettings
	routes["PUT /api/admin/settings"] = rt.updateSettings
	routes["GET /api/admin/prices"] = rt.getPrices
	routes["PUT /api/admin/prices"] = rt.replacePrices
	routes["POST /api/admin/prices/refresh"] = rt.refreshPriceCatalog
}

// getSettings answers the stored document as it is, credentials included: it is the
// administrator's to edit, and a redacted copy sent back whole would overwrite them.
func (rt *router) getSettings(rw http.ResponseWriter, req *http.Request) {
	c, _ := callerFrom(req.Context())

	view, err := rt.Settings.Get(req.Context(), c.user)
	if err != nil {
		rt.adminFailure(rw, req, err)

		return
	}

	writeJSON(rw, http.StatusOK, settingsOf(view))
}

func (rt *router) updateSettings(rw http.ResponseWriter, req *http.Request) {
	actor, _ := callerFrom(req.Context())

	var body api.SettingsUpdateRequest
	if !decodeJSON(rw, req, &body) {
		return
	}

	update := settings.Update{YAML: body.Yaml, DryRun: body.DryRun != nil && *body.DryRun}
	if f := body.Fields; f != nil {
		update.Fields = &settings.Patch{ProxyURL: f.ProxyURL, RequestRetry: f.RequestRetry, MaxRetryInterval: f.MaxRetryInterval}
	}

	res, err := rt.Settings.Update(req.Context(), actor.user, update)
	if err != nil {
		rt.adminFailure(rw, req, err)

		return
	}

	writeJSON(rw, http.StatusOK, api.SettingsUpdateResult{Applied: res.Applied, Diff: res.Diff, Settings: settingsOf(res.Settings)})
}

func settingsOf(v settings.View) api.Settings {
	f := v.Fields
	out := api.Settings{Yaml: v.YAML}
	out.Fields.ProxyURL = &f.ProxyURL
	out.Fields.RequestRetry = &f.RequestRetry
	out.Fields.MaxRetryInterval = &f.MaxRetryInterval

	return out
}

func (rt *router) getPrices(rw http.ResponseWriter, req *http.Request) {
	c, _ := callerFrom(req.Context())

	list, err := rt.Prices.Get(req.Context(), c.user)
	if err != nil {
		rt.adminFailure(rw, req, err)

		return
	}

	writeJSON(rw, http.StatusOK, priceListOf(list))
}

// replacePrices makes the body the whole manual override list. A body of null is
// not a list: clearing every override takes an explicit [].
func (rt *router) replacePrices(rw http.ResponseWriter, req *http.Request) {
	actor, _ := callerFrom(req.Context())

	var body api.ReplacePricesJSONRequestBody
	if !decodeJSON(rw, req, &body) {
		return
	}

	if body == nil {
		writeError(rw, http.StatusUnprocessableEntity, codeInvalidInput, "the price list must be an array")

		return
	}

	list := make([]app.ModelPrice, 0, len(body))
	for _, p := range body {
		list = append(list, app.ModelPrice{
			Provider: p.Provider, Model: p.Model,
			Input: p.Input, Output: p.Output, CacheRead: p.CacheRead, CacheWrite: p.CacheWrite,
		})
	}

	stored, err := rt.Prices.Replace(req.Context(), actor.user, list)
	if err != nil {
		rt.adminFailure(rw, req, err)

		return
	}

	writeJSON(rw, http.StatusOK, priceListOf(stored))
}

// refreshWriteTime is how long POST /api/admin/prices/refresh may take to answer:
// the check may first wait for a scheduled one in flight, then fetch the catalog
// itself, each up to app.CatalogFetchTimeout, and then store it. The server-wide
// write timeout is far shorter, and this one route is given more.
const refreshWriteTime = 2*app.CatalogFetchTimeout + time.Minute

// refreshPriceCatalog checks the catalog now. A failed check is still a 200: its
// reason is in catalog.lastError.
func (rt *router) refreshPriceCatalog(rw http.ResponseWriter, req *http.Request) {
	if err := http.NewResponseController(rw).SetWriteDeadline(time.Now().Add(refreshWriteTime)); err != nil &&
		!errors.Is(err, http.ErrNotSupported) {
		rt.Log.Warn("extending the write deadline failed",
			slog.String("method", req.Method), slog.String("path", req.URL.Path), slog.Any("err", err))
	}

	c, _ := callerFrom(req.Context())

	list, err := rt.Prices.Refresh(req.Context(), c.user)
	if err != nil {
		rt.adminFailure(rw, req, err)

		return
	}

	writeJSON(rw, http.StatusOK, priceListOf(list))
}

func priceListOf(list app.PriceList) api.PriceList {
	prices := make([]api.PriceEntry, 0, len(list.Prices))
	for _, price := range list.Prices {
		entry := api.PriceEntry{
			Provider: price.Provider, Model: price.Model,
			Input: price.Input, Output: price.Output, CacheRead: price.CacheRead, CacheWrite: price.CacheWrite,
			Source: api.PriceEntrySource(price.Source), UpdatedAt: price.UpdatedAt,
		}
		if c := price.Catalog; c != nil {
			entry.CatalogRates = &api.PriceRates{Input: c.Input, Output: c.Output, CacheRead: c.CacheRead, CacheWrite: c.CacheWrite}
		}

		prices = append(prices, entry)
	}

	state := list.Catalog

	catalog := api.PriceCatalog{Enabled: state.Enabled, Models: state.Models}
	if !state.CheckedAt.IsZero() {
		catalog.CheckedAt = &state.CheckedAt
	}

	if !state.ChangedAt.IsZero() {
		catalog.ChangedAt = &state.ChangedAt
	}

	if state.LastError != "" {
		catalog.LastError = &state.LastError
	}

	return api.PriceList{Prices: prices, Catalog: catalog}
}
