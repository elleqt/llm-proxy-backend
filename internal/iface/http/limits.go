package http

import (
	"net/http"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app/spendlimits"
	"github.com/elleqt/llm-proxy-backend/internal/domain/limits"
	"github.com/elleqt/llm-proxy-backend/internal/iface/http/api"
)

func (rt *router) registerLimits(routes map[string]http.HandlerFunc) {
	routes["GET /api/me/limits"] = rt.getMyLimits
	routes["GET /api/admin/limits"] = rt.getDefaultLimits
	routes["PUT /api/admin/limits"] = rt.replaceDefaultLimits
	routes["GET /api/admin/users/{userId}/limits"] = rt.getUserLimits
	routes["PUT /api/admin/users/{userId}/limits"] = rt.setUserLimits
	routes["POST /api/admin/users/{userId}/limits/reset"] = rt.resetUserLimits
}

// getMyLimits shows the caller each window's share of its limit, and the amounts
// in US dollars only when the caller may see costs.
func (rt *router) getMyLimits(rw http.ResponseWriter, req *http.Request) {
	actor, _ := callerFrom(req.Context())

	view, err := rt.Limits.Mine(req.Context(), actor.user)
	if err != nil {
		writeAppError(rw, req, rt.Log, err)

		return
	}

	costs := rt.Display.CostsVisibleTo(actor.user)

	out := api.MySpendLimits{Windows: make([]api.MySpendWindow, 0, len(view.Windows))}
	for _, state := range view.Windows {
		started, resets := liveSpan(state)

		window := api.MySpendWindow{
			WindowMinutes: int(state.Rule.Window / time.Minute), SpentPercent: state.SpentPercent(),
			StartedAt: started, ResetsAt: resets, Exhausted: state.Exhausted,
		}
		if costs {
			window.AmountUsd, window.SpentUsd = &state.Rule.AmountUSD, &state.SpentUSD
		}

		out.Windows = append(out.Windows, window)
	}

	writeJSON(rw, http.StatusOK, out)
}

func (rt *router) getDefaultLimits(rw http.ResponseWriter, req *http.Request) {
	actor, _ := callerFrom(req.Context())

	set, err := rt.Limits.Defaults(actor.user)
	if err != nil {
		rt.adminFailure(rw, req, err)

		return
	}

	writeJSON(rw, http.StatusOK, spendLimitList(set))
}

func (rt *router) replaceDefaultLimits(rw http.ResponseWriter, req *http.Request) {
	actor, _ := callerFrom(req.Context())

	var body api.ReplaceDefaultLimitsJSONRequestBody
	if !decodeJSON(rw, req, &body) {
		return
	}

	set, err := rt.Limits.SetDefaults(req.Context(), actor.user, setOf(body))
	if err != nil {
		rt.adminFailure(rw, req, err)

		return
	}

	writeJSON(rw, http.StatusOK, spendLimitList(set))
}

func (rt *router) getUserLimits(rw http.ResponseWriter, req *http.Request) {
	actor, _ := callerFrom(req.Context())

	id, ok := pathID(rw, req, "userId")
	if !ok {
		return
	}

	view, err := rt.Limits.ForUser(req.Context(), actor.user, id)
	if err != nil {
		rt.adminFailure(rw, req, err)

		return
	}

	writeJSON(rw, http.StatusOK, spendLimitsOf(view))
}

// setUserLimits reads the mode as the contract pairs it with limits: custom
// needs the list (an empty one meaning no limits), default refuses it. A missing
// or unknown mode, or limits wrongly paired with it, is refused before the
// service is asked.
func (rt *router) setUserLimits(rw http.ResponseWriter, req *http.Request) {
	actor, _ := callerFrom(req.Context())

	id, ok := pathID(rw, req, "userId")
	if !ok {
		return
	}

	var body api.SetUserLimitsJSONRequestBody
	if !decodeJSON(rw, req, &body) {
		return
	}

	var custom *limits.Set

	switch body.Mode {
	case api.SpendLimitsUpdateModeCustom:
		if body.Limits == nil {
			writeFieldError(rw, http.StatusUnprocessableEntity, codeInvalidInput, "limits", "custom mode needs limits")

			return
		}

		set := setOf(*body.Limits)
		custom = &set
	case api.SpendLimitsUpdateModeDefault:
		if body.Limits != nil {
			writeFieldError(rw, http.StatusUnprocessableEntity, codeInvalidInput, "limits", "default mode takes no limits")

			return
		}
	default:
		writeFieldError(rw, http.StatusUnprocessableEntity, codeInvalidInput, "mode", "mode must be custom or default")

		return
	}

	view, err := rt.Limits.SetUser(req.Context(), actor.user, id, custom)
	if err != nil {
		rt.adminFailure(rw, req, err)

		return
	}

	writeJSON(rw, http.StatusOK, spendLimitsOf(view))
}

func (rt *router) resetUserLimits(rw http.ResponseWriter, req *http.Request) {
	actor, _ := callerFrom(req.Context())

	id, ok := pathID(rw, req, "userId")
	if !ok {
		return
	}

	var body api.ResetUserLimitsJSONRequestBody
	if !decodeJSON(rw, req, &body) {
		return
	}

	var window *time.Duration

	if body.WindowMinutes != nil {
		w := windowOf(*body.WindowMinutes)
		window = &w
	}

	view, err := rt.Limits.Reset(req.Context(), actor.user, id, window)
	if err != nil {
		rt.adminFailure(rw, req, err)

		return
	}

	writeJSON(rw, http.StatusOK, spendLimitsOf(view))
}

// maxWindowMinutes is limits.MaxWindow in the contract's whole minutes.
const maxWindowMinutes = int(limits.MaxWindow / time.Minute)

// windowOf converts a client's minutes. A value out of the contract's range is
// checked before it is multiplied, since a large one would wrap round to a valid
// duration, and becomes one just past the range, which validation then names.
func windowOf(minutes int) time.Duration {
	if minutes < 1 || minutes > maxWindowMinutes {
		return limits.MaxWindow + time.Minute
	}

	return time.Duration(minutes) * time.Minute
}

func setOf(body []api.SpendLimit) limits.Set {
	set := make(limits.Set, 0, len(body))
	for _, l := range body {
		set = append(set, limits.Rule{Window: windowOf(l.WindowMinutes), AmountUSD: l.AmountUsd})
	}

	return set
}

// spendLimitList writes a set as the contract's list; an empty set is [].
func spendLimitList(set limits.Set) []api.SpendLimit {
	out := make([]api.SpendLimit, 0, len(set))
	for _, r := range set {
		out = append(out, api.SpendLimit{WindowMinutes: int(r.Window / time.Minute), AmountUsd: r.AmountUSD})
	}

	return out
}

// spendLimitsOf writes a view as the contract's SpendLimits: custom is [] in
// default mode, and a rule with no live window has null timestamps.
func spendLimitsOf(view spendlimits.View) api.SpendLimits {
	out := api.SpendLimits{
		Mode: api.SpendLimitsModeDefault, Custom: []api.SpendLimit{}, Windows: make([]api.SpendWindow, 0, len(view.Windows)),
	}
	if view.Custom != nil {
		out.Mode, out.Custom = api.SpendLimitsModeCustom, spendLimitList(*view.Custom)
	}

	for _, state := range view.Windows {
		started, resets := liveSpan(state)
		out.Windows = append(out.Windows, api.SpendWindow{
			WindowMinutes: int(state.Rule.Window / time.Minute), AmountUsd: state.Rule.AmountUSD,
			SpentUsd: state.SpentUSD, SpentPercent: state.SpentPercent(), StartedAt: started, ResetsAt: resets,
			Exhausted: state.Exhausted,
		})
	}

	return out
}

// liveSpan is a window's start and reset in UTC, both nil when none is live.
func liveSpan(state limits.WindowState) (*time.Time, *time.Time) {
	if state.StartedAt.IsZero() {
		return nil, nil
	}

	started, resets := state.StartedAt.UTC(), state.ResetsAt.UTC()

	return &started, &resets
}
