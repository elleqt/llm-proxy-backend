package gateway

import (
	"strings"

	"github.com/gin-gonic/gin"
)

// routeKind is what the policy gate does with a request on a route.
type routeKind int

const (
	// routeDenied answers 404 before upstream sees the request.
	routeDenied routeKind = iota
	// routePublic is the service's own unauthenticated route.
	routePublic
	// routeListing needs an active token; its response is cut down to the
	// models the owner's policy allows (see listing).
	routeListing
	// routeModel needs an active token and a policy allowing the model the
	// request names on every provider serving it.
	routeModel
)

// route is one classified route: its kind; for a model route, where the model
// is read from, how large a body may be and whether an encoded body is
// decoded for its handler; for a listing, which models its response names.
type route struct {
	kind  routeKind
	model modelSource
	// maxBody bounds the body as sent and, decoded, as the handler gets it.
	maxBody int64
	// maxMultipartBody, when set, bounds a multipart body instead.
	maxMultipartBody int64
	// decodes reports whether the route's handler would decode a request's
	// Content-Encoding (through handlers.ReadRequestBody); nil means never.
	// Only then does the gate decode an encoded body; otherwise it refuses
	// it (see encoding.go).
	decodes func(c *gin.Context) bool
	listing listing
}

// Request body limits of model routes, applied before the gate reads a body.
// Multipart image edits carry the images themselves.
const (
	maxJSONBody      int64 = 64 << 20
	maxMultipartBody int64 = 256 << 20
)

// always and jsonContent are route.decodes values: upstream's image-edit
// handler decodes only a JSON body (openai_images_handlers.go ImagesEdits).
func always(*gin.Context) bool { return true }

func jsonContent(c *gin.Context) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(c.GetHeader("Content-Type"))), "application/json")
}

// bodyLimitFor is r's bound on c's body.
func (r route) bodyLimitFor(c *gin.Context) int64 {
	if r.maxMultipartBody > 0 && !jsonContent(c) {
		return r.maxMultipartBody
	}
	return r.maxBody
}

// routes classifies every route upstream v7.3.15 registers on its engine
// (internal/api/server_routes.go setupRoutes, and AttachWebsocketRoute from
// sdk/cliproxy/service_lifecycle.go), keyed by method and gin route pattern.
// A request whose route is absent — including an unrouted path — is denied
// like a routeDenied one. TestEveryUpstreamRouteIsClassified fails when
// upstream registers a route missing here, so an upgrade cannot open one.
//
// A model route is admitted only when the model the policy decides on is the
// model upstream routes by; every route where they can differ, or where no
// model is named, is denied.
var routes = map[string]route{
	// The service's own liveness probe.
	"GET /healthz":  {kind: routePublic},
	"HEAD /healthz": {kind: routePublic},

	// Model listings (see listing.go): OpenAI, Anthropic, Codex and Grok
	// clients on one route, Gemini's list, and a single Gemini model.
	"GET /v1/models":             {kind: routeListing, listing: v1Models},
	"GET /v1beta/models":         {kind: routeListing, listing: geminiModels},
	"GET /v1beta/models/*action": {kind: routeListing, listing: geminiModel},

	// Requests routed by the model they name.
	"POST /v1/chat/completions":                 {kind: routeModel, model: bodyModel, maxBody: maxJSONBody, decodes: always},
	"POST /v1/completions":                      {kind: routeModel, model: bodyModel, maxBody: maxJSONBody, decodes: always},
	"POST /v1/responses":                        {kind: routeModel, model: bodyModel, maxBody: maxJSONBody, decodes: always},
	"POST /v1/responses/compact":                {kind: routeModel, model: bodyModel, maxBody: maxJSONBody, decodes: always},
	"POST /backend-api/codex/responses":         {kind: routeModel, model: bodyModel, maxBody: maxJSONBody, decodes: always},
	"POST /backend-api/codex/responses/compact": {kind: routeModel, model: bodyModel, maxBody: maxJSONBody, decodes: always},
	"POST /v1/messages":                         {kind: routeModel, model: claudeModel, maxBody: maxJSONBody},
	"POST /v1/messages/count_tokens":            {kind: routeModel, model: claudeModel, maxBody: maxJSONBody},
	"POST /v1beta/models/*action":               {kind: routeModel, model: geminiActionModel, maxBody: maxJSONBody},
	"POST /v1beta/interactions":                 {kind: routeModel, model: interactionsModel, maxBody: maxJSONBody},
	"POST /v1/images/generations":               {kind: routeModel, model: imageGenerationModel, maxBody: maxJSONBody, decodes: always},
	"POST /v1/images/edits":                     {kind: routeModel, model: imageEditModel, maxBody: maxJSONBody, maxMultipartBody: maxMultipartBody, decodes: jsonContent},

	// Denied: the websocket relay, through which a connecting client
	// registers itself as an "aistudio" provider account and is then sent
	// other users' requests.
	"GET /v1/ws": {kind: routeDenied},

	// Denied: Responses over a websocket. Each message names its own model
	// after the upgrade, where the gate cannot see it.
	"GET /v1/responses":                {kind: routeDenied},
	"GET /backend-api/codex/responses": {kind: routeDenied},

	// Denied: Codex live and realtime. They mint client secrets that
	// authenticate later requests without the access provider and outlive a
	// revoked token or a blocked owner, and carry sessions whose models the
	// gate cannot see.
	"POST /v1/live":                                 {kind: routeDenied},
	"GET /v1/live/:call_id":                         {kind: routeDenied},
	"GET /v1/realtime":                              {kind: routeDenied},
	"POST /v1/realtime":                             {kind: routeDenied},
	"POST /v1/realtime/calls":                       {kind: routeDenied},
	"GET /v1/realtime/calls/:call_id":               {kind: routeDenied},
	"POST /v1/realtime/client_secrets":              {kind: routeDenied},
	"POST /v1/realtime/sessions":                    {kind: routeDenied},
	"POST /v1/realtime/transcription_sessions":      {kind: routeDenied},
	"GET /v1/realtime/translations":                 {kind: routeDenied},
	"POST /v1/realtime/translations":                {kind: routeDenied},
	"POST /v1/realtime/translations/client_secrets": {kind: routeDenied},
	"POST /v1/realtime/calls/:call_id/hangup":       {kind: routeDenied},
	"POST /v1/realtime/calls/:call_id/accept":       {kind: routeDenied},
	"POST /v1/realtime/calls/:call_id/reject":       {kind: routeDenied},
	"POST /v1/realtime/calls/:call_id/refer":        {kind: routeDenied},

	// Denied: Codex alpha search always goes to a codex account, whichever
	// provider serves the model it names.
	"POST /v1/alpha/search":                {kind: routeDenied},
	"POST /backend-api/codex/alpha/search": {kind: routeDenied},

	// Denied: video generation. Retrieving a result names no model, so half
	// of each workflow could not be decided on.
	"POST /v1/videos":                         {kind: routeDenied},
	"POST /v1/videos/generations":             {kind: routeDenied},
	"POST /v1/videos/edits":                   {kind: routeDenied},
	"POST /v1/videos/extensions":              {kind: routeDenied},
	"GET /v1/videos/:request_id":              {kind: routeDenied},
	"POST /openai/v1/videos":                  {kind: routeDenied},
	"GET /openai/v1/videos/:video_id":         {kind: routeDenied},
	"GET /openai/v1/videos/:video_id/content": {kind: routeDenied},

	// Denied: upstream's banner, its management panel, and the OAuth
	// callbacks of logins its management API starts, which write into the
	// auth directory.
	"GET /":                     {kind: routeDenied},
	"GET /management.html":      {kind: routeDenied},
	"GET /anthropic/callback":   {kind: routeDenied},
	"GET /codex/callback":       {kind: routeDenied},
	"GET /antigravity/callback": {kind: routeDenied},
	"GET /callback":             {kind: routeDenied},
	"GET /devin/callback":       {kind: routeDenied},
}

// classify returns the route registered for method and gin route pattern. The
// zero route, for an unrouted request (empty pattern) or an unlisted route, is
// denied.
func classify(method, pattern string) route {
	return routes[method+" "+pattern]
}
