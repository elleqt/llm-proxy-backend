package http

import (
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
)

// maxBodyBytes caps every request body. The largest body this API accepts is a
// handful of short strings; 1 MiB is generous and still bounds what a client can make
// the server buffer.
const maxBodyBytes = 1 << 20

// maxUserAgentBytes bounds the User-Agent copied onto a session row and an audit row.
const maxUserAgentBytes = 512

// recoverPanics turns a handler panic into the contract's 500 instead of a dropped
// connection, and logs it. http.ErrAbortHandler is re-raised: it is the standard
// library's way of aborting a response on purpose.
func recoverPanics(log app.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				log.Warnf("web: panic serving %s %s: %v", r.Method, r.URL.Path, v)
				writeError(w, http.StatusInternalServerError, codeInternal, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// limitBody refuses a body declared too large up front and caps one that is not
// declared, so decodeJSON sees the overrun as an *http.MaxBytesError.
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > maxBodyBytes {
			writeError(w, http.StatusRequestEntityTooLarge, codePayloadTooLarge, "request body too large")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		next.ServeHTTP(w, r)
	})
}

// requireJSON answers 415 to a POST, PUT or PATCH that does not declare a JSON body,
// whether or not it carries one. DELETE is exempt: it carries no body in this API,
// and SameSite=Lax already keeps the session cookie off a cross-site DELETE, which no
// HTML form can send anyway.
//
// Besides keeping the handlers honest, this is half of the CSRF defence: an HTML form
// can only send form encodings and text/plain, so a cross-site form post never
// reaches a handler, and the SameSite=Lax session cookie keeps a cross-site fetch
// that could set the header from being authenticated.
func requireJSON(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch:
			mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil || mt != "application/json" {
				writeError(w, http.StatusUnsupportedMediaType, codeUnsupportedMediaType,
					"a POST, PUT or PATCH must send Content-Type: application/json")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// rateLimited admits a request only while its client's bucket in l has a token, and
// hands a refused one to refuse with the time until the next token.
func rateLimited(l *limiter, refuse func(http.ResponseWriter, *http.Request, time.Duration), next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ok, wait := l.allow(rateKey(clientIP(r))); !ok {
			refuse(w, r, wait)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// refuseJSON is the rate limit's answer on an API route: 429 rate_limited.
func refuseJSON(w http.ResponseWriter, _ *http.Request, wait time.Duration) {
	writeRetryAfter(w, wait, codeRateLimited, "too many attempts from this client")
}

// refuseNavigation is the rate limit's answer on a route the browser navigates to
// (the OIDC start and callback): back to the login page, which renders the code.
func refuseNavigation(w http.ResponseWriter, r *http.Request, _ time.Duration) {
	http.Redirect(w, r, loginRateLimited, http.StatusFound)
}

// rateKey is the bucket a client address is limited under. An IPv6 client is keyed
// by its /64: one end site usually holds a whole /64 and can pick a fresh address
// from it for every request, so keying the full address would give it 2^64 buckets.
// An IPv4 address, and anything that is not an address, is its own key.
func rateKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.Is6() {
		return ip
	}
	p, err := a.Prefix(64)
	if err != nil {
		return ip
	}
	return p.String()
}

// clientIP is the address the request came from.
//
// The web listener is reachable only from the frontend's nginx (see
// config.Web.Addr), which overwrites X-Real-IP on every request, so whatever a
// client sent in it never arrives here. nginx sets it to the TCP peer it accepted
// the connection from, unless the deployment lists its reverse proxies in the
// frontend's REAL_IP_FROM: then it is the client address those trusted proxies
// put in X-Forwarded-For. Without REAL_IP_FROM behind a reverse proxy, every
// client shares the proxy's address and so its rate-limit bucket. That nginx is
// the one reason the header is trusted here; exposing this listener to clients
// directly would let each of them pick their own rate-limit key. Without the
// header, or with one that is not an address, the connection's peer is the client.
func clientIP(r *http.Request) string {
	if a, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("X-Real-IP"))); err == nil {
		return a.Unmap().String()
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// sessionMeta is what a sign-in records about where it came from. The User-Agent is
// bounded and made valid UTF-8: it is client-chosen bytes bound for a text column.
func sessionMeta(r *http.Request) app.SessionMeta {
	ua := r.UserAgent()
	if len(ua) > maxUserAgentBytes {
		ua = ua[:maxUserAgentBytes]
	}
	return app.SessionMeta{IP: clientIP(r), UserAgent: strings.ToValidUTF8(ua, "")}
}
