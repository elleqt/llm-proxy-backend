// Package pricecatalog reads the price catalog: the model catalog of oh-my-pi (MIT),
// whose per-model costs, in US dollars per million tokens, become the gateway's
// catalog prices under the provider names usage events carry.
package pricecatalog

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"runtime/debug"
	"slices"
	"strings"
	"unicode"

	"github.com/elleqt/llm-proxy-backend/internal/app"
)

// MaxBody is the largest catalog accepted. The catalog is about 11 MiB.
const MaxBody = 64 << 20

// parserVersion changes whenever Parse or sections would read the same document
// into different prices, so validators stored by an older build are not sent.
const parserVersion = 2

// The sentinels below carry the fixed part of each error message; where a call
// site appends detail, the full text still reads as one sentence. The messages
// are shown to operators verbatim, so they keep no package prefix.
var (
	errInvalidURL       = errors.New("the catalog URL is not valid")
	errFetch            = errors.New("the catalog could not be fetched")
	errRead             = errors.New("the catalog could not be read")
	errUnconditional304 = errors.New("the catalog answered 304 to an unconditional request")
	errStatus           = errors.New("the catalog answered")
	errTooLarge         = fmt.Errorf("the catalog is larger than %d MiB", MaxBody>>20)
	errNotObject        = errors.New("the catalog is not a JSON object")
	errSection          = errors.New("the catalog's")
)

// sections maps the catalog's provider sections onto our provider names, in
// precedence order: a model an earlier section prices is not taken from a later
// one. openai-codex is what the chatgpt accounts serve; openai only fills in the
// models it lacks.
var sections = [...]struct{ section, provider string }{
	{"anthropic", "claude"},
	{"openai-codex", "chatgpt"},
	{"openai", "chatgpt"},
}

// Source fetches the catalog from one URL. It is an app.PriceCatalogSource.
type Source struct {
	url       string
	userAgent string
	client    *http.Client
}

var _ app.PriceCatalogSource = (*Source)(nil)

// New returns a Source for url. version names the build in the User-Agent; empty
// takes it from the binary's build information. The client is a plain one: it
// honours the process's proxy environment.
func New(url, version string) *Source {
	if version == "" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			version = bi.Main.Version
		}
	}

	return &Source{
		url:       url,
		userAgent: "llm-proxy/" + cmp.Or(version, "unknown") + " (price catalog)",
		client:    &http.Client{Timeout: app.CatalogFetchTimeout},
	}
}

// Fingerprint is a SHA-256 of the parser's version and the URL: stored, so the URL,
// which may carry credentials, is not.
func (s *Source) Fingerprint() string {
	sum := sha256.Sum256(fmt.Appendf(nil, "%d %s", parserVersion, s.url))

	return hex.EncodeToString(sum[:])
}

// Fetch downloads the catalog unless it has not changed since the validators.
func (s *Source) Fetch(ctx context.Context, since app.CatalogValidators) (app.CatalogFetch, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, http.NoBody)
	if err != nil {
		return app.CatalogFetch{}, errInvalidURL
	}

	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Accept", "application/json")

	if since.ETag != "" {
		req.Header.Set("If-None-Match", since.ETag)
	}

	if since.LastModified != "" {
		req.Header.Set("If-Modified-Since", since.LastModified)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		// *url.Error names the URL; the cause alone is what went wrong.
		if ue, ok := errors.AsType[*url.Error](err); ok {
			err = ue.Err
		}

		//nolint:errorlint // Transport errors are reported as text, not part of the fetch's error contract.
		return app.CatalogFetch{}, fmt.Errorf("%w: %v", errFetch, err)
	}

	defer func() { _ = resp.Body.Close() }()

	// The status code alone: the reason phrase is whatever the server sent.
	switch {
	case resp.StatusCode == http.StatusNotModified && since == (app.CatalogValidators{}):
		// Nothing to be unchanged from: a cache in the way answered for someone else.
		return app.CatalogFetch{}, errUnconditional304
	case resp.StatusCode == http.StatusNotModified:
		return app.CatalogFetch{Unchanged: true}, nil
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return app.CatalogFetch{}, fmt.Errorf("%w %d", errStatus, resp.StatusCode)
	case resp.ContentLength > MaxBody:
		return app.CatalogFetch{}, errTooLarge
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody+1))
	if err != nil {
		//nolint:errorlint // Transport errors are reported as text, not part of the fetch's error contract.
		return app.CatalogFetch{}, fmt.Errorf("%w: %v", errRead, err)
	}

	if len(body) > MaxBody {
		return app.CatalogFetch{}, errTooLarge
	}

	prices, err := Parse(body)
	if err != nil {
		return app.CatalogFetch{}, err
	}

	return app.CatalogFetch{
		Prices:     prices,
		Validators: app.CatalogValidators{ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified")},
	}, nil
}

// entry is the part of a catalog model this package reads. Input and Output are
// pointers so a cost that lacks either is told from one that is zero.
type entry struct {
	Cost *struct {
		Input      *float64 `json:"input"`
		Output     *float64 `json:"output"`
		CacheRead  float64  `json:"cacheRead"`
		CacheWrite float64  `json:"cacheWrite"`
	} `json:"cost"`
}

// Parse maps a catalog document onto our prices, ordered by provider then model.
// Only the mapped sections are decoded. A model is skipped when its id is blank or
// carries a control character, when it has no cost, no input or no output rate,
// when a rate is negative or not a finite number, or when its entry does not
// decode; a missing cache rate is 0. Rates are taken as the catalog states them.
func Parse(doc []byte) ([]app.ModelPrice, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(doc, &top); err != nil {
		return nil, errNotObject
	}

	type key struct{ provider, model string }

	seen := make(map[key]bool)

	var out []app.ModelPrice

	for _, sec := range sections {
		raw, ok := top[sec.section]
		if !ok {
			continue
		}

		var models map[string]json.RawMessage
		if err := json.Unmarshal(raw, &models); err != nil {
			return nil, fmt.Errorf("%w %s section is not a JSON object", errSection, sec.section)
		}

		for model, rawEntry := range models {
			entryKey := key{sec.provider, model}
			if seen[entryKey] || !modelID(model) {
				continue
			}

			var e entry
			if json.Unmarshal(rawEntry, &e) != nil || e.Cost == nil || e.Cost.Input == nil || e.Cost.Output == nil {
				continue
			}

			cost := e.Cost
			if !rate(*cost.Input) || !rate(*cost.Output) || !rate(cost.CacheRead) || !rate(cost.CacheWrite) {
				continue
			}

			seen[entryKey] = true

			out = append(out, app.ModelPrice{
				Provider: sec.provider, Model: model,
				Input: *cost.Input, Output: *cost.Output, CacheRead: cost.CacheRead, CacheWrite: cost.CacheWrite,
			})
		}
	}

	slices.SortFunc(out, func(a, b app.ModelPrice) int {
		return cmp.Or(strings.Compare(a.Provider, b.Provider), strings.Compare(a.Model, b.Model))
	})

	return out, nil
}

func rate(v float64) bool { return v >= 0 && !math.IsNaN(v) && !math.IsInf(v, 0) }

// modelID reports whether id can be a stored model name: not blank, and free of
// control characters (a NUL, for one, Postgres refuses in text).
func modelID(id string) bool {
	return strings.TrimSpace(id) != "" && !strings.ContainsFunc(id, unicode.IsControl)
}
