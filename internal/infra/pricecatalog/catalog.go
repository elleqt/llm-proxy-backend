// Package pricecatalog reads the price catalog: the model catalog of oh-my-pi (MIT),
// whose per-model costs, in US dollars per million tokens, become the gateway's
// catalog prices under the provider names usage events carry.
package pricecatalog

import (
	"cmp"
	"context"
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
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
)

const (
	// MaxBody is the largest catalog accepted. The catalog is about 11 MiB.
	MaxBody = 64 << 20
	// fetchTimeout bounds one fetch, headers and body. The raw file host can be
	// slow, and nothing waits on a check but the check itself.
	fetchTimeout = 2 * time.Minute
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
		client:    &http.Client{Timeout: fetchTimeout},
	}
}

// Fetch downloads the catalog unless it has not changed since the validators.
func (s *Source) Fetch(ctx context.Context, since app.CatalogValidators) (app.CatalogFetch, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return app.CatalogFetch{}, errors.New("the catalog URL is not valid")
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
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return app.CatalogFetch{}, fmt.Errorf("the catalog could not be fetched: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode == http.StatusNotModified:
		return app.CatalogFetch{Unchanged: true}, nil
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return app.CatalogFetch{}, fmt.Errorf("the catalog answered %s", resp.Status)
	case resp.ContentLength > MaxBody:
		return app.CatalogFetch{}, fmt.Errorf("the catalog is larger than %d MiB", MaxBody>>20)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody+1))
	if err != nil {
		return app.CatalogFetch{}, fmt.Errorf("the catalog could not be read: %v", err)
	}
	if len(body) > MaxBody {
		return app.CatalogFetch{}, fmt.Errorf("the catalog is larger than %d MiB", MaxBody>>20)
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

// entry is the part of a catalog model this package reads.
type entry struct {
	Cost *struct {
		Input      float64 `json:"input"`
		Output     float64 `json:"output"`
		CacheRead  float64 `json:"cacheRead"`
		CacheWrite float64 `json:"cacheWrite"`
	} `json:"cost"`
}

// Parse maps a catalog document onto our prices, ordered by provider then model.
// Only the mapped sections are decoded. A model without a cost, or with a rate
// that is negative or not a finite number, is skipped, as is one whose entry does
// not decode; a missing cache rate is 0. Rates are taken as the catalog states
// them.
func Parse(doc []byte) ([]app.ModelPrice, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(doc, &top); err != nil {
		return nil, errors.New("the catalog is not a JSON object")
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
			return nil, fmt.Errorf("the catalog's %s section is not a JSON object", sec.section)
		}
		for model, rawEntry := range models {
			k := key{sec.provider, model}
			if model == "" || seen[k] {
				continue
			}
			var e entry
			if json.Unmarshal(rawEntry, &e) != nil || e.Cost == nil {
				continue
			}
			c := e.Cost
			if !rate(c.Input) || !rate(c.Output) || !rate(c.CacheRead) || !rate(c.CacheWrite) {
				continue
			}
			seen[k] = true
			out = append(out, app.ModelPrice{
				Provider: sec.provider, Model: model,
				Input: c.Input, Output: c.Output, CacheRead: c.CacheRead, CacheWrite: c.CacheWrite,
			})
		}
	}
	slices.SortFunc(out, func(a, b app.ModelPrice) int {
		return cmp.Or(strings.Compare(a.Provider, b.Provider), strings.Compare(a.Model, b.Model))
	})
	return out, nil
}

func rate(v float64) bool { return v >= 0 && !math.IsNaN(v) && !math.IsInf(v, 0) }
