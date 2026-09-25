package pricecatalog_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/app/mocks"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/elleqt/llm-proxy-backend/internal/infra/metrics"
	"github.com/elleqt/llm-proxy-backend/internal/infra/pricecatalog"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// catalogDoc is a catalog in the upstream shape: sections we map, one we do not,
// and entries that must be skipped.
const catalogDoc = `{
  "anthropic": {
    "claude-sonnet-5": {"id": "claude-sonnet-5", "name": "Sonnet", "cost": {"input": 3, "output": 15, "cacheRead": 0.3, "cacheWrite": 3.75, "longContext": {"input": 6}}},
    "claude-free":     {"id": "claude-free", "cost": {"input": 0, "output": 0}},
    "claude-nocost":   {"id": "claude-nocost"},
    "claude-negative": {"id": "claude-negative", "cost": {"input": -1, "output": 15}},
    "claude-garbled":  {"id": "claude-garbled", "cost": {"input": "three", "output": 15}},
    "claude-renamed":  {"id": "claude-renamed", "cost": {"inputPerMTok": 3, "outputPerMTok": 15}},
    "claude-empty":    {"id": "claude-empty", "cost": {}},
    "claude-no-output": {"id": "claude-no-output", "cost": {"input": 3}},
    "   ":             {"cost": {"input": 3, "output": 15}},
    "claude-\u0000nul": {"cost": {"input": 3, "output": 15}},
    "claude-\ttab":    {"cost": {"input": 3, "output": 15}}
  },
  "openai-codex": {
    "gpt-5.5": {"cost": {"input": 5, "output": 30, "cacheRead": 0.5}},
    "gpt-codex-nocost": {"cost": null}
  },
  "openai": {
    "gpt-5.5":    {"cost": {"input": 99, "output": 99}},
    "gpt-4.1":    {"cost": {"input": 2, "output": 8, "cacheRead": 0.5}},
    "gpt-codex-nocost": {"cost": {"input": 1, "output": 4}}
  },
  "openrouter": {
    "anthropic/claude-sonnet-5": {"cost": {"input": 3, "output": 15}}
  }
}`

func TestParseMapsSectionsOntoOurProviders(t *testing.T) {
	got, err := pricecatalog.Parse([]byte(catalogDoc))
	require.NoError(t, err, "Parse")

	want := []app.ModelPrice{
		// openai fills what openai-codex lacks a price for, and nothing else.
		{Provider: "chatgpt", Model: "gpt-4.1", Input: 2, Output: 8, CacheRead: 0.5},
		{Provider: "chatgpt", Model: "gpt-5.5", Input: 5, Output: 30, CacheRead: 0.5},
		{Provider: "chatgpt", Model: "gpt-codex-nocost", Input: 1, Output: 4},
		{Provider: "claude", Model: "claude-free"},
		{Provider: "claude", Model: "claude-sonnet-5", Input: 3, Output: 15, CacheRead: 0.3, CacheWrite: 3.75},
	}
	require.Len(t, got, len(want), "Parse = %+v", got)

	assert.Equal(t, want, got)
}

func TestParseRefusesWhatIsNotACatalog(t *testing.T) {
	for _, doc := range []string{`[]`, `{"anthropic": [1, 2]}`, `not json`} {
		_, err := pricecatalog.Parse([]byte(doc))
		assert.Error(t, err, "Parse(%s) accepted", doc)
	}
}

// The source sends the stored validators and names itself; a 304 is an unchanged
// catalog, a 200 carries its prices and new validators.
func TestFetchIsConditional(t *testing.T) {
	var gotETag, gotSince, gotUA string

	srv := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, r *http.Request) {
		gotETag, gotSince, gotUA = r.Header.Get("If-None-Match"), r.Header.Get("If-Modified-Since"), r.Header.Get("User-Agent")
		if gotETag == `"v1"` {
			writer.WriteHeader(http.StatusNotModified)

			return
		}

		writer.Header().Set("ETag", `"v1"`)
		writer.Header().Set("Last-Modified", "Tue, 22 Sep 2026 10:00:00 GMT")
		_, _ = writer.Write([]byte(catalogDoc))
	}))
	defer srv.Close()

	src := pricecatalog.New(srv.URL, "v9.9.9")

	first, err := src.Fetch(context.Background(), app.CatalogValidators{})
	require.NoError(t, err, "first fetch")

	want := app.CatalogValidators{ETag: `"v1"`, LastModified: "Tue, 22 Sep 2026 10:00:00 GMT"}

	require.False(t, first.Unchanged, "first fetch unchanged")
	require.Len(t, first.Prices, 5, "first fetch prices")
	require.Equal(t, want, first.Validators, "first fetch validators")

	require.Empty(t, gotETag, "first request If-None-Match")
	require.Empty(t, gotSince, "first request If-Modified-Since")
	require.Contains(t, gotUA, "llm-proxy/v9.9.9", "first request User-Agent")

	second, err := src.Fetch(context.Background(), first.Validators)
	require.NoError(t, err, "second fetch")
	require.True(t, second.Unchanged, "second fetch = %+v, want unchanged", second)
	require.Equal(t, want.LastModified, gotSince, "second request If-Modified-Since")
}

// A failure is an error that says what happened and never repeats the body.
func TestFetchFailuresAreShortAndBodyless(t *testing.T) {
	const secret = "body-that-must-not-leak"

	for name, tc := range map[string]struct {
		handler http.HandlerFunc
		want    string
	}{
		"server error": {func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, secret, http.StatusBadGateway)
		}, "502"},
		"not json": {func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(secret))
		}, "not a JSON object"},
		"too large": {func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "70000000")
			_, _ = w.Write([]byte(secret))
		}, "larger than 64 MiB"},
		// No Content-Length: only reading the body can find it too large.
		"too large, chunked": {func(writer http.ResponseWriter, _ *http.Request) {
			// A writer that cannot flush makes the fetch fail differently, failing the test.
			flusher, ok := writer.(http.Flusher)
			if !ok {
				return
			}

			chunk := make([]byte, 1<<20)
			for range pricecatalog.MaxBody>>20 + 1 {
				if _, err := writer.Write(chunk); err != nil {
					return
				}

				flusher.Flush()
			}
		}, "larger than 64 MiB"},
		// With no validators sent there is nothing to be unchanged from.
		"304 to an unconditional request": {func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotModified)
		}, "304 to an unconditional request"},
		// The reason phrase is the server's to choose; only the code is kept.
		"reason phrase": {func(w http.ResponseWriter, _ *http.Request) {
			// A writer that cannot be hijacked makes the fetch fail differently, failing the test.
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				return
			}

			conn, buf, err := hijacker.Hijack()
			if err != nil {
				return
			}
			defer func() { _ = conn.Close() }()

			_, _ = buf.WriteString("HTTP/1.1 503 " + secret + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			_ = buf.Flush()
		}, "the catalog answered 503"},
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()

			_, err := pricecatalog.New(srv.URL, "").Fetch(context.Background(), app.CatalogValidators{})
			require.ErrorContains(t, err, tc.want)
			require.NotContains(t, err.Error(), secret, "error repeats the body")
		})
	}
}

// Through the real price table: once a check has applied the catalog, a request is
// priced for a model only the catalog prices.
func TestACheckedCatalogPricesUsage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(catalogDoc))
	}))
	defer srv.Close()

	manual, catalog, audit := mocks.NewPriceRepo(t), mocks.NewPriceCatalogRepo(t), mocks.NewAuditSink(t)
	manual.EXPECT().List(mock.Anything).Return(nil, nil)

	var stored []app.ModelPrice

	catalog.EXPECT().List(mock.Anything).RunAndReturn(func(context.Context) ([]app.ModelPrice, error) { return stored, nil })
	catalog.EXPECT().State(mock.Anything).Return(app.CatalogState{}, nil)
	catalog.EXPECT().Replace(mock.Anything, mock.Anything, mock.Anything, mock.Anything).RunAndReturn(
		func(_ context.Context, p []app.ModelPrice, _ app.CatalogState, _ time.Time) error {
			stored = p

			return nil
		})
	audit.EXPECT().Record(mock.Anything, mock.Anything).Return(nil)

	table := &app.PriceTable{}
	m := metrics.New(prometheus.NewRegistry())

	prices := app.NewPrices(manual, catalog, pricecatalog.New(srv.URL, ""), table, m, audit, clock{}, quiet{})
	require.NoError(t, prices.Load(context.Background()), "Load")

	usage := app.UsageEvent{Provider: "claude", Model: "claude-sonnet-5", TokensInput: 1_000_000, TokensTotal: 1_000_000}

	cost := func() app.UsageCost {
		p, ok := table.Price(usage.Provider, usage.Model)

		return app.PriceUsage(usage, p, ok)
	}
	before := cost()
	require.False(t, before.Priced, "before the check: %+v, want every token unpriced", before)
	require.Equal(t, int64(1_000_000), before.UnpricedTokens, "before the check: want every token unpriced")

	admin := identity.User{ID: uuid.New(), Kind: identity.KindHuman, Role: identity.RoleAdmin, Status: identity.StatusActive}
	_, err := prices.Refresh(context.Background(), admin)
	require.NoError(t, err, "Refresh")

	after := cost()
	require.True(t, after.Priced, "after the check: %+v, want priced", after)
	require.Equal(t, 3.0, after.TotalUSD(), "after the check")
}

type clock struct{}

func (clock) Now() time.Time { return time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC) }

type quiet struct{}

func (quiet) Warn(string, ...slog.Attr) {}
func (quiet) Info(string, ...slog.Attr) {}

// The fingerprint tells two URLs apart without holding either: a credential in the
// URL must not reach the store.
func TestFingerprintNamesTheURLWithoutHoldingIt(t *testing.T) {
	a := pricecatalog.New("https://user:s3cret@catalog.example.com/models.json", "").Fingerprint()

	b := pricecatalog.New("https://catalog.example.com/models.json", "").Fingerprint()
	require.NotEqual(t, a, b, "fingerprints must be distinct")
	require.NotContains(t, a, "s3cret", "fingerprint holds the URL")
	require.NotContains(t, a, "catalog.example.com", "fingerprint holds the URL")
}
