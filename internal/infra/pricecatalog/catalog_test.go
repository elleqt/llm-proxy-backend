package pricecatalog_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/mock"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/app/mocks"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/elleqt/llm-proxy-backend/internal/infra/metrics"
	"github.com/elleqt/llm-proxy-backend/internal/infra/pricecatalog"
)

// catalogDoc is a catalog in the upstream shape: sections we map, one we do not,
// and entries that must be skipped.
const catalogDoc = `{
  "anthropic": {
    "claude-sonnet-5": {"id": "claude-sonnet-5", "name": "Sonnet", "cost": {"input": 3, "output": 15, "cacheRead": 0.3, "cacheWrite": 3.75, "longContext": {"input": 6}}},
    "claude-free":     {"id": "claude-free", "cost": {"input": 0, "output": 0}},
    "claude-nocost":   {"id": "claude-nocost"},
    "claude-negative": {"id": "claude-negative", "cost": {"input": -1, "output": 15}},
    "claude-garbled":  {"id": "claude-garbled", "cost": {"input": "three", "output": 15}}
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
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []app.ModelPrice{
		// openai fills what openai-codex lacks a price for, and nothing else.
		{Provider: "chatgpt", Model: "gpt-4.1", Input: 2, Output: 8, CacheRead: 0.5},
		{Provider: "chatgpt", Model: "gpt-5.5", Input: 5, Output: 30, CacheRead: 0.5},
		{Provider: "chatgpt", Model: "gpt-codex-nocost", Input: 1, Output: 4},
		{Provider: "claude", Model: "claude-free"},
		{Provider: "claude", Model: "claude-sonnet-5", Input: 3, Output: 15, CacheRead: 0.3, CacheWrite: 3.75},
	}
	if len(got) != len(want) {
		t.Fatalf("Parse = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestParseRefusesWhatIsNotACatalog(t *testing.T) {
	for _, doc := range []string{`[]`, `{"anthropic": [1, 2]}`, `not json`} {
		if _, err := pricecatalog.Parse([]byte(doc)); err == nil {
			t.Errorf("Parse(%s) accepted", doc)
		}
	}
}

// The source sends the stored validators and names itself; a 304 is an unchanged
// catalog, a 200 carries its prices and new validators.
func TestFetchIsConditional(t *testing.T) {
	var gotETag, gotSince, gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotETag, gotSince, gotUA = r.Header.Get("If-None-Match"), r.Header.Get("If-Modified-Since"), r.Header.Get("User-Agent")
		if gotETag == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Last-Modified", "Tue, 22 Sep 2026 10:00:00 GMT")
		_, _ = w.Write([]byte(catalogDoc))
	}))
	defer srv.Close()
	src := pricecatalog.New(srv.URL, "v9.9.9")

	first, err := src.Fetch(context.Background(), app.CatalogValidators{})
	if err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	want := app.CatalogValidators{ETag: `"v1"`, LastModified: "Tue, 22 Sep 2026 10:00:00 GMT"}
	if first.Unchanged || len(first.Prices) != 5 || first.Validators != want {
		t.Fatalf("first fetch = %+v, want 5 prices and the validators", first)
	}
	if gotETag != "" || gotSince != "" || !strings.Contains(gotUA, "llm-proxy/v9.9.9") {
		t.Fatalf("first request: If-None-Match %q, If-Modified-Since %q, User-Agent %q", gotETag, gotSince, gotUA)
	}

	second, err := src.Fetch(context.Background(), first.Validators)
	if err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	if !second.Unchanged || gotSince != want.LastModified {
		t.Fatalf("second fetch = %+v (If-Modified-Since %q), want unchanged", second, gotSince)
	}
}

// A failure is an error that says what happened and never repeats the body.
func TestFetchFailuresAreShortAndBodyless(t *testing.T) {
	const secret = "body-that-must-not-leak"
	for name, c := range map[string]struct {
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
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(c.handler)
			defer srv.Close()
			_, err := pricecatalog.New(srv.URL, "").Fetch(context.Background(), app.CatalogValidators{})
			if err == nil || !strings.Contains(err.Error(), c.want) || strings.Contains(err.Error(), secret) {
				t.Fatalf("err = %v, want one naming %q without the body", err, c.want)
			}
		})
	}
}

// Through the real sink: once a check has applied the catalog, the cost metric
// prices a model only the catalog prices.
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

	table := &metrics.PriceTable{}
	m := metrics.New(prometheus.NewRegistry(), metrics.WithPrices(table))
	prices := app.NewPrices(manual, catalog, pricecatalog.New(srv.URL, ""), table, m, audit, clock{}, quiet{})
	if err := prices.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}
	usage := app.UsageEvent{Provider: "claude", Model: "claude-sonnet-5", TokensInput: 1_000_000, TokensTotal: 1_000_000}
	m.ObserveUsage(usage, "before")

	admin := identity.User{ID: uuid.New(), Kind: identity.KindHuman, Role: identity.RoleAdmin, Status: identity.StatusActive}
	if _, err := prices.Refresh(context.Background(), admin); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	m.ObserveUsage(usage, "after")

	body := scrape(t, m)
	if !strings.Contains(body, `llmproxy_cost_usd_total{model="claude-sonnet-5",provider="claude",user="after"} 3`) ||
		strings.Contains(body, `llmproxy_cost_usd_total{model="claude-sonnet-5",provider="claude",user="before"}`) {
		t.Fatalf("want the request after the check priced at $3 and the one before unpriced:\n%s", body)
	}
}

func scrape(t *testing.T, m *metrics.Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	return rec.Body.String()
}

type clock struct{}

func (clock) Now() time.Time { return time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC) }

type quiet struct{}

func (quiet) Warnf(string, ...any) {}
func (quiet) Infof(string, ...any) {}
