package postgres_test

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/pgtest"
)

// TestSettingsAndPriceRepos covers both repositories on one container.
func TestSettingsAndPriceRepos(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.NewTestPool(t)

	t.Run("upstream document round-trips verbatim", func(t *testing.T) {
		repo := postgres.NewSettingsRepo(pool)
		if _, err := repo.UpstreamDocument(ctx); !errors.Is(err, app.ErrNotFound) {
			t.Fatalf("before any save: err = %v, want ErrNotFound", err)
		}

		admin := identity.User{ID: uuid.New(), Kind: identity.KindHuman, Email: "root@example.com",
			Role: identity.RoleAdmin, Status: identity.StatusActive, PolicySource: identity.PolicyLocal}
		if err := postgres.NewUserRepo(pool).Create(ctx, admin); err != nil {
			t.Fatalf("create admin: %v", err)
		}
		at := time.Now().UTC().Truncate(time.Microsecond)
		first := "# notes: \"quoted\" and unicode ✓\nproxy-url: http://u:p@proxy.test:3128\nrequest-retry: 2\n"
		if err := repo.SetUpstreamDocument(ctx, first, admin.ID, at); err != nil {
			t.Fatalf("set: %v", err)
		}
		second := "request-retry: 3\n"
		if err := repo.SetUpstreamDocument(ctx, second, admin.ID, at.Add(time.Second)); err != nil {
			t.Fatalf("overwrite: %v", err)
		}
		got, err := repo.UpstreamDocument(ctx)
		if err != nil || got != second {
			t.Fatalf("UpstreamDocument = %q, %v; want %q", got, err, second)
		}

		if err := repo.SetUpstreamDocument(ctx, first, admin.ID, at); err != nil {
			t.Fatalf("set again: %v", err)
		}
		if got, _ := repo.UpstreamDocument(ctx); got != first {
			t.Fatalf("UpstreamDocument = %q, want the document byte for byte", got)
		}
		var by uuid.UUID
		var updated time.Time
		if err := pool.QueryRow(ctx, `SELECT updated_by, updated_at FROM settings WHERE key = 'upstream'`).Scan(&by, &updated); err != nil {
			t.Fatalf("read row: %v", err)
		}
		if by != admin.ID || !updated.Equal(at) {
			t.Fatalf("row updated_by/at = %v/%v, want %v/%v", by, updated, admin.ID, at)
		}
	})

	t.Run("prices replace the whole list", func(t *testing.T) {
		repo := postgres.NewPriceRepo(pool)
		t0 := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
		t1 := t0.Add(time.Minute)

		sonnet := app.ModelPrice{Provider: "claude", Model: "claude-sonnet-5", Input: 3, Output: 15, CacheRead: 0.3, CacheWrite: 3.75}
		gpt := app.ModelPrice{Provider: "chatgpt", Model: "gpt-6", Input: 1.25, Output: 10}
		opus := app.ModelPrice{Provider: "claude", Model: "claude-opus-5", Input: 15, Output: 75}
		if err := repo.Replace(ctx, []app.ModelPrice{sonnet, gpt, opus}, t0); err != nil {
			t.Fatalf("first replace: %v", err)
		}

		cheaperGPT := gpt
		cheaperGPT.Output = 8
		haiku := app.ModelPrice{Provider: "claude", Model: "claude-haiku-5", Input: 1, Output: 5}
		// sonnet unchanged, gpt changed, opus dropped, haiku added.
		if err := repo.Replace(ctx, []app.ModelPrice{sonnet, cheaperGPT, haiku}, t1); err != nil {
			t.Fatalf("second replace: %v", err)
		}

		got, err := repo.List(ctx)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		want := []struct {
			price app.ModelPrice
			at    time.Time
		}{{cheaperGPT, t1}, {haiku, t1}, {sonnet, t0}} // ordered by provider, model
		if len(got) != len(want) {
			t.Fatalf("List = %+v, want %d rows", got, len(want))
		}
		for i, w := range want {
			g := got[i]
			if !g.UpdatedAt.Equal(w.at) {
				t.Errorf("%s/%s updated_at = %v, want %v", g.Provider, g.Model, g.UpdatedAt, w.at)
			}
			g.UpdatedAt = time.Time{}
			if g != w.price {
				t.Errorf("row %d = %+v, want %+v", i, g, w.price)
			}
		}

		// A list naming one model twice fails whole: nothing it carries is written.
		if err := repo.Replace(ctx, []app.ModelPrice{haiku, haiku}, t1.Add(time.Minute)); err == nil {
			t.Fatal("Replace accepted a duplicate model")
		}
		if after, _ := repo.List(ctx); len(after) != 3 {
			t.Fatalf("a failed replace changed the list: %+v", after)
		}

		// The schema refuses what the service validates, for writers that skip it.
		for name, p := range map[string]app.ModelPrice{
			"negative": {Provider: "x", Model: "y", Input: -1},
			"NaN":      {Provider: "x", Model: "y", Output: math.NaN()},
			"infinite": {Provider: "x", Model: "y", CacheRead: math.Inf(1)},
			"blank":    {Provider: "", Model: "y"},
		} {
			if err := repo.Replace(ctx, []app.ModelPrice{p}, t1); err == nil {
				t.Errorf("%s price accepted", name)
			}
		}

		if err := repo.Replace(ctx, nil, t1); err != nil {
			t.Fatalf("empty replace: %v", err)
		}
		if after, err := repo.List(ctx); err != nil || len(after) != 0 {
			t.Fatalf("after an empty replace List = %+v, %v; want none", after, err)
		}
	})
}
