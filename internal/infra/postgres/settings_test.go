package postgres_test

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/pgtest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSettingsAndPriceRepos covers both repositories on one container.
func TestSettingsAndPriceRepos(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.NewTestPool(t)

	t.Run("upstream document round-trips verbatim", func(t *testing.T) {
		repo := postgres.NewSettingsRepo(pool)
		_, err := repo.UpstreamDocument(ctx)
		require.ErrorIs(t, err, app.ErrNotFound, "before any save")

		admin := identity.User{
			ID: uuid.New(), Kind: identity.KindHuman, Email: "root@example.com",
			Role: identity.RoleAdmin, Status: identity.StatusActive, PolicySource: identity.PolicyLocal,
		}
		require.NoError(t, postgres.NewUserRepo(pool).Create(ctx, admin), "create admin")

		at := time.Now().UTC().Truncate(time.Microsecond)

		first := "# notes: \"quoted\" and unicode ✓\nproxy-url: http://u:p@proxy.test:3128\nrequest-retry: 2\n"
		require.NoError(t, repo.SetUpstreamDocument(ctx, first, admin.ID, at), "set")

		second := "request-retry: 3\n"
		require.NoError(t, repo.SetUpstreamDocument(ctx, second, admin.ID, at.Add(time.Second)), "overwrite")

		got, err := repo.UpstreamDocument(ctx)
		require.NoError(t, err, "UpstreamDocument")
		require.Equal(t, second, got, "UpstreamDocument")

		require.NoError(t, repo.SetUpstreamDocument(ctx, first, admin.ID, at), "set again")

		got, _ = repo.UpstreamDocument(ctx)
		require.Equal(t, first, got, "UpstreamDocument must return the document byte for byte")

		var (
			by      uuid.UUID
			updated time.Time
		)

		err = pool.QueryRow(ctx, `SELECT updated_by, updated_at FROM settings WHERE key = 'upstream'`).Scan(&by, &updated)
		require.NoError(t, err, "read row")
		require.Equal(t, admin.ID, by, "row updated_by")
		require.True(t, updated.Equal(at), "row updated_at = %v, want %v", updated, at)
	})

	t.Run("prices replace the whole list", func(t *testing.T) {
		repo := postgres.NewPriceRepo(pool)
		t0 := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
		t1 := t0.Add(time.Minute)

		sonnet := app.ModelPrice{Provider: "claude", Model: "claude-sonnet-5", Input: 3, Output: 15, CacheRead: 0.3, CacheWrite: 3.75}
		gpt := app.ModelPrice{Provider: "chatgpt", Model: "gpt-6", Input: 1.25, Output: 10}

		opus := app.ModelPrice{Provider: "claude", Model: "claude-opus-5", Input: 15, Output: 75}
		require.NoError(t, repo.Replace(ctx, []app.ModelPrice{sonnet, gpt, opus}, t0), "first replace")

		cheaperGPT := gpt
		cheaperGPT.Output = 8
		haiku := app.ModelPrice{Provider: "claude", Model: "claude-haiku-5", Input: 1, Output: 5}
		// sonnet unchanged, gpt changed, opus dropped, haiku added.
		require.NoError(t, repo.Replace(ctx, []app.ModelPrice{sonnet, cheaperGPT, haiku}, t1), "second replace")

		got, err := repo.List(ctx)
		require.NoError(t, err, "List")

		want := []struct {
			price app.ModelPrice
			at    time.Time
		}{{cheaperGPT, t1}, {haiku, t1}, {sonnet, t0}} // ordered by provider, model
		require.Len(t, got, len(want), "List")

		for idx, expected := range want {
			actual := got[idx]
			assert.True(t, actual.UpdatedAt.Equal(expected.at),
				"%s/%s updated_at = %v, want %v", actual.Provider, actual.Model, actual.UpdatedAt, expected.at)

			// UpdatedAt is checked above as an instant; the rest compares exactly.
			actual.UpdatedAt = time.Time{}
			assert.Equal(t, expected.price, actual, "row %d", idx)
		}

		// A list naming one model twice fails whole: nothing it carries is written.
		require.Error(t, repo.Replace(ctx, []app.ModelPrice{haiku, haiku}, t1.Add(time.Minute)), "Replace accepted a duplicate model")

		after, _ := repo.List(ctx)
		require.Len(t, after, 3, "a failed replace changed the list")

		// The schema refuses what the service validates, for writers that skip it.
		for name, price := range map[string]app.ModelPrice{
			"negative": {Provider: "x", Model: "y", Input: -1},
			"NaN":      {Provider: "x", Model: "y", Output: math.NaN()},
			"infinite": {Provider: "x", Model: "y", CacheRead: math.Inf(1)},
			"blank":    {Provider: "", Model: "y"},
		} {
			// A subtest per price: every accepted one is reported, as before.
			t.Run(name, func(t *testing.T) {
				require.Error(t, repo.Replace(ctx, []app.ModelPrice{price}, t1), "%s price accepted", name)
			})
		}

		require.NoError(t, repo.Replace(ctx, nil, t1), "empty replace")

		after, err = repo.List(ctx)
		require.NoError(t, err, "List after an empty replace")
		require.Empty(t, after, "List after an empty replace")
	})

	t.Run("catalog prices and state replace together", func(t *testing.T) {
		repo := postgres.NewPriceCatalogRepo(pool)
		t0 := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
		t1 := t0.Add(time.Minute)
		sonnet := app.ModelPrice{Provider: "claude", Model: "claude-sonnet-5", Input: 3, Output: 15, CacheRead: 0.3, CacheWrite: 3.75}
		gpt := app.ModelPrice{Provider: "chatgpt", Model: "gpt-6", Input: 1.25, Output: 10}

		first := app.CatalogState{
			Validators:  app.CatalogValidators{ETag: `"v1"`, LastModified: "Tue, 22 Sep 2026 10:00:00 GMT"},
			Fingerprint: "2 https://catalog.example.com/models.json", CheckedAt: t0, ChangedAt: t0,
		}
		require.NoError(t, repo.Replace(ctx, []app.ModelPrice{sonnet, gpt}, first, t0), "first replace")

		cheaper := gpt
		cheaper.Output = 8

		second := app.CatalogState{
			Validators: app.CatalogValidators{ETag: `"v2"`}, Fingerprint: "3 https://catalog.example.com/models.json",
			CheckedAt: t1, ChangedAt: t1,
		}
		require.NoError(t, repo.Replace(ctx, []app.ModelPrice{sonnet, cheaper}, second, t1), "second replace")

		// want gpt-6 changed at t1 and sonnet kept at t0
		got, err := repo.List(ctx)
		require.NoError(t, err, "List")
		require.Len(t, got, 2, "List")
		require.True(t, got[0].UpdatedAt.Equal(t1), "gpt-6 updated_at = %v, want %v", got[0].UpdatedAt, t1)
		require.Equal(t, 8.0, got[0].Output, "gpt-6 output")
		require.True(t, got[1].UpdatedAt.Equal(t0), "sonnet updated_at = %v, want %v", got[1].UpdatedAt, t0)

		state, err := repo.State(ctx)
		require.NoError(t, err, "State")
		// Exact, times included: State normalises to UTC, and a location slip must fail.
		require.Equal(t, second, state, "State")

		// A replacement that fails writes neither the prices nor the state.
		require.Error(t, repo.Replace(ctx, []app.ModelPrice{sonnet, sonnet}, first, t1.Add(time.Minute)), "Replace accepted a duplicate model")

		state, _ = repo.State(ctx)
		require.Equal(t, second, state, "a failed replace changed the state")

		failed := second

		failed.LastError = "the catalog answered 503"
		require.NoError(t, repo.SetState(ctx, failed), "SetState")

		state, err = repo.State(ctx)
		require.NoError(t, err, "State")
		require.Equal(t, failed, state, "State after SetState")

		after, _ := repo.List(ctx)
		require.Len(t, after, 2, "SetState changed the prices")
	})
}
