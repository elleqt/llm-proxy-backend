package vendorcreds_test

import (
	"context"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/pgtest"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/vendorcreds"
	"github.com/stretchr/testify/require"
)

var (
	createdAt = time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	updatedAt = createdAt.Add(time.Hour)
)

// credential builds a row. sealed stands in for the gateway's ciphertext, which the
// repository stores without looking at.
func credential(id, provider, sealed string, created, updated time.Time) app.VendorCredential {
	return app.VendorCredential{ID: id, Provider: provider, Sealed: []byte(sealed), CreatedAt: created, UpdatedAt: updated}
}

// TestVendorCredentialRepo shares one container across its subtests: a pool costs
// roughly two seconds to stand up, and each subtest owns its own ids.
func TestVendorCredentialRepo(t *testing.T) {
	ctx := context.Background()
	repo := vendorcreds.New(pgtest.NewTestPool(t))

	stored := func(t *testing.T, id string) (app.VendorCredential, bool) {
		t.Helper()

		all, err := repo.List(ctx)
		require.NoError(t, err, "list")

		for _, cred := range all {
			if cred.ID == id {
				return cred, true
			}
		}

		return app.VendorCredential{}, false
	}

	// Runs first: the only subtest that asserts the whole table, which the others
	// then add their own rows to.
	t.Run("ListReturnsEveryRowByID", func(t *testing.T) {
		codex := credential("codex-b@example.com.json", "codex", "sealed-b", createdAt, createdAt)
		claude := credential("claude-a@example.com.json", "claude", "sealed-a", createdAt, updatedAt)

		require.NoError(t, repo.Upsert(ctx, codex), "upsert codex")
		require.NoError(t, repo.Upsert(ctx, claude), "upsert claude")

		all, err := repo.List(ctx)
		require.NoError(t, err, "list")
		require.Equal(t, []app.VendorCredential{claude, codex}, all, "list")
	})

	t.Run("UpsertOverwritesAndKeepsCreatedAt", func(t *testing.T) {
		// A re-login of the same account overwrites its row; the account's age stays
		// that of its first sign-in.
		first := credential("claude-upsert@example.com.json", "claude", "sealed-1", createdAt, createdAt)
		require.NoError(t, repo.Upsert(ctx, first), "first upsert")

		again := credential(first.ID, "codex", "sealed-2", updatedAt, updatedAt)
		require.NoError(t, repo.Upsert(ctx, again), "second upsert")

		got, ok := stored(t, first.ID)
		require.True(t, ok, "row missing after the second upsert")
		require.Equal(t, credential(first.ID, "codex", "sealed-2", createdAt, updatedAt), got, "overwritten row")
	})

	t.Run("UpdateOverwritesAndKeepsCreatedAt", func(t *testing.T) {
		row := credential("codex-update@example.com.json", "codex", "sealed-1", createdAt, createdAt)
		require.NoError(t, repo.Upsert(ctx, row), "upsert")

		require.NoError(t, repo.Update(ctx, credential(row.ID, "codex", "sealed-2", updatedAt, updatedAt)), "update")

		got, ok := stored(t, row.ID)
		require.True(t, ok, "row missing after update")
		require.Equal(t, credential(row.ID, "codex", "sealed-2", createdAt, updatedAt), got, "updated row")
	})

	t.Run("UpdateOfMissingIDIsNotFound", func(t *testing.T) {
		// The gateway's runtime saves go through Update: this refusal is what keeps a
		// token refresh from re-creating an account an administrator removed.
		missing := credential("claude-missing@example.com.json", "claude", "sealed", createdAt, createdAt)
		require.ErrorIs(t, repo.Update(ctx, missing), app.ErrNotFound)

		_, ok := stored(t, missing.ID)
		require.False(t, ok, "Update created the missing row")
	})

	t.Run("DeleteRemovesRow", func(t *testing.T) {
		row := credential("claude-delete@example.com.json", "claude", "sealed", createdAt, createdAt)
		require.NoError(t, repo.Upsert(ctx, row), "upsert")

		require.NoError(t, repo.Delete(ctx, row.ID), "delete")

		_, ok := stored(t, row.ID)
		require.False(t, ok, "row survived Delete")
	})

	t.Run("DeleteOfMissingIDIsNil", func(t *testing.T) {
		// Removing an account deletes its row; a row already gone is the same outcome.
		require.NoError(t, repo.Delete(ctx, "claude-never-stored@example.com.json"))
	})
}
