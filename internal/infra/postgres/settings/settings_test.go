package settings_test

import (
	"context"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/elleqt/llm-proxy-backend/internal/domain/limits"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/pgtest"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/settings"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/users"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestSpendLimitDefaults(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.NewTestPool(t)
	repo := settings.New(pool)

	// Never saved is "no defaults", not an error: every account would otherwise
	// fail its limit check until an administrator first opened the screen.
	got, err := repo.SpendLimitDefaults(ctx)
	require.NoError(t, err, "SpendLimitDefaults before any save")
	require.Equal(t, limits.Set{}, got, "SpendLimitDefaults before any save")

	admin := identity.User{
		ID: uuid.New(), Kind: identity.KindHuman, Email: "root@example.com",
		Role: identity.RoleAdmin, Status: identity.StatusActive, PolicySource: identity.PolicyLocal,
	}
	require.NoError(t, users.New(pool).Create(ctx, admin), "create admin")

	at := time.Now().UTC().Truncate(time.Microsecond)

	want := limits.Set{{Window: 2 * time.Hour, AmountUSD: 10}, {Window: 24 * time.Hour, AmountUSD: 30}}
	require.NoError(t, repo.SetSpendLimitDefaults(ctx, want, admin.ID, at), "save two rules")

	got, err = repo.SpendLimitDefaults(ctx)
	require.NoError(t, err, "SpendLimitDefaults after save")
	require.Equal(t, want, got, "SpendLimitDefaults after save")

	require.NoError(t, repo.SetSpendLimitDefaults(ctx, limits.Set{}, admin.ID, at.Add(time.Second)), "save empty")

	got, err = repo.SpendLimitDefaults(ctx)
	require.NoError(t, err, "SpendLimitDefaults after clearing")
	require.Empty(t, got, "SpendLimitDefaults after clearing")

	// Both documents live in the one settings table: saving the limits must not
	// make an upstream document appear.
	_, err = repo.UpstreamDocument(ctx)
	require.ErrorIs(t, err, app.ErrNotFound, "UpstreamDocument after saving spend limits")
}
