package identity

import (
	"testing"

	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceAccountCannotSignIn(t *testing.T) {
	u := NewService(uuid.New(), "chat-panel", access.Policy{})
	require.False(t, u.CanSignIn(), "service account must never be able to sign in")
}

func TestServiceAccountPolicyIsAlwaysLocal(t *testing.T) {
	u := NewService(uuid.New(), "chat-panel", access.Policy{})
	require.Equal(t, PolicyLocal, u.PolicySource, "PolicySource")
	require.True(t, u.PolicyEditableByAdmin(), "service account policy must stay admin-editable")
}

func TestBlockedHumanCannotSignIn(t *testing.T) {
	u := User{Kind: KindHuman, Status: StatusBlocked}
	require.False(t, u.CanSignIn(), "blocked user must not be able to sign in")
}

func TestIDPManagedPolicyIsNotAdminEditable(t *testing.T) {
	u := User{Kind: KindHuman, Status: StatusActive, PolicySource: PolicyIDP}
	require.False(t, u.PolicyEditableByAdmin(), "IdP-managed policy must not be editable; it is overwritten on next login")
}

func TestActiveHumanCanSignIn(t *testing.T) {
	u := User{Kind: KindHuman, Status: StatusActive}
	require.True(t, u.CanSignIn(), "active human must be able to sign in")
}

func TestActiveUsersCanUseAPI(t *testing.T) {
	for _, u := range []User{
		{Kind: KindHuman, Status: StatusActive},
		NewService(uuid.New(), "chat-panel", access.Policy{}),
	} {
		require.True(t, u.CanUseAPI(), "active %s account must be able to use the API", u.Kind)
	}
}

func TestBlockedOrUnknownUsersCannotUseAPI(t *testing.T) {
	blockedService := NewService(uuid.New(), "chat-panel", access.Policy{})

	blockedService.Status = StatusBlocked
	for name, user := range map[string]User{
		"blocked human":   {Kind: KindHuman, Status: StatusBlocked},
		"blocked service": blockedService,
		"unknown status":  {Kind: KindHuman, Status: "suspended"},
		"unknown kind":    {Kind: "robot", Status: StatusActive},
		"zero value":      {},
	} {
		assert.False(t, user.CanUseAPI(), "%s must not be able to use the API", name)
	}
}
