package identity

import (
	"testing"

	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/google/uuid"
)

func TestServiceAccountCannotSignIn(t *testing.T) {
	u := NewService(uuid.New(), "chat-panel", access.Policy{})
	if u.CanSignIn() {
		t.Fatal("service account must never be able to sign in")
	}
}

func TestServiceAccountPolicyIsAlwaysLocal(t *testing.T) {
	u := NewService(uuid.New(), "chat-panel", access.Policy{})
	if u.PolicySource != PolicyLocal {
		t.Fatalf("PolicySource = %v, want local", u.PolicySource)
	}

	if !u.PolicyEditableByAdmin() {
		t.Fatal("service account policy must stay admin-editable")
	}
}

func TestBlockedHumanCannotSignIn(t *testing.T) {
	u := User{Kind: KindHuman, Status: StatusBlocked}
	if u.CanSignIn() {
		t.Fatal("blocked user must not be able to sign in")
	}
}

func TestIDPManagedPolicyIsNotAdminEditable(t *testing.T) {
	u := User{Kind: KindHuman, Status: StatusActive, PolicySource: PolicyIDP}
	if u.PolicyEditableByAdmin() {
		t.Fatal("IdP-managed policy must not be editable; it is overwritten on next login")
	}
}

func TestActiveHumanCanSignIn(t *testing.T) {
	u := User{Kind: KindHuman, Status: StatusActive}
	if !u.CanSignIn() {
		t.Fatal("active human must be able to sign in")
	}
}

func TestActiveUsersCanUseAPI(t *testing.T) {
	for _, u := range []User{
		{Kind: KindHuman, Status: StatusActive},
		NewService(uuid.New(), "chat-panel", access.Policy{}),
	} {
		if !u.CanUseAPI() {
			t.Fatalf("active %s account must be able to use the API", u.Kind)
		}
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
		if user.CanUseAPI() {
			t.Errorf("%s must not be able to use the API", name)
		}
	}
}
