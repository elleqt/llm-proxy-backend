package identity

import (
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/google/uuid"
)

type Kind string

const (
	KindHuman   Kind = "human"
	KindService Kind = "service"
)

type Role string

const (
	RoleUser  Role = "user"
	RoleAdmin Role = "admin"
)

type Status string

const (
	StatusActive  Status = "active"
	StatusBlocked Status = "blocked"
)

type PolicySource string

const (
	PolicyLocal PolicySource = "local"
	PolicyIDP   PolicySource = "idp"
)

type User struct {
	ID                 uuid.UUID
	Kind               Kind
	Email              string
	DisplayName        string
	Role               Role
	Status             Status
	Policy             access.Policy
	PolicySource       PolicySource
	MustChangePassword bool
	LastSeenAt         *time.Time
	CreatedAt          time.Time
}

// NewService builds a machine account: no password, no federated identity,
// no web session, and a policy that only an administrator edits.
//
// A service account has no email, so Email is left empty. The write path MUST bind
// an empty Email as SQL NULL: users.email is UNIQUE, and Postgres permits many NULL
// values but only one empty string, so persisting the zero value would make the
// second service account collide on a column nobody set. Enforced at the repository
// boundary, not here.
func NewService(id uuid.UUID, name string, p access.Policy) User {
	return User{
		ID:           id,
		Kind:         KindService,
		DisplayName:  name,
		Role:         RoleUser,
		Status:       StatusActive,
		Policy:       p,
		PolicySource: PolicyLocal,
		CreatedAt:    time.Now().UTC(),
	}
}

func (u User) CanSignIn() bool {
	return u.Kind == KindHuman && u.Status == StatusActive
}

// CanUseAPI reports whether the user's API tokens authenticate: a human or a
// service account, and active. Blocking a user stops their tokens at once,
// without revoking them. This is the only place the rule lives.
func (u User) CanUseAPI() bool {
	return (u.Kind == KindHuman || u.Kind == KindService) && u.Status == StatusActive
}

// Label is how metrics name the user: the email, or, for a service account
// (which has none), its display name. Never an id.
func (u User) Label() string {
	if u.Email != "" {
		return u.Email
	}
	return u.DisplayName
}

// PolicyEditableByAdmin reports whether the admin UI may change the policy.
// An IdP-managed policy is recomputed at every login, so editing it would be
// silently undone.
func (u User) PolicyEditableByAdmin() bool {
	return u.PolicySource == PolicyLocal
}
