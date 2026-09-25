package app

import (
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/google/uuid"
)

// RequireAdmin admits an active human administrator who is not under a temporary
// password, and nobody else: every administrator-only service method opens with
// it. An unpopulated actor is nobody: a transport that forgot
// to fill it in must not inherit authority. The temporary-password refusal repeats
// the restricted-session gate on purpose: if a transport ever skips that gate, an
// administrator's unchanged temporary password — possibly read out of a bootstrap
// log — still grants nothing here.
func RequireAdmin(actor identity.User) error {
	if actor.ID == uuid.Nil || actor.Role != identity.RoleAdmin || !actor.CanSignIn() || actor.MustChangePassword {
		return ErrForbidden
	}

	return nil
}
