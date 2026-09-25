package app

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/elleqt/llm-proxy-backend/internal/domain/credentials"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
)

// MaxLiveTokensPerOwner is how many tokens that are not revoked one owner may hold.
// Revoking one makes room for another. The bound keeps what one account can make the
// gateway hold — token rows, and the state kept per token — proportional to the
// number of accounts rather than to how often someone calls the issue endpoint.
const MaxLiveTokensPerOwner = 50

// TokenService issues, lists and revokes API keys.
//
// A token carries no permissions of its own: it is a named, revocable key belonging
// to an owner, and every restriction is read from that owner at request time. So the
// only authorisation question here is whose keys the actor may manage.
type TokenService struct {
	users  UserRepo
	tokens TokenRepo
	audit  AuditSink
	clock  Clock
	logger Logger
}

func NewTokenService(users UserRepo, tokens TokenRepo, audit AuditSink, clock Clock, logger Logger) *TokenService {
	return &TokenService{users: users, tokens: tokens, audit: audit, clock: clock, logger: logger}
}

// manages reports whether actor may manage owner's keys: a person manages their own,
// and an administrator manages anyone's. That second half is the only way a service
// account gets a key at all — it cannot sign in, so it can never ask for one itself.
func manages(actor identity.User, owner uuid.UUID) error {
	// An unpopulated actor is nobody. Without this a handler that forgets to fill the
	// actor from the session matches any owner the caller also left empty, and the
	// ownership rule silently becomes an allow.
	if actor.ID == uuid.Nil {
		return ErrForbidden
	}
	if actor.ID == owner || actor.Role == identity.RoleAdmin {
		return nil
	}
	return ErrForbidden
}

// Issue mints a key for owner and returns the record plus the secret. The secret is
// returned here and nowhere else: it is not recoverable from the stored record, is
// never logged, and never reaches an audit detail. An owner already holding
// MaxLiveTokensPerOwner live keys is refused with ErrTokenLimit.
func (s *TokenService) Issue(ctx context.Context, actor identity.User, owner uuid.UUID, label string) (credentials.Token, string, error) {
	if err := manages(actor, owner); err != nil {
		return credentials.Token{}, "", err
	}
	// Refuse before minting anything if the owner is gone: a token row pointing at a
	// missing user would be unusable and unattributable.
	if _, err := s.users.ByID(ctx, owner); err != nil {
		return credentials.Token{}, "", err
	}

	tok, secret, err := credentials.Generate(owner, label)
	if err != nil {
		return credentials.Token{}, "", err
	}
	// The service owns time so tests and the ledger see one consistent instant;
	// credentials.Generate only defaults it.
	now := s.clock.Now().UTC()
	tok.CreatedAt = now

	if err := s.tokens.Create(ctx, tok); err != nil {
		return credentials.Token{}, "", err
	}
	// Fail closed: an unrecorded security event is not allowed to stand. The row is
	// already durable at this point, so it is retracted rather than left unaudited.
	if err := s.audit.Record(ctx, AuditEvent{
		At:      now,
		ActorID: actor.ID,
		Action:  "token.issue",
		Target:  "token/" + tok.ID.String(),
		Detail:  map[string]any{"token_id": tok.ID.String(), "owner_id": owner.String(), "label": label},
	}); err != nil {
		return credentials.Token{}, "", s.retract(ctx, tok, actor.ID, now, err)
	}
	return tok, secret, nil
}

// retract compensates for an issue whose audit record did not land: the row is marked
// revoked, which is honest because its secret was never returned and the key it names
// can never be presented. This is a mitigation, not a fix — the row and its audit
// record want to be one unit of work, and that is a port-level change deferred out of
// this task. Recording the audit before the create is not the answer: a phantom
// credential in the security log is worse than a phantom row, because operators trust
// the log and cannot correct it.
//
// The save runs on a detached context (compensationContext): the audit most likely
// failed because the client hung up, and that must not also skip the retraction.
func (s *TokenService) retract(ctx context.Context, tok credentials.Token, by uuid.UUID, now time.Time, cause error) error {
	if err := tok.Revoke(by, now); err != nil {
		return s.stranded(tok, cause, err, "compensating revoke refused")
	}
	cctx, cancel := compensationContext(ctx)
	defer cancel()
	if err := s.tokens.Save(cctx, tok); err != nil {
		return s.stranded(tok, cause, err, "compensating revoke not saved")
	}
	return fmt.Errorf("app: issued token not audited, token revoked: %w", cause)
}

// stranded reports the one outcome an operator has to act on by hand: a live token row
// that no audit record describes. The caller's error string would otherwise be the only
// trace of it, and the caller is not who fixes this.
func (s *TokenService) stranded(tok credentials.Token, cause, failure error, what string) error {
	s.logger.Warn("token is live but unaudited — revoke it by hand",
		slog.String("token", tok.ID.String()), slog.String("owner", tok.UserID.String()),
		slog.Any("audit_err", cause), slog.String("cleanup", what), slog.Any("cleanup_err", failure))
	return fmt.Errorf("app: issued token not audited (%w); %s: %v", cause, what, failure)
}

// Revoke retires a key. Ownership lives on the token, so the record is loaded before
// the check can be made: an unknown id is ErrNotFound, someone else's is ErrForbidden.
// The two stay distinct because a token id is a random UUID — telling them apart
// reveals nothing a caller could not already have guessed at, and nothing that lets
// anyone walk another person's ids.
func (s *TokenService) Revoke(ctx context.Context, actor identity.User, tokenID uuid.UUID) error {
	tok, err := s.tokens.ByID(ctx, tokenID)
	if err != nil {
		return err
	}
	if err := manages(actor, tok.UserID); err != nil {
		return err
	}

	now := s.clock.Now().UTC()
	if err := tok.Revoke(actor.ID, now); err != nil {
		return err
	}
	if err := s.tokens.Save(ctx, tok); err != nil {
		return err
	}
	// The state change is durable and safe — the key is dead either way — so a failed
	// audit write is logged rather than returned. Returning it would report failure for
	// an operation that succeeded, and the caller's retry would then hit
	// credentials.ErrAlreadyRevoked: a second error for work that was already done.
	if err := s.audit.Record(ctx, AuditEvent{
		At:      now,
		ActorID: actor.ID,
		Action:  "token.revoke",
		Target:  "token/" + tok.ID.String(),
		Detail:  map[string]any{"token_id": tok.ID.String(), "owner_id": tok.UserID.String(), "label": tok.Label},
	}); err != nil {
		s.logger.Warn("token revoked but the audit record failed", slog.String("token", tok.ID.String()), slog.Any("err", err))
	}
	return nil
}

// List returns owner's keys. The records hold a hash and a prefix, never a secret.
func (s *TokenService) List(ctx context.Context, actor identity.User, owner uuid.UUID) ([]credentials.Token, error) {
	if err := manages(actor, owner); err != nil {
		return nil, err
	}
	return s.tokens.ListByUser(ctx, owner)
}
