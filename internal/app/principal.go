package app

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/domain/credentials"
	"github.com/google/uuid"
)

// ErrMalformedPrincipal reports a string ParsePrincipal cannot read back.
var ErrMalformedPrincipal = errors.New("app: malformed principal")

// Principal is who a proxied request acts for: the owner of the API token it
// presented, and that token.
type Principal struct {
	UserID  uuid.UUID
	TokenID uuid.UUID
	// Owner is the owner's label (identity.User.Label), set by Resolve from the
	// owner it reads anyway, so labelling a refused request needs no second read.
	// It is not part of String: ParsePrincipal leaves it empty.
	Owner string
}

// String is "<userID>:<tokenID>". Upstream copies it into every usage record,
// which is how the usage sink attributes a record to a user and a token without
// another lookup; ParsePrincipal reverses it.
func (p Principal) String() string {
	return p.UserID.String() + ":" + p.TokenID.String()
}

// ParsePrincipal reads what String wrote. It accepts only that form — two
// canonical, non-nil UUIDs joined by one colon — so a value that did not come
// from String is never attributed to anyone. The input is not echoed in the
// error: a caller may hand it whatever upstream recorded.
func ParsePrincipal(s string) (Principal, error) {
	user, token, ok := strings.Cut(s, ":")
	if !ok {
		return Principal{}, ErrMalformedPrincipal
	}

	userID, err := parseCanonical(user)
	if err != nil {
		return Principal{}, err
	}

	tokenID, err := parseCanonical(token)
	if err != nil {
		return Principal{}, err
	}

	return Principal{UserID: userID, TokenID: tokenID}, nil
}

// parseCanonical parses s as a UUID in the form uuid.UUID.String writes.
// uuid.Parse alone also accepts braces, a urn:uuid: prefix and no hyphens.
func parseCanonical(s string) (uuid.UUID, error) {
	id, err := uuid.Parse(s)
	if err != nil || id == uuid.Nil || id.String() != s {
		return uuid.UUID{}, ErrMalformedPrincipal
	}

	return id, nil
}

// TokenResolver turns an API token secret into the principal it authenticates.
type TokenResolver struct {
	users  UserRepo
	tokens TokenRepo
}

func NewTokenResolver(users UserRepo, tokens TokenRepo) *TokenResolver {
	return &TokenResolver{users: users, tokens: tokens}
}

// Resolve authenticates secret, and returns the policy of the token's owner as
// Resolve read it, so a caller deciding what the request may do needs no second
// read of the owner. A token authenticates only while it is not revoked and
// its owner may use the API (identity.User.CanUseAPI), so blocking a user
// stops their tokens at once.
//
// Every refusal — no secret, an unknown or revoked token, an owner that is gone
// or may not use the API — is ErrInvalidCredentials and nothing else, with a
// zero principal and no policy, so a caller cannot tell a revoked or blocked
// key from one that never existed. Any other error is a failed lookup, not a
// refusal, and is returned wrapped. The secret appears in no error.
func (r *TokenResolver) Resolve(ctx context.Context, secret string) (Principal, access.Policy, error) {
	if secret == "" {
		return Principal{}, nil, ErrInvalidCredentials
	}

	tok, err := r.tokens.ByHash(ctx, credentials.HashSecret(secret))
	if errors.Is(err, ErrNotFound) {
		return Principal{}, nil, ErrInvalidCredentials
	}

	if err != nil {
		return Principal{}, nil, fmt.Errorf("app: resolve token: %w", err)
	}

	if !tok.Active() {
		return Principal{}, nil, ErrInvalidCredentials
	}

	owner, err := r.users.ByID(ctx, tok.UserID)
	if errors.Is(err, ErrNotFound) {
		return Principal{}, nil, ErrInvalidCredentials
	}

	if err != nil {
		return Principal{}, nil, fmt.Errorf("app: resolve token owner: %w", err)
	}

	if !owner.CanUseAPI() {
		return Principal{}, nil, ErrInvalidCredentials
	}

	return Principal{UserID: tok.UserID, TokenID: tok.ID, Owner: owner.Label()}, owner.Policy, nil
}
