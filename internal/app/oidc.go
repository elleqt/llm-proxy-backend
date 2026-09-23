package app

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"sort"

	"github.com/google/uuid"

	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
)

// challengeLen is the number of random bytes behind each of state, nonce and PKCE
// verifier. 32 bytes base64url-encode to 43 characters, the minimum RFC 7636 allows
// for a code_verifier, so one length serves all three.
const challengeLen = 32

// NewChallenge draws fresh, independent secrets for one login.
func NewChallenge() (Challenge, error) {
	var ch Challenge
	for _, f := range []*string{&ch.State, &ch.Nonce, &ch.Verifier} {
		buf := make([]byte, challengeLen)
		if _, err := rand.Read(buf); err != nil {
			return Challenge{}, fmt.Errorf("app: read login challenge: %w", err)
		}
		*f = base64.RawURLEncoding.EncodeToString(buf)
	}
	return ch, nil
}

// OIDCConfig is the deployment's federated sign-in policy.
type OIDCConfig struct {
	// RequiredGroup gates every login; empty means no group gate.
	RequiredGroup string
	// AllowSignUp lets a subject with neither a link nor an invitation create an
	// account. Off, the service is closed to strangers.
	AllowSignUp bool
	// DefaultPolicy holds the rule strings a signed-up user starts with when
	// GroupPolicy is empty.
	DefaultPolicy []string
	// GroupPolicy maps a group path, as the IdP sends it, to rule strings. Non-empty,
	// it owns the policy of every federated user: recomputed at each login.
	GroupPolicy map[string][]string
}

// groupGrant is one parsed GroupPolicy entry.
type groupGrant struct {
	group  string
	policy access.Policy
}

// OIDCService signs people in through an OpenID Connect provider.
type OIDCService struct {
	users  UserRepo
	idents IdentityRepo
	idp    IdentityProvider
	sessionOpener

	requiredGroup string
	allowSignUp   bool
	defaultPolicy access.Policy
	// grants is GroupPolicy parsed once and sorted by group, so a malformed rule is a
	// startup failure rather than a login-time one and the stored policy does not
	// depend on the order the IdP lists groups in.
	grants []groupGrant
}

// NewOIDCService parses the default policy and the group mapping up front — the one
// place either is parsed: a rule that does not parse is a configuration error the
// operator sees at startup, never a surprise on some user's login.
func NewOIDCService(users UserRepo, idents IdentityRepo, sessions SessionRepo, idp IdentityProvider, audit AuditSink, clock Clock, cfg OIDCConfig) (*OIDCService, error) {
	defaultPolicy, err := parseRules(cfg.DefaultPolicy)
	if err != nil {
		return nil, fmt.Errorf("app: oidc default policy: %w", err)
	}
	grants := make([]groupGrant, 0, len(cfg.GroupPolicy))
	for group, rules := range cfg.GroupPolicy {
		policy, err := parseRules(rules)
		if err != nil {
			return nil, fmt.Errorf("app: oidc group policy for %q: %w", group, err)
		}
		grants = append(grants, groupGrant{group: group, policy: policy})
	}
	sort.Slice(grants, func(i, j int) bool { return grants[i].group < grants[j].group })

	return &OIDCService{
		users:         users,
		idents:        idents,
		idp:           idp,
		sessionOpener: sessionOpener{sessions: sessions, audit: audit, clock: clock},
		requiredGroup: cfg.RequiredGroup,
		allowSignUp:   cfg.AllowSignUp,
		defaultPolicy: defaultPolicy,
		grants:        grants,
	}, nil
}

// parseRules parses rule strings; the error names the first that does not parse.
func parseRules(raw []string) (access.Policy, error) {
	policy := make(access.Policy, 0, len(raw))
	for _, s := range raw {
		r, err := access.ParseRule(s)
		if err != nil {
			return nil, err
		}
		policy = append(policy, r)
	}
	return policy, nil
}

// Begin starts a login: the URL to send the browser to, and the challenge the
// transport must hold until the callback.
func (s *OIDCService) Begin() (authURL string, ch Challenge, err error) {
	ch, err = NewChallenge()
	if err != nil {
		return "", Challenge{}, err
	}
	return s.idp.AuthURL(ch), ch, nil
}

// Complete finishes a login and opens a session.
//
// A callback whose state does not match the challenge is refused before the code is
// redeemed: the IdP is never called on behalf of a browser that did not start this
// login. The gates then run in order — required group, identity resolution (link,
// verified invitation, sign-up policy), CanSignIn — and only a user through all of
// them has anything written on their behalf.
func (s *OIDCService) Complete(ctx context.Context, code, state string, ch Challenge, meta SessionMeta) (Session, error) {
	if !stateMatches(state, ch.State) {
		return Session{}, ErrInvalidCredentials
	}
	claims, err := s.idp.Exchange(ctx, code, ch)
	if err != nil {
		return Session{}, fmt.Errorf("oidc exchange: %w", err)
	}
	if s.requiredGroup != "" && !slices.Contains(claims.Groups, s.requiredGroup) {
		return Session{}, ErrForbidden
	}

	user, err := s.resolve(ctx, claims)
	if err != nil {
		return Session{}, err
	}

	if len(s.grants) > 0 {
		user.Policy = s.policyFor(claims.Groups)
		user.PolicySource = identity.PolicyIDP
		if err := s.users.SaveIdentityState(ctx, user); err != nil {
			return Session{}, err
		}
	}
	return s.open(ctx, user, "auth.signin.oidc", meta)
}

// stateMatches compares in constant time. An empty value on either side is a
// mismatch: two empty strings are equal, and a transport that lost its cookie must
// not thereby accept a callback that carries no state either.
func stateMatches(got, want string) bool {
	if got == "" || want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// resolve finds or creates the account behind the claims and returns it only if it
// may sign in. Nothing is linked, consumed or created for a user CanSignIn refuses.
func (s *OIDCService) resolve(ctx context.Context, c Claims) (identity.User, error) {
	id, err := s.idents.BySubject(ctx, c.Issuer, c.Subject)
	switch {
	case err == nil:
		return s.eligible(ctx, id)
	case !errors.Is(err, ErrNotFound):
		return identity.User{}, err
	}

	// An invitation is addressed to a mailbox, so only a provider's statement that
	// the person controls that mailbox may redeem it. Unverified, the invitation is
	// invisible and sign-up policy decides as if there were none.
	if c.EmailVerified && c.Email != "" {
		invited, err := s.idents.PendingByEmail(ctx, c.Issuer, c.Email)
		switch {
		case err == nil:
			return s.redeem(ctx, invited, c)
		case !errors.Is(err, ErrNotFound):
			return identity.User{}, err
		}
	}

	if !s.allowSignUp {
		return identity.User{}, ErrForbidden
	}
	return s.signUp(ctx, c)
}

// eligible loads a user and applies the one sign-in rule. The refusal is the same
// answer a wrong password gets: a blocked account is not announced as such.
func (s *OIDCService) eligible(ctx context.Context, id uuid.UUID) (identity.User, error) {
	user, err := s.users.ByID(ctx, id)
	if err != nil {
		return identity.User{}, err
	}
	if !user.CanSignIn() {
		return identity.User{}, ErrInvalidCredentials
	}
	return user, nil
}

// redeem binds the subject to the invited account and retires the invitation. The
// account is checked first, so an invitation to an account blocked since it was
// issued stays unredeemed.
//
// The invitation is spent BEFORE the link is written. Two independent writes can
// fail between them, and this order makes that failure close: the worst case is a
// consumed invitation with no link, which an administrator fixes by re-inviting. The
// other order would leave a live invitation beside a working link — redeemable a
// second time, by a second subject, until it expired.
func (s *OIDCService) redeem(ctx context.Context, invited uuid.UUID, c Claims) (identity.User, error) {
	user, err := s.eligible(ctx, invited)
	if err != nil {
		return identity.User{}, err
	}
	if err := s.idents.ConsumePending(ctx, user.ID); err != nil {
		return identity.User{}, fmt.Errorf("oidc consume invitation: %w", err)
	}
	if err := s.idents.Link(ctx, user.ID, c.Issuer, c.Subject); err != nil {
		return identity.User{}, fmt.Errorf("oidc link invited subject: %w", err)
	}
	return user, nil
}

// signUpID is the id a subject's self-provisioned account gets. Deriving it from the
// subject, rather than drawing it at random, makes sign-up resumable: if the process
// dies between Create and Link, the subject's retry finds its own account by id and
// finishes the link, instead of colliding with it forever. Issuer URLs carry no
// fragment, so "#" joins the pair unambiguously.
func signUpID(issuer, subject string) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte(issuer+"#"+subject))
}

// signUp provisions an account for a stranger. With a group mapping the policy comes
// from the groups, exactly as it would on every later login; without one the
// operator's default applies and stays administrator-owned.
func (s *OIDCService) signUp(ctx context.Context, c Claims) (identity.User, error) {
	user := identity.User{
		ID:           signUpID(c.Issuer, c.Subject),
		Kind:         identity.KindHuman,
		Role:         identity.RoleUser,
		Status:       identity.StatusActive,
		Policy:       s.defaultPolicy,
		PolicySource: identity.PolicyLocal,
		CreatedAt:    s.clock.Now(),
	}
	// users.email is a unique key that local sign-in and invitations resolve by. An
	// address the IdP has not verified must not occupy it, or whoever types a
	// colleague's address into their profile first locks the colleague out of it.
	// The account is still created — the subject is the identity — just without one.
	if c.EmailVerified {
		user.Email = c.Email
	}
	if len(s.grants) > 0 {
		user.Policy = s.policyFor(c.Groups)
		user.PolicySource = identity.PolicyIDP
	}
	if err := s.users.Create(ctx, user); err != nil {
		if !errors.Is(err, ErrConflict) {
			return identity.User{}, fmt.Errorf("oidc sign-up: %w", err)
		}
		// Either this subject's own account from an attempt that died before Link,
		// or somebody else's account holding the address. Only the first may be
		// continued, and only the derived id can tell them apart: resolving the
		// conflict by address would attach a stranger's subject to another
		// person's account.
		existing, lerr := s.eligible(ctx, user.ID)
		switch {
		case errors.Is(lerr, ErrNotFound):
			return identity.User{}, fmt.Errorf("oidc sign-up: %w", err)
		case lerr != nil:
			return identity.User{}, lerr
		}
		user = existing
	}
	if err := s.idents.Link(ctx, user.ID, c.Issuer, c.Subject); err != nil {
		return identity.User{}, fmt.Errorf("oidc link new subject: %w", err)
	}
	return user, nil
}

// policyFor is the union of the rules of every mapped group the user holds. Holding
// none yields an empty, non-nil policy: signed in, entitled to no model.
func (s *OIDCService) policyFor(groups []string) access.Policy {
	policy := access.Policy{}
	seen := map[string]bool{}
	for _, g := range s.grants {
		if !slices.Contains(groups, g.group) {
			continue
		}
		for _, r := range g.policy {
			if key := r.String(); !seen[key] {
				seen[key] = true
				policy = append(policy, r)
			}
		}
	}
	return policy
}
