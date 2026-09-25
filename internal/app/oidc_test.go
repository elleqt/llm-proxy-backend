package app_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/app/mocks"
	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const testIssuer = "https://idp.example.com"

// loginChallenge is what the transport held between Begin and the callback. Every
// test redeems it with its own state, so the state gate is open unless a test says
// otherwise.
var loginChallenge = app.Challenge{State: "state-1", Nonce: "nonce-1", Verifier: "verifier-1"}

func newOIDC(t *testing.T, users app.UserRepo, idents app.IdentityRepo, sessions app.SessionRepo,
	idp app.IdentityProvider, cfg app.OIDCConfig,
) *app.OIDCService {
	t.Helper()

	svc, err := app.NewOIDCService(users, idents, sessions, idp, nopAudit{}, systemClock{}, cfg)
	require.NoError(t, err, "NewOIDCService")

	return svc
}

func complete(svc *app.OIDCService) (app.Session, error) {
	return svc.Complete(context.Background(), "code", loginChallenge.State, loginChallenge, app.SessionMeta{})
}

// acceptingSessions stands in for a store that takes exactly one new session.
func acceptingSessions(t *testing.T) *mocks.SessionRepo {
	t.Helper()

	sessions := mocks.NewSessionRepo(t)
	sessions.EXPECT().Create(mock.Anything, mock.Anything).Return(nil).Once()

	return sessions
}

func idpAsserting(t *testing.T, claims app.Claims) *mocks.IdentityProvider {
	t.Helper()

	idp := mocks.NewIdentityProvider(t)
	// The challenge is matched exactly: the provider must receive the same nonce and
	// verifier the login started with, or it cannot bind the token to this browser.
	idp.EXPECT().Exchange(mock.Anything, "code", loginChallenge).Return(claims, nil)

	return idp
}

func ruleStrings(p access.Policy) []string {
	out := make([]string, len(p))
	for i, r := range p {
		out[i] = r.String()
	}

	slices.Sort(out)

	return out
}

func TestLoginRejectedWithoutRequiredGroup(t *testing.T) {
	users, idents := mocks.NewUserRepo(t), mocks.NewIdentityRepo(t)
	idp := idpAsserting(t, app.Claims{
		Issuer: testIssuer, Subject: "sub-1",
		Email: "someone@example.com", EmailVerified: true, Groups: []string{"/other"},
	})

	// No expectations on idents or sessions: nothing may be looked up or written
	// for a person outside the gate group.
	svc := newOIDC(t, users, idents, mocks.NewSessionRepo(t), idp, app.OIDCConfig{
		RequiredGroup: "/gate",
		AllowSignUp:   true,
	})

	_, err := complete(svc)
	require.ErrorIs(t, err, app.ErrForbidden)
}

func TestUnknownSubjectRejectedWhenSignUpDisabled(t *testing.T) {
	users, idents := mocks.NewUserRepo(t), mocks.NewIdentityRepo(t)
	idp := idpAsserting(t, app.Claims{
		Issuer: testIssuer, Subject: "sub-unknown",
		Email: "stranger@example.com", EmailVerified: true, Groups: []string{"/gate"},
	})
	idents.EXPECT().BySubject(mock.Anything, testIssuer, "sub-unknown").Return(uuid.Nil, app.ErrNotFound)
	idents.EXPECT().PendingByEmail(mock.Anything, testIssuer, "stranger@example.com").Return(uuid.Nil, app.ErrNotFound)

	svc := newOIDC(t, users, idents, mocks.NewSessionRepo(t), idp, app.OIDCConfig{
		RequiredGroup: "/gate",
		AllowSignUp:   false,
	})

	_, err := complete(svc)
	require.ErrorIs(t, err, app.ErrForbidden)

	users.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}

func TestPendingIdentityLinksSubjectOnce(t *testing.T) {
	users, idents := mocks.NewUserRepo(t), mocks.NewIdentityRepo(t)
	invited := humanUser("invited@example.com")

	idp := idpAsserting(t, app.Claims{
		Issuer: testIssuer, Subject: "sub-1",
		Email: "invited@example.com", EmailVerified: true, Groups: []string{"/gate"},
	})
	idents.EXPECT().BySubject(mock.Anything, testIssuer, "sub-1").Return(uuid.Nil, app.ErrNotFound)
	idents.EXPECT().PendingByEmail(mock.Anything, testIssuer, "invited@example.com").Return(invited.ID, nil)
	idents.EXPECT().Link(mock.Anything, invited.ID, testIssuer, "sub-1").Return(nil).Once()
	idents.EXPECT().ConsumePending(mock.Anything, invited.ID).Return(nil).Once()
	users.EXPECT().ByID(mock.Anything, invited.ID).Return(invited, nil)

	svc := newOIDC(t, users, idents, acceptingSessions(t), idp, app.OIDCConfig{
		RequiredGroup: "/gate", AllowSignUp: false,
	})

	sess, err := complete(svc)
	require.NoError(t, err, "first login")
	require.Equal(t, invited.ID, sess.UserID, "session, want the invited account")

	users.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}

func TestGroupMappingSetsPolicyAndMarksItIDPManaged(t *testing.T) {
	users, idents := mocks.NewUserRepo(t), mocks.NewIdentityRepo(t)
	existing := humanUser("user@example.com")

	idp := idpAsserting(t, app.Claims{
		Issuer: testIssuer, Subject: "sub-1",
		Email: "user@example.com", EmailVerified: true, Groups: []string{"/gate", "/team-a"},
	})
	idents.EXPECT().BySubject(mock.Anything, testIssuer, "sub-1").Return(existing.ID, nil)
	users.EXPECT().ByID(mock.Anything, existing.ID).Return(existing, nil)

	var saved identity.User

	users.EXPECT().SaveIdentityState(mock.Anything, mock.Anything).
		Run(func(_ context.Context, u identity.User) { saved = u }).Return(nil)

	svc := newOIDC(t, users, idents, acceptingSessions(t), idp, app.OIDCConfig{
		RequiredGroup: "/gate",
		GroupPolicy:   map[string][]string{"/team-a": {"chatgpt:*"}},
	})

	_, err := complete(svc)
	require.NoError(t, err, "Complete")

	require.Equal(t, identity.PolicyIDP, saved.PolicySource, "PolicySource")
	require.Equal(t, []string{"chatgpt:*"}, ruleStrings(saved.Policy), "policy")
}

func TestWithoutGroupMappingPolicyStaysLocal(t *testing.T) {
	users, idents := mocks.NewUserRepo(t), mocks.NewIdentityRepo(t)
	existing := humanUser("user@example.com")
	existing.Policy = mustPolicy(t, "claude:claude-sonnet-5")

	idp := idpAsserting(t, app.Claims{
		Issuer: testIssuer, Subject: "sub-1",
		Email: "user@example.com", EmailVerified: true, Groups: []string{"/gate"},
	})
	idents.EXPECT().BySubject(mock.Anything, testIssuer, "sub-1").Return(existing.ID, nil)
	users.EXPECT().ByID(mock.Anything, existing.ID).Return(existing, nil)

	svc := newOIDC(t, users, idents, acceptingSessions(t), idp, app.OIDCConfig{
		RequiredGroup: "/gate",
	})

	_, err := complete(svc)
	require.NoError(t, err, "Complete")

	users.AssertNotCalled(t, "SaveIdentityState", mock.Anything, mock.Anything)
}

// A callback that does not carry the state this browser was given is someone
// else's login. The code is never redeemed, so an attacker's code cannot be spent in
// the victim's browser.
func TestCompleteRefusesAMismatchedStateWithoutCallingTheIdP(t *testing.T) {
	cases := []struct {
		name     string
		state    string
		expected string
	}{
		{"different state", "state-from-another-browser", "state-1"},
		{"callback without state", "", "state-1"},
		// Two empty strings compare equal; a transport that lost its cookie must not
		// thereby accept a callback that also carries no state.
		{"both empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// No expectations anywhere: the IdP, the stores and the sessions are all
			// untouched by a refused callback.
			svc := newOIDC(t, mocks.NewUserRepo(t), mocks.NewIdentityRepo(t), mocks.NewSessionRepo(t),
				mocks.NewIdentityProvider(t), app.OIDCConfig{AllowSignUp: true})

			ch := loginChallenge
			ch.State = tc.expected

			_, err := svc.Complete(context.Background(), "code", tc.state, ch, app.SessionMeta{})
			require.ErrorIs(t, err, app.ErrInvalidCredentials)
		})
	}
}

// An invitation is addressed to a mailbox. An address the IdP has not verified is
// an assertion anyone can make, so it redeems nothing.
func TestUnverifiedEmailDoesNotRedeemAnInvitation(t *testing.T) {
	users, idents := mocks.NewUserRepo(t), mocks.NewIdentityRepo(t)
	invited := uuid.New()

	idp := idpAsserting(t, app.Claims{
		Issuer: testIssuer, Subject: "sub-squatter",
		Email: "invited@example.com", EmailVerified: false, Groups: []string{"/gate"},
	})
	idents.EXPECT().BySubject(mock.Anything, testIssuer, "sub-squatter").Return(uuid.Nil, app.ErrNotFound)
	// The invitation exists: were it consulted, it would be found.
	idents.EXPECT().PendingByEmail(mock.Anything, testIssuer, "invited@example.com").Return(invited, nil).Maybe()

	svc := newOIDC(t, users, idents, mocks.NewSessionRepo(t), idp, app.OIDCConfig{
		RequiredGroup: "/gate", AllowSignUp: false,
	})

	_, err := complete(svc)
	require.ErrorIs(t, err, app.ErrForbidden)

	idents.AssertNotCalled(t, "Link", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	idents.AssertNotCalled(t, "ConsumePending", mock.Anything, mock.Anything)
}

// A valid subject is not a licence. A blocked account is refused like a wrong
// password — not with an error that tells the caller the account exists and is
// blocked — and gets no session.
func TestBlockedUserIsRefusedWithoutASession(t *testing.T) {
	users, idents := mocks.NewUserRepo(t), mocks.NewIdentityRepo(t)
	blocked := humanUser("blocked@example.com")
	blocked.Status = identity.StatusBlocked

	idp := idpAsserting(t, app.Claims{
		Issuer: testIssuer, Subject: "sub-blocked",
		Email: "blocked@example.com", EmailVerified: true, Groups: []string{"/gate"},
	})
	idents.EXPECT().BySubject(mock.Anything, testIssuer, "sub-blocked").Return(blocked.ID, nil)
	users.EXPECT().ByID(mock.Anything, blocked.ID).Return(blocked, nil)

	// A group mapping is configured so that a gate placed too late would also
	// rewrite the blocked user's policy; the users mock has no SaveIdentityState.
	svc := newOIDC(t, users, idents, mocks.NewSessionRepo(t), idp, app.OIDCConfig{
		RequiredGroup: "/gate",
		GroupPolicy:   map[string][]string{"/gate": {"claude:*"}},
	})

	_, err := complete(svc)
	require.ErrorIs(t, err, app.ErrInvalidCredentials)
}

// Every mapped group the user holds contributes; unmapped groups contribute
// nothing; a rule granted twice is stored once.
func TestGroupPolicyIsTheUnionOfEveryMappedGroup(t *testing.T) {
	users, idents := mocks.NewUserRepo(t), mocks.NewIdentityRepo(t)
	existing := humanUser("user@example.com")

	idp := idpAsserting(t, app.Claims{
		Issuer: testIssuer, Subject: "sub-1", Email: "user@example.com", EmailVerified: true,
		Groups: []string{"/team-b", "/unrelated", "/team-a"},
	})
	idents.EXPECT().BySubject(mock.Anything, testIssuer, "sub-1").Return(existing.ID, nil)
	users.EXPECT().ByID(mock.Anything, existing.ID).Return(existing, nil)

	var saved identity.User

	users.EXPECT().SaveIdentityState(mock.Anything, mock.Anything).
		Run(func(_ context.Context, u identity.User) { saved = u }).Return(nil)

	svc := newOIDC(t, users, idents, acceptingSessions(t), idp, app.OIDCConfig{
		GroupPolicy: map[string][]string{
			"/team-a":   {"claude:*"},
			"/team-b":   {"openai:gpt-*", "claude:*"},
			"/everyone": {"*:*"},
		},
	})

	_, err := complete(svc)
	require.NoError(t, err, "Complete")

	require.Equal(t, []string{"claude:*", "openai:gpt-*"}, ruleStrings(saved.Policy), "policy")
}

// The mapping owns the policy. Holding none of the mapped groups is an empty
// policy, not the one the account had before — otherwise leaving a group at the IdP
// would never take a grant away.
func TestUserWithNoMappedGroupGetsAnEmptyPolicy(t *testing.T) {
	users, idents := mocks.NewUserRepo(t), mocks.NewIdentityRepo(t)
	existing := humanUser("user@example.com")
	existing.Policy = mustPolicy(t, "claude:*")
	existing.PolicySource = identity.PolicyIDP

	idp := idpAsserting(t, app.Claims{
		Issuer: testIssuer, Subject: "sub-1", Email: "user@example.com", EmailVerified: true,
		Groups: []string{"/gate"},
	})
	idents.EXPECT().BySubject(mock.Anything, testIssuer, "sub-1").Return(existing.ID, nil)
	users.EXPECT().ByID(mock.Anything, existing.ID).Return(existing, nil)

	var saved *identity.User

	users.EXPECT().SaveIdentityState(mock.Anything, mock.Anything).
		Run(func(_ context.Context, u identity.User) { saved = &u }).Return(nil)

	svc := newOIDC(t, users, idents, acceptingSessions(t), idp, app.OIDCConfig{
		RequiredGroup: "/gate",
		GroupPolicy:   map[string][]string{"/team-a": {"claude:*"}},
	})

	_, err := complete(svc)
	require.NoError(t, err, "Complete")

	require.NotNil(t, saved, "the stale policy was not overwritten")
	require.Empty(t, saved.Policy, "saved policy, want empty")
	require.Equal(t, identity.PolicyIDP, saved.PolicySource, "saved policy source, want idp-managed")
}

// A typo in the mapping or the default policy is the operator's problem at
// startup, not a user's at login, and the error names the rule.
func TestNewOIDCServiceRejectsAMalformedRule(t *testing.T) {
	for name, cfg := range map[string]app.OIDCConfig{
		"group policy":   {GroupPolicy: map[string][]string{"/team-a": {"claude:*", "no-colon"}}},
		"default policy": {DefaultPolicy: []string{"claude:*", "no-colon"}},
	} {
		_, err := app.NewOIDCService(mocks.NewUserRepo(t), mocks.NewIdentityRepo(t), mocks.NewSessionRepo(t),
			mocks.NewIdentityProvider(t), nopAudit{}, systemClock{}, cfg)
		require.ErrorIs(t, err, access.ErrMalformedRule, name)
		require.ErrorContains(t, err, "no-colon", "%s: the error must name the rule", name)
	}
}

// With sign-up open and no mapping, a stranger gets an account with the operator's
// default policy, administrator-owned, and their subject is linked to it.
func TestSignUpProvisionsWithTheDefaultPolicy(t *testing.T) {
	users, idents := mocks.NewUserRepo(t), mocks.NewIdentityRepo(t)
	idp := idpAsserting(t, app.Claims{
		Issuer: testIssuer, Subject: "sub-new", Email: "new@example.com", EmailVerified: true,
		Groups: []string{"/gate"}, Name: "New Person",
	})
	idents.EXPECT().BySubject(mock.Anything, testIssuer, "sub-new").Return(uuid.Nil, app.ErrNotFound)
	idents.EXPECT().PendingByEmail(mock.Anything, testIssuer, "new@example.com").Return(uuid.Nil, app.ErrNotFound)

	var created identity.User

	users.EXPECT().Create(mock.Anything, mock.Anything).
		Run(func(_ context.Context, u identity.User) { created = u }).Return(nil)

	var linked uuid.UUID

	idents.EXPECT().Link(mock.Anything, mock.Anything, testIssuer, "sub-new").
		Run(func(_ context.Context, id uuid.UUID, _, _ string) { linked = id }).Return(nil)

	svc := newOIDC(t, users, idents, acceptingSessions(t), idp, app.OIDCConfig{
		RequiredGroup: "/gate",
		AllowSignUp:   true,
		DefaultPolicy: []string{"claude:claude-sonnet-5"},
	})

	sess, err := complete(svc)
	require.NoError(t, err, "Complete")
	require.True(t, created.CanSignIn(), "created user %+v cannot sign in", created)
	require.Equal(t, identity.RoleUser, created.Role, "created role")
	require.Equal(t, "new@example.com", created.Email, "created email, want the asserted address")
	require.Equal(t, "New Person", created.DisplayName, "created name, want the asserted name")
	require.Equal(t, []string{"claude:claude-sonnet-5"}, ruleStrings(created.Policy), "policy, want the default")
	require.Equal(t, identity.PolicyLocal, created.PolicySource, "policy source, want locally managed")
	require.Equal(t, created.ID, linked, "linked id, want the new account")
	require.Equal(t, created.ID, sess.UserID, "session user, want the new account")
}

// A federated sign-in opens the same kind of session a password does, and the
// security log can tell the two methods apart.
func TestOIDCSignInOpensASessionAndAuditsTheMethod(t *testing.T) {
	users, idents := mocks.NewUserRepo(t), mocks.NewIdentityRepo(t)
	sessions, audit := mocks.NewSessionRepo(t), mocks.NewAuditSink(t)
	user := humanUser("user@example.com")
	user.MustChangePassword = true
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	idp := idpAsserting(t, app.Claims{Issuer: testIssuer, Subject: "sub-1", Email: "user@example.com", EmailVerified: true})
	idents.EXPECT().BySubject(mock.Anything, testIssuer, "sub-1").Return(user.ID, nil)
	users.EXPECT().ByID(mock.Anything, user.ID).Return(user, nil)

	var stored app.Session

	sessions.EXPECT().Create(mock.Anything, mock.Anything).
		Run(func(_ context.Context, s app.Session) { stored = s }).Return(nil)

	var recorded app.AuditEvent

	audit.EXPECT().Record(mock.Anything, mock.Anything).
		Run(func(_ context.Context, e app.AuditEvent) { recorded = e }).Return(nil)

	svc, err := app.NewOIDCService(users, idents, sessions, idp, audit, fixedClock{now: now}, app.OIDCConfig{})
	require.NoError(t, err, "NewOIDCService")

	got, err := svc.Complete(context.Background(), "code", loginChallenge.State, loginChallenge,
		app.SessionMeta{IP: "198.51.100.7", UserAgent: "a browser"})
	require.NoError(t, err, "Complete")
	require.NotEmpty(t, got.ID, "want the plaintext id returned")
	require.Empty(t, stored.ID, "the stored session carries the plaintext id")
	require.Equal(t, app.HashSessionID(got.ID), stored.IDHash, "stored hash, want the hash of the returned id")
	require.True(t, stored.ExpiresAt.Equal(now.Add(app.SessionTTL)),
		"session expires at %v, want the local window ending %v", stored.ExpiresAt, now.Add(app.SessionTTL))
	require.Equal(t, "auth.signin.oidc", recorded.Action, "audit action")
	require.Equal(t, user.ID, recorded.ActorID, "audit actor")
	require.Equal(t, "198.51.100.7", recorded.IP, "audit IP")
}

// Begin hands the transport the very challenge the IdP was told about, and the three
// secrets in it are independent full-strength values.
func TestBeginReturnsTheChallengeTheAuthURLWasBuiltFrom(t *testing.T) {
	idp := mocks.NewIdentityProvider(t)

	var sent app.Challenge

	idp.EXPECT().AuthURL(mock.Anything).
		Run(func(ch app.Challenge) { sent = ch }).Return("https://idp.example.com/auth?x=1")

	svc := newOIDC(t, mocks.NewUserRepo(t), mocks.NewIdentityRepo(t), mocks.NewSessionRepo(t), idp, app.OIDCConfig{})

	url, ch, err := svc.Begin()
	require.NoError(t, err, "Begin")
	require.Equal(t, "https://idp.example.com/auth?x=1", url, "Begin URL")
	require.Equal(t, sent, ch, "Begin challenge, want the one the IdP was sent")

	fields := []string{ch.State, ch.Nonce, ch.Verifier}
	for _, f := range fields {
		raw, err := base64.RawURLEncoding.DecodeString(f)
		require.NoError(t, err, "challenge field %q, want base64url", f)
		require.Len(t, raw, 32, "challenge field %q", f)
	}

	require.NotEqual(t, ch.State, ch.Nonce, "challenge fields are not independent")
	require.NotEqual(t, ch.Nonce, ch.Verifier, "challenge fields are not independent")
	require.NotEqual(t, ch.State, ch.Verifier, "challenge fields are not independent")
}

// An unverified address must not occupy users.email: whoever typed a colleague's
// address into their IdP profile first would own that address here. The sign-up
// itself still goes ahead — the subject is the identity.
func TestUnverifiedSignUpStoresNoEmail(t *testing.T) {
	users, idents := mocks.NewUserRepo(t), mocks.NewIdentityRepo(t)
	idp := idpAsserting(t, app.Claims{
		Issuer: testIssuer, Subject: "sub-new", Email: "colleague@example.com", EmailVerified: false,
	})
	idents.EXPECT().BySubject(mock.Anything, testIssuer, "sub-new").Return(uuid.Nil, app.ErrNotFound)

	var created identity.User

	users.EXPECT().Create(mock.Anything, mock.Anything).
		Run(func(_ context.Context, u identity.User) { created = u }).Return(nil)
	idents.EXPECT().Link(mock.Anything, mock.Anything, testIssuer, "sub-new").Return(nil)

	svc := newOIDC(t, users, idents, acceptingSessions(t), idp, app.OIDCConfig{AllowSignUp: true})
	_, err := complete(svc)
	require.NoError(t, err, "Complete")

	require.Empty(t, created.Email, "want no email stored for an unverified address")
}

// Create and Link are two writes. When the second one fails, the same subject's next
// attempt must finish the job rather than collide with the account the first one
// left behind.
func TestSignUpResumesAfterALinkFailure(t *testing.T) {
	users, idents := mocks.NewUserRepo(t), mocks.NewIdentityRepo(t)
	claims := app.Claims{Issuer: testIssuer, Subject: "sub-new", Email: "new@example.com", EmailVerified: true}
	idp := mocks.NewIdentityProvider(t)
	idp.EXPECT().Exchange(mock.Anything, "code", loginChallenge).Return(claims, nil).Times(2)
	idents.EXPECT().BySubject(mock.Anything, testIssuer, "sub-new").Return(uuid.Nil, app.ErrNotFound).Times(2)
	idents.EXPECT().PendingByEmail(mock.Anything, testIssuer, "new@example.com").Return(uuid.Nil, app.ErrNotFound).Times(2)

	var orphan identity.User

	users.EXPECT().Create(mock.Anything, mock.Anything).
		Run(func(_ context.Context, u identity.User) { orphan = u }).Return(nil).Once()
	users.EXPECT().Create(mock.Anything, mock.Anything).
		Return(fmt.Errorf("%w: users_email_lower_key", app.ErrConflict)).Once()
	idents.EXPECT().Link(mock.Anything, mock.Anything, testIssuer, "sub-new").
		Return(errors.New("connection reset")).Once()

	svc := newOIDC(t, users, idents, acceptingSessions(t), idp, app.OIDCConfig{AllowSignUp: true})
	_, err := complete(svc)
	require.Error(t, err, "first attempt: want the Link failure reported")

	// The retry: Create now conflicts with the orphan, which is found by the id
	// derived from this subject and linked.
	users.EXPECT().ByID(mock.Anything, orphan.ID).Return(orphan, nil).Once()
	idents.EXPECT().Link(mock.Anything, orphan.ID, testIssuer, "sub-new").Return(nil).Once()

	sess, err := complete(svc)
	require.NoError(t, err, "retry")
	require.Equal(t, orphan.ID, sess.UserID, "retry session, want the resumed account")
}

// A sign-up whose address belongs to another account is refused. Resolving the
// conflict by address — find the holder, link to it — would hand that account to
// whoever asserted the address, so neither ByEmail nor Link may be called.
func TestSignUpConflictWithAnotherAccountIsRefusedAndNeverLinked(t *testing.T) {
	users, idents := mocks.NewUserRepo(t), mocks.NewIdentityRepo(t)
	idp := idpAsserting(t, app.Claims{
		Issuer: testIssuer, Subject: "sub-stranger", Email: "taken@example.com", EmailVerified: true,
	})
	idents.EXPECT().BySubject(mock.Anything, testIssuer, "sub-stranger").Return(uuid.Nil, app.ErrNotFound)
	idents.EXPECT().PendingByEmail(mock.Anything, testIssuer, "taken@example.com").Return(uuid.Nil, app.ErrNotFound)

	var derived uuid.UUID

	users.EXPECT().Create(mock.Anything, mock.Anything).
		Run(func(_ context.Context, u identity.User) { derived = u.ID }).
		Return(fmt.Errorf("%w: users_email_lower_key", app.ErrConflict))
	// The only lookup allowed is by this subject's own derived id, and it finds
	// nothing: the conflicting row is somebody else's.
	users.EXPECT().ByID(mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, id uuid.UUID) (identity.User, error) {
			assert.Equal(t, derived, id, "ByID, want only the derived id")

			return identity.User{}, app.ErrNotFound
		})

	svc := newOIDC(t, users, idents, mocks.NewSessionRepo(t), idp, app.OIDCConfig{AllowSignUp: true})
	_, err := complete(svc)
	require.ErrorIs(t, err, app.ErrConflict)
}

// Redemption spends the invitation before it links. When the link then fails, the
// invitation is already gone: the failure closes, and an administrator re-invites.
func TestInvitationIsSpentEvenWhenTheLinkFails(t *testing.T) {
	users, idents := mocks.NewUserRepo(t), mocks.NewIdentityRepo(t)
	invited := humanUser("invited@example.com")
	idp := idpAsserting(t, app.Claims{
		Issuer: testIssuer, Subject: "sub-1", Email: "invited@example.com", EmailVerified: true,
	})
	idents.EXPECT().BySubject(mock.Anything, testIssuer, "sub-1").Return(uuid.Nil, app.ErrNotFound)
	idents.EXPECT().PendingByEmail(mock.Anything, testIssuer, "invited@example.com").Return(invited.ID, nil)
	users.EXPECT().ByID(mock.Anything, invited.ID).Return(invited, nil)
	idents.EXPECT().ConsumePending(mock.Anything, invited.ID).Return(nil).Once()
	idents.EXPECT().Link(mock.Anything, invited.ID, testIssuer, "sub-1").Return(errors.New("connection reset"))

	svc := newOIDC(t, users, idents, mocks.NewSessionRepo(t), idp, app.OIDCConfig{})
	_, err := complete(svc)
	require.Error(t, err, "want the Link failure reported")
	// The mock's cleanup fails the test if ConsumePending was not called.
}

// An invitation to an account blocked since it was issued is not redeemable: the
// subject is not linked to it and the invitation is not spent.
func TestBlockedInviteeIsNeitherLinkedNorConsumed(t *testing.T) {
	users, idents := mocks.NewUserRepo(t), mocks.NewIdentityRepo(t)
	invited := humanUser("invited@example.com")
	invited.Status = identity.StatusBlocked
	idp := idpAsserting(t, app.Claims{
		Issuer: testIssuer, Subject: "sub-1", Email: "invited@example.com", EmailVerified: true,
	})
	idents.EXPECT().BySubject(mock.Anything, testIssuer, "sub-1").Return(uuid.Nil, app.ErrNotFound)
	idents.EXPECT().PendingByEmail(mock.Anything, testIssuer, "invited@example.com").Return(invited.ID, nil)
	users.EXPECT().ByID(mock.Anything, invited.ID).Return(invited, nil)

	// No Link or ConsumePending expectation: either call fails the test.
	svc := newOIDC(t, users, idents, mocks.NewSessionRepo(t), idp, app.OIDCConfig{})
	_, err := complete(svc)
	require.ErrorIs(t, err, app.ErrInvalidCredentials)
}

// The derived id belongs to the subject, not to the address. Two subjects asserting
// one verified address get two ids, so the second one's conflict can never resume
// onto the first one's account.
func TestSecondSubjectWithTheSameEmailIsNotResumedOntoTheFirstAccount(t *testing.T) {
	users, idents := mocks.NewUserRepo(t), mocks.NewIdentityRepo(t)

	// A minimal users table: unique by id and by address.
	stored := map[uuid.UUID]identity.User{}

	users.EXPECT().Create(mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, user identity.User) error {
			for _, other := range stored {
				if other.ID == user.ID || (user.Email != "" && other.Email == user.Email) {
					return fmt.Errorf("%w: users_email_lower_key", app.ErrConflict)
				}
			}

			stored[user.ID] = user

			return nil
		})
	users.EXPECT().ByID(mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, id uuid.UUID) (identity.User, error) {
			if u, ok := stored[id]; ok {
				return u, nil
			}

			return identity.User{}, app.ErrNotFound
		}).Maybe()

	claimsA := app.Claims{Issuer: testIssuer, Subject: "sub-a", Email: "shared@example.com", EmailVerified: true}
	claimsB := app.Claims{Issuer: testIssuer, Subject: "sub-b", Email: "shared@example.com", EmailVerified: true}
	idp := mocks.NewIdentityProvider(t)
	idp.EXPECT().Exchange(mock.Anything, "code", loginChallenge).Return(claimsA, nil).Once()
	idp.EXPECT().Exchange(mock.Anything, "code", loginChallenge).Return(claimsB, nil).Once()

	for _, sub := range []string{"sub-a", "sub-b"} {
		idents.EXPECT().BySubject(mock.Anything, testIssuer, sub).Return(uuid.Nil, app.ErrNotFound)
	}

	idents.EXPECT().PendingByEmail(mock.Anything, testIssuer, "shared@example.com").Return(uuid.Nil, app.ErrNotFound)
	// Only subject A is ever linked; a Link for sub-b fails the test.
	var linkedA uuid.UUID

	idents.EXPECT().Link(mock.Anything, mock.Anything, testIssuer, "sub-a").
		Run(func(_ context.Context, id uuid.UUID, _, _ string) { linkedA = id }).Return(nil).Once()

	svc := newOIDC(t, users, idents, acceptingSessions(t), idp, app.OIDCConfig{AllowSignUp: true})
	_, err := complete(svc)
	require.NoError(t, err, "subject A")

	_, err = complete(svc)
	require.ErrorIs(t, err, app.ErrConflict, "subject B")
	require.Len(t, stored, 1, "want only subject A's account")
	require.Equal(t, "shared@example.com", stored[linkedA].Email, "want only subject A's account")
}

// Resuming is itself a sign-in and goes through the one sign-in rule: an orphan an
// administrator blocked before the link landed is not finished off.
func TestResumeOntoABlockedOrphanIsRefused(t *testing.T) {
	users, idents := mocks.NewUserRepo(t), mocks.NewIdentityRepo(t)
	idp := idpAsserting(t, app.Claims{
		Issuer: testIssuer, Subject: "sub-new", Email: "new@example.com", EmailVerified: true,
	})
	idents.EXPECT().BySubject(mock.Anything, testIssuer, "sub-new").Return(uuid.Nil, app.ErrNotFound)
	idents.EXPECT().PendingByEmail(mock.Anything, testIssuer, "new@example.com").Return(uuid.Nil, app.ErrNotFound)

	var orphan identity.User

	users.EXPECT().Create(mock.Anything, mock.Anything).
		Run(func(_ context.Context, u identity.User) {
			orphan = u
			orphan.Status = identity.StatusBlocked
		}).
		Return(fmt.Errorf("%w: users_pkey", app.ErrConflict))
	users.EXPECT().ByID(mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, id uuid.UUID) (identity.User, error) {
			if id != orphan.ID {
				return identity.User{}, app.ErrNotFound
			}

			return orphan, nil
		})

	// No Link expectation and no session store expectation: either fails the test.
	svc := newOIDC(t, users, idents, mocks.NewSessionRepo(t), idp, app.OIDCConfig{AllowSignUp: true})
	_, err := complete(svc)
	require.ErrorIs(t, err, app.ErrInvalidCredentials)
}

// A linked account that has no name yet gets the provider's at its next login; one
// that has a name keeps it, whatever the provider now says.
func TestOIDCLoginFillsOnlyAMissingDisplayName(t *testing.T) {
	claims := app.Claims{Issuer: testIssuer, Subject: "sub-1", Email: "user@example.com", EmailVerified: true, Name: "From The IdP"}

	t.Run("empty name is filled", func(t *testing.T) {
		users, idents := mocks.NewUserRepo(t), mocks.NewIdentityRepo(t)
		user := humanUser("user@example.com")
		user.DisplayName = ""
		idents.EXPECT().BySubject(mock.Anything, testIssuer, "sub-1").Return(user.ID, nil)
		users.EXPECT().ByID(mock.Anything, user.ID).Return(user, nil)
		users.EXPECT().FillDisplayName(mock.Anything, user.ID, "From The IdP").Return(true, nil).Once()

		_, err := complete(newOIDC(t, users, idents, acceptingSessions(t), idpAsserting(t, claims), app.OIDCConfig{}))
		require.NoError(t, err, "Complete")
	})

	t.Run("a name already set is kept", func(t *testing.T) {
		users, idents := mocks.NewUserRepo(t), mocks.NewIdentityRepo(t)
		user := humanUser("user@example.com")
		user.DisplayName = "Set By An Admin"
		idents.EXPECT().BySubject(mock.Anything, testIssuer, "sub-1").Return(user.ID, nil)
		users.EXPECT().ByID(mock.Anything, user.ID).Return(user, nil)
		// No FillDisplayName expectation: a call fails the test.
		_, err := complete(newOIDC(t, users, idents, acceptingSessions(t), idpAsserting(t, claims), app.OIDCConfig{}))
		require.NoError(t, err, "Complete")
	})
}
