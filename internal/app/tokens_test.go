package app_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/app/mocks"
	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/domain/credentials"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// frozen is the instant the injected clock reports, so every timestamp the service
// writes is asserted exactly rather than within a tolerance.
var frozen = time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)

func TestIssueForOtherUserRequiresAdmin(t *testing.T) {
	users, tokens, clock := mocks.NewUserRepo(t), mocks.NewTokenRepo(t), mocks.NewClock(t)
	svc := app.NewTokenService(users, tokens, nopAudit{}, clock, discardLogger{})

	actor := identity.User{ID: uuid.New(), Kind: identity.KindHuman, Role: identity.RoleUser}

	_, _, err := svc.Issue(context.Background(), actor, uuid.New(), "someone else")
	require.Same(t, app.ErrForbidden, err, "want the bare ErrForbidden")
	// The strict mocks carry no expectations: a refusal must not reach the owner
	// lookup or the repository at all.
}

func TestAdminIssuesForServiceAccount(t *testing.T) {
	users, tokens, clock := mocks.NewUserRepo(t), mocks.NewTokenRepo(t), mocks.NewClock(t)
	audit := mocks.NewAuditSink(t)
	svc := app.NewTokenService(users, tokens, audit, clock, discardLogger{})

	service := identity.NewService(uuid.New(), "chat-panel", access.Policy{})
	users.EXPECT().ByID(mock.Anything, service.ID).Return(service, nil)

	var stored credentials.Token

	tokens.EXPECT().Create(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, tok credentials.Token) error {
		stored = tok

		return nil
	})

	var event app.AuditEvent

	audit.EXPECT().Record(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, e app.AuditEvent) error {
		event = e

		return nil
	})
	clock.EXPECT().Now().Return(frozen)

	admin := identity.User{ID: uuid.New(), Kind: identity.KindHuman, Role: identity.RoleAdmin}

	issued, secret, err := svc.Issue(context.Background(), admin, service.ID, "panel")
	require.NoError(t, err, "Issue")
	require.NotEmpty(t, secret, "issued secret must be returned exactly once")
	// This is the only successful issue where the actor is not the owner, so it is the
	// only place that can catch a key minted for the administrator who asked for it.
	require.Equal(t, service.ID, stored.UserID, "persisted owner: want the service account (the actor is %v)", admin.ID)
	require.Equal(t, service.ID, issued.UserID, "returned owner: want the service account")
	require.Equal(t, "panel", stored.Label, "persisted label")
	require.Equal(t, "panel", issued.Label, "returned label")
	require.Equal(t, credentials.HashSecret(secret), stored.Hash, "the persisted hash does not verify the returned secret")
	require.Equal(t, service.ID.String(), event.Detail["owner_id"], "audit owner_id: want the service account")
	require.Equal(t, admin.ID, event.ActorID, "audit actor: want the admin")
}

func TestIssueForUnknownOwnerIsNotFound(t *testing.T) {
	users, tokens, clock := mocks.NewUserRepo(t), mocks.NewTokenRepo(t), mocks.NewClock(t)
	svc := app.NewTokenService(users, tokens, nopAudit{}, clock, discardLogger{})

	owner := uuid.New()
	users.EXPECT().ByID(mock.Anything, owner).Return(identity.User{}, app.ErrNotFound)

	admin := identity.User{ID: uuid.New(), Kind: identity.KindHuman, Role: identity.RoleAdmin}

	_, _, err := svc.Issue(context.Background(), admin, owner, "panel")
	require.ErrorIs(t, err, app.ErrNotFound)
}

func TestIssueReturnsNoSecretWhenTheRowIsNotPersisted(t *testing.T) {
	users, tokens, clock := mocks.NewUserRepo(t), mocks.NewTokenRepo(t), mocks.NewClock(t)
	audit := mocks.NewAuditSink(t)
	svc := app.NewTokenService(users, tokens, audit, clock, discardLogger{})
	clock.EXPECT().Now().Return(frozen)

	owner := identity.User{ID: uuid.New(), Kind: identity.KindHuman, Role: identity.RoleUser}
	users.EXPECT().ByID(mock.Anything, owner.ID).Return(owner, nil)

	boom := errors.New("write failed")
	tokens.EXPECT().Create(mock.Anything, mock.Anything).Return(boom)

	issued, secret, err := svc.Issue(context.Background(), owner, owner.ID, "laptop")
	require.ErrorIs(t, err, boom, "want the repository failure")
	require.Empty(t, secret, "a secret was handed out for a token that was never stored")
	require.Zero(t, issued, "returned record: want the zero token")
	// audit is a strict mock with no expectation: a failed create records nothing, and
	// any Record call fails the test.
}

func TestIssueRetractsTheRowWhenTheAuditRecordFails(t *testing.T) {
	users, tokens, clock := mocks.NewUserRepo(t), mocks.NewTokenRepo(t), mocks.NewClock(t)
	audit := mocks.NewAuditSink(t)
	svc := app.NewTokenService(users, tokens, audit, clock, discardLogger{})
	clock.EXPECT().Now().Return(frozen)

	owner := identity.User{ID: uuid.New(), Kind: identity.KindHuman, Role: identity.RoleUser}
	users.EXPECT().ByID(mock.Anything, owner.ID).Return(owner, nil)
	tokens.EXPECT().Create(mock.Anything, mock.Anything).Return(nil)

	sinkDown := errors.New("audit sink unreachable")
	audit.EXPECT().Record(mock.Anything, mock.Anything).Return(sinkDown)

	var saved credentials.Token

	tokens.EXPECT().Save(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, tok credentials.Token) error {
		saved = tok

		return nil
	})

	_, secret, err := svc.Issue(context.Background(), owner, owner.ID, "laptop")
	require.ErrorIs(t, err, sinkDown, "want the audit failure")
	require.Empty(t, secret, "a secret was handed out for an unaudited token")
	// The row is durable by now, so it must not be left unaudited *and* live.
	require.False(t, saved.Active(), "the unaudited token was left active")
	require.NotNil(t, saved.RevokedBy, "compensating revoke RevokedBy")
	require.Equal(t, owner.ID, *saved.RevokedBy, "compensating revoke RevokedBy")
	require.NotNil(t, saved.RevokedAt, "compensating revoke RevokedAt")
	require.True(t, saved.RevokedAt.Equal(frozen), "compensating revoke RevokedAt = %v, want %v", *saved.RevokedAt, frozen)
}

func TestIssueErrorNamesBothFailuresWhenTheRetractionAlsoFails(t *testing.T) {
	users, tokens, clock := mocks.NewUserRepo(t), mocks.NewTokenRepo(t), mocks.NewClock(t)
	audit, logger := mocks.NewAuditSink(t), mocks.NewLogger(t)
	svc := app.NewTokenService(users, tokens, audit, clock, logger)
	clock.EXPECT().Now().Return(frozen)

	owner := identity.User{ID: uuid.New(), Kind: identity.KindHuman, Role: identity.RoleUser}
	users.EXPECT().ByID(mock.Anything, owner.ID).Return(owner, nil)

	var stored credentials.Token

	tokens.EXPECT().Create(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, tok credentials.Token) error {
		stored = tok

		return nil
	})

	sinkDown := errors.New("audit sink unreachable")
	audit.EXPECT().Record(mock.Anything, mock.Anything).Return(sinkDown)

	saveDown := errors.New("save failed")
	tokens.EXPECT().Save(mock.Anything, mock.Anything).Return(saveDown)

	var warned string

	logger.EXPECT().Warn(mock.Anything, mock.Anything).Run(func(msg string, attrs ...slog.Attr) {
		warned = fmt.Sprint(msg, attrs)
	})

	_, secret, err := svc.Issue(context.Background(), owner, owner.ID, "laptop")
	require.ErrorIs(t, err, sinkDown, "want it to wrap the audit failure")
	require.ErrorContains(t, err, saveDown.Error(), "want it to name the failed compensating write too")
	require.Empty(t, secret, "a secret was handed out for an unaudited token")
	// A live row no audit record describes is the one outcome an operator must fix by
	// hand, so the error string handed to the caller cannot be its only trace.
	for _, want := range []string{stored.ID.String(), owner.ID.String(), sinkDown.Error(), saveDown.Error()} {
		require.Contains(t, warned, want, "warning does not name it")
	}
}

func TestOwnerIssuesListsAndRevokesOwnToken(t *testing.T) {
	users, tokens, clock := mocks.NewUserRepo(t), mocks.NewTokenRepo(t), mocks.NewClock(t)
	svc := app.NewTokenService(users, tokens, nopAudit{}, clock, discardLogger{})
	clock.EXPECT().Now().Return(frozen)

	owner := identity.User{ID: uuid.New(), Kind: identity.KindHuman, Role: identity.RoleUser}
	users.EXPECT().ByID(mock.Anything, owner.ID).Return(owner, nil)

	var stored credentials.Token

	tokens.EXPECT().Create(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, tok credentials.Token) error {
		stored = tok

		return nil
	})

	ctx := context.Background()

	issued, secret, err := svc.Issue(ctx, owner, owner.ID, "laptop")
	require.NoError(t, err, "Issue")
	require.Equal(t, issued.ID, stored.ID, "persisted token id")
	require.Equal(t, owner.ID, stored.UserID, "persisted token owner")
	require.Equal(t, "laptop", stored.Label, "persisted token label")
	require.Equal(t, credentials.HashSecret(secret), stored.Hash, "the persisted hash does not verify the returned secret")
	require.True(t, stored.CreatedAt.Equal(frozen), "CreatedAt = %v, want the injected clock %v", stored.CreatedAt, frozen)
	require.True(t, stored.Active(), "a freshly issued token must be active")

	tokens.EXPECT().ListByUser(mock.Anything, owner.ID).RunAndReturn(func(_ context.Context, _ uuid.UUID) ([]credentials.Token, error) {
		return []credentials.Token{stored}, nil
	})

	listed, err := svc.List(ctx, owner, owner.ID)
	require.NoError(t, err, "List")
	require.Len(t, listed, 1, "List: want the issued token")
	require.Equal(t, issued.ID, listed[0].ID, "List: want the issued token")

	tokens.EXPECT().ByID(mock.Anything, issued.ID).RunAndReturn(func(_ context.Context, _ uuid.UUID) (credentials.Token, error) {
		return stored, nil
	})

	var saved credentials.Token

	tokens.EXPECT().Save(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, tok credentials.Token) error {
		saved = tok

		return nil
	})

	require.NoError(t, svc.Revoke(ctx, owner, issued.ID), "Revoke")
	require.False(t, saved.Active(), "the saved token is still active after Revoke")
	require.NotNil(t, saved.RevokedBy, "RevokedBy")
	require.Equal(t, owner.ID, *saved.RevokedBy, "RevokedBy: want the actor")
	require.NotNil(t, saved.RevokedAt, "RevokedAt")
	require.True(t, saved.RevokedAt.Equal(frozen), "RevokedAt = %v, want the injected clock %v", *saved.RevokedAt, frozen)
}

func TestListForOtherUserRequiresAdmin(t *testing.T) {
	users, tokens, clock := mocks.NewUserRepo(t), mocks.NewTokenRepo(t), mocks.NewClock(t)
	svc := app.NewTokenService(users, tokens, nopAudit{}, clock, discardLogger{})

	actor := identity.User{ID: uuid.New(), Kind: identity.KindHuman, Role: identity.RoleUser}
	_, err := svc.List(context.Background(), actor, uuid.New())
	require.Same(t, app.ErrForbidden, err, "want the bare ErrForbidden")
}

// An actor nobody populated is nobody: without the nil guard its zero id matches an
// equally empty owner and the ownership rule turns into an allow.
func TestUnpopulatedActorIsForbidden(t *testing.T) {
	users, tokens, clock := mocks.NewUserRepo(t), mocks.NewTokenRepo(t), mocks.NewClock(t)
	svc := app.NewTokenService(users, tokens, nopAudit{}, clock, discardLogger{})

	ctx := context.Background()
	_, _, err := svc.Issue(ctx, identity.User{}, uuid.Nil, "ghost")
	require.Same(t, app.ErrForbidden, err, "Issue: want the bare ErrForbidden")

	_, err = svc.List(ctx, identity.User{}, uuid.Nil)
	require.Same(t, app.ErrForbidden, err, "List: want the bare ErrForbidden")

	orphan, _, err := credentials.Generate(uuid.Nil, "ghost")
	require.NoError(t, err, "Generate")

	tokens.EXPECT().ByID(mock.Anything, orphan.ID).Return(orphan, nil)

	err = svc.Revoke(ctx, identity.User{}, orphan.ID)
	require.Same(t, app.ErrForbidden, err, "Revoke: want the bare ErrForbidden")
}

func TestRevokeOtherUsersTokenIsForbidden(t *testing.T) {
	users, tokens, clock := mocks.NewUserRepo(t), mocks.NewTokenRepo(t), mocks.NewClock(t)
	svc := app.NewTokenService(users, tokens, nopAudit{}, clock, discardLogger{})

	victim := uuid.New()

	tok, _, err := credentials.Generate(victim, "laptop")
	require.NoError(t, err, "Generate")

	tokens.EXPECT().ByID(mock.Anything, tok.ID).Return(tok, nil)

	actor := identity.User{ID: uuid.New(), Kind: identity.KindHuman, Role: identity.RoleUser}
	err = svc.Revoke(context.Background(), actor, tok.ID)
	require.Same(t, app.ErrForbidden, err, "want the bare ErrForbidden")
	// No Save expectation: a refused revocation must not touch the record.
}

func TestAdminRevokesAnotherUsersToken(t *testing.T) {
	users, tokens, clock := mocks.NewUserRepo(t), mocks.NewTokenRepo(t), mocks.NewClock(t)
	svc := app.NewTokenService(users, tokens, nopAudit{}, clock, discardLogger{})
	clock.EXPECT().Now().Return(frozen)

	tok, _, err := credentials.Generate(uuid.New(), "laptop")
	require.NoError(t, err, "Generate")

	tokens.EXPECT().ByID(mock.Anything, tok.ID).Return(tok, nil)

	var saved credentials.Token

	tokens.EXPECT().Save(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, got credentials.Token) error {
		saved = got

		return nil
	})

	admin := identity.User{ID: uuid.New(), Kind: identity.KindHuman, Role: identity.RoleAdmin}
	require.NoError(t, svc.Revoke(context.Background(), admin, tok.ID), "Revoke")
	require.NotNil(t, saved.RevokedBy, "RevokedBy")
	require.Equal(t, admin.ID, *saved.RevokedBy, "RevokedBy: want the admin")
}

func TestRevokeUnknownTokenIsNotFound(t *testing.T) {
	users, tokens, clock := mocks.NewUserRepo(t), mocks.NewTokenRepo(t), mocks.NewClock(t)
	svc := app.NewTokenService(users, tokens, nopAudit{}, clock, discardLogger{})

	id := uuid.New()
	tokens.EXPECT().ByID(mock.Anything, id).Return(credentials.Token{}, app.ErrNotFound)

	actor := identity.User{ID: uuid.New(), Kind: identity.KindHuman, Role: identity.RoleAdmin}
	require.ErrorIs(t, svc.Revoke(context.Background(), actor, id), app.ErrNotFound)
}

func TestRevokeTwiceFails(t *testing.T) {
	users, tokens, clock := mocks.NewUserRepo(t), mocks.NewTokenRepo(t), mocks.NewClock(t)
	svc := app.NewTokenService(users, tokens, nopAudit{}, clock, discardLogger{})
	clock.EXPECT().Now().Return(frozen)

	owner := identity.User{ID: uuid.New(), Kind: identity.KindHuman, Role: identity.RoleUser}

	stored, _, err := credentials.Generate(owner.ID, "laptop")
	require.NoError(t, err, "Generate")

	tokens.EXPECT().ByID(mock.Anything, stored.ID).RunAndReturn(func(_ context.Context, _ uuid.UUID) (credentials.Token, error) {
		return stored, nil
	})
	tokens.EXPECT().Save(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, got credentials.Token) error {
		stored = got

		return nil
	})

	ctx := context.Background()
	require.NoError(t, svc.Revoke(ctx, owner, stored.ID), "first Revoke")
	// The second attempt must fail against the state the first one wrote, and must
	// not write again — Save is expected but the mock records every call.
	require.ErrorIs(t, svc.Revoke(ctx, owner, stored.ID), credentials.ErrAlreadyRevoked, "second Revoke")

	tokens.AssertNumberOfCalls(t, "Save", 1)
}

// A revocation that is durable is not reported as a failure: the key is dead, and a
// retry would only produce ErrAlreadyRevoked for work that succeeded.
func TestRevokeSucceedsAndLogsWhenTheAuditRecordFails(t *testing.T) {
	users, tokens, clock := mocks.NewUserRepo(t), mocks.NewTokenRepo(t), mocks.NewClock(t)
	audit, logger := mocks.NewAuditSink(t), mocks.NewLogger(t)
	svc := app.NewTokenService(users, tokens, audit, clock, logger)
	clock.EXPECT().Now().Return(frozen)

	owner := identity.User{ID: uuid.New(), Kind: identity.KindHuman, Role: identity.RoleUser}

	tok, _, err := credentials.Generate(owner.ID, "laptop")
	require.NoError(t, err, "Generate")

	tokens.EXPECT().ByID(mock.Anything, tok.ID).Return(tok, nil)

	var saved credentials.Token

	tokens.EXPECT().Save(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, got credentials.Token) error {
		saved = got

		return nil
	})

	sinkDown := errors.New("audit sink unreachable")
	audit.EXPECT().Record(mock.Anything, mock.Anything).Return(sinkDown)

	var warned string

	logger.EXPECT().Warn(mock.Anything, mock.Anything).Run(func(msg string, attrs ...slog.Attr) {
		warned = fmt.Sprint(msg, attrs)
	})

	require.NoError(t, svc.Revoke(context.Background(), owner, tok.ID), "Revoke: want nil for a revocation that was saved")
	require.False(t, saved.Active(), "the token was not revoked")
	require.Contains(t, warned, tok.ID.String(), "warning does not name the token whose audit record was lost")
}

func TestAuditDetailsNeverCarrySecretOrHash(t *testing.T) {
	users, tokens, clock := mocks.NewUserRepo(t), mocks.NewTokenRepo(t), mocks.NewClock(t)
	audit := mocks.NewAuditSink(t)
	svc := app.NewTokenService(users, tokens, audit, clock, discardLogger{})
	clock.EXPECT().Now().Return(frozen)

	var events []app.AuditEvent

	audit.EXPECT().Record(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, e app.AuditEvent) error {
		events = append(events, e)

		return nil
	})

	owner := identity.User{ID: uuid.New(), Kind: identity.KindHuman, Role: identity.RoleUser}
	users.EXPECT().ByID(mock.Anything, owner.ID).Return(owner, nil)

	var stored credentials.Token

	tokens.EXPECT().Create(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, tok credentials.Token) error {
		stored = tok

		return nil
	})

	ctx := context.Background()

	issued, secret, err := svc.Issue(ctx, owner, owner.ID, "laptop")
	require.NoError(t, err, "Issue")

	tokens.EXPECT().ByID(mock.Anything, issued.ID).RunAndReturn(func(_ context.Context, _ uuid.UUID) (credentials.Token, error) {
		return stored, nil
	})
	tokens.EXPECT().Save(mock.Anything, mock.Anything).Return(nil)

	require.NoError(t, svc.Revoke(ctx, owner, issued.ID), "Revoke")
	require.Len(t, events, 2, "want one audit event for the issue and one for the revoke")

	wantActions := []string{"token.issue", "token.revoke"}
	for idx, event := range events {
		require.Equal(t, wantActions[idx], event.Action, "event %d action", idx)
		require.Equal(t, owner.ID, event.ActorID, "event %d actor", idx)
		require.True(t, event.At.Equal(frozen), "event %d At = %v, want the injected clock %v", idx, event.At, frozen)

		rendered := renderEvent(event)
		require.NotContains(t, rendered, secret, "audit event %d carried the token secret", idx)
		require.NotContains(t, rendered, stored.Hash, "audit event %d carried the token hash", idx)
		require.Contains(t, rendered, issued.ID.String(), "audit event %d does not identify the token", idx)
	}
}

// renderEvent flattens an audit event to text so a leak is caught wherever it hides,
// not only in the field a test happened to look at.
func renderEvent(e app.AuditEvent) string {
	return fmt.Sprintf("%s %s %v %s %s", e.Action, e.Target, e.Detail, e.IP, e.UserAgent)
}

// The audit most likely fails because the client hung up, which cancels the request
// context. The retraction must still be saved, so it cannot run on that context.
func TestIssueRetractsTheRowEvenWhenTheClientHungUp(t *testing.T) {
	users, tokens, clock := mocks.NewUserRepo(t), mocks.NewTokenRepo(t), mocks.NewClock(t)
	audit := mocks.NewAuditSink(t)
	svc := app.NewTokenService(users, tokens, audit, clock, discardLogger{})
	clock.EXPECT().Now().Return(frozen)

	owner := identity.User{ID: uuid.New(), Kind: identity.KindHuman, Role: identity.RoleUser}
	users.EXPECT().ByID(mock.Anything, owner.ID).Return(owner, nil)
	tokens.EXPECT().Create(mock.Anything, mock.Anything).Return(nil)

	ctx, hangUp := context.WithCancel(context.Background())
	defer hangUp()

	audit.EXPECT().Record(mock.Anything, mock.Anything).RunAndReturn(func(context.Context, app.AuditEvent) error {
		hangUp()

		return ctx.Err()
	})

	var saveCtx compensationSeen

	tokens.EXPECT().Save(mock.Anything, mock.Anything).RunAndReturn(func(sctx context.Context, _ credentials.Token) error {
		saveCtx = observe(sctx)

		return sctx.Err()
	})

	_, _, err := svc.Issue(ctx, owner, owner.ID, "laptop")
	require.Error(t, err, "Issue succeeded although the issuance was never recorded")

	assertCompensationContext(t, saveCtx)
}
