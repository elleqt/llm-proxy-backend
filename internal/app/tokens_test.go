package app_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/app/mocks"
	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/domain/credentials"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
)

// frozen is the instant the injected clock reports, so every timestamp the service
// writes is asserted exactly rather than within a tolerance.
var frozen = time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)

func TestIssueForOtherUserRequiresAdmin(t *testing.T) {
	users, tokens, clock := mocks.NewUserRepo(t), mocks.NewTokenRepo(t), mocks.NewClock(t)
	svc := app.NewTokenService(users, tokens, nopAudit{}, clock, discardLogger{})

	actor := identity.User{ID: uuid.New(), Kind: identity.KindHuman, Role: identity.RoleUser}

	_, _, err := svc.Issue(context.Background(), actor, uuid.New(), "someone else")
	if !isExactly(err, app.ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
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
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if secret == "" {
		t.Fatal("issued secret must be returned exactly once")
	}
	// This is the only successful issue where the actor is not the owner, so it is the
	// only place that can catch a key minted for the administrator who asked for it.
	if stored.UserID != service.ID {
		t.Fatalf("persisted owner = %v, want the service account %v (the actor is %v)", stored.UserID, service.ID, admin.ID)
	}

	if issued.UserID != service.ID {
		t.Fatalf("returned owner = %v, want the service account %v", issued.UserID, service.ID)
	}

	if stored.Label != "panel" || issued.Label != "panel" {
		t.Fatalf("label persisted %q, returned %q, want %q", stored.Label, issued.Label, "panel")
	}

	if stored.Hash != credentials.HashSecret(secret) {
		t.Fatal("the persisted hash does not verify the returned secret")
	}

	if got := event.Detail["owner_id"]; got != service.ID.String() {
		t.Fatalf("audit owner_id = %v, want the service account %v", got, service.ID)
	}

	if event.ActorID != admin.ID {
		t.Fatalf("audit actor = %v, want the admin %v", event.ActorID, admin.ID)
	}
}

func TestIssueForUnknownOwnerIsNotFound(t *testing.T) {
	users, tokens, clock := mocks.NewUserRepo(t), mocks.NewTokenRepo(t), mocks.NewClock(t)
	svc := app.NewTokenService(users, tokens, nopAudit{}, clock, discardLogger{})

	owner := uuid.New()
	users.EXPECT().ByID(mock.Anything, owner).Return(identity.User{}, app.ErrNotFound)

	admin := identity.User{ID: uuid.New(), Kind: identity.KindHuman, Role: identity.RoleAdmin}

	_, _, err := svc.Issue(context.Background(), admin, owner, "panel")
	if !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
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
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the repository failure", err)
	}

	if secret != "" {
		t.Fatal("a secret was handed out for a token that was never stored")
	}

	if issued != (credentials.Token{}) {
		t.Fatalf("returned record = %+v, want the zero token", issued)
	}
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
	if !errors.Is(err, sinkDown) {
		t.Fatalf("err = %v, want the audit failure", err)
	}

	if secret != "" {
		t.Fatal("a secret was handed out for an unaudited token")
	}
	// The row is durable by now, so it must not be left unaudited *and* live.
	if saved.Active() {
		t.Fatal("the unaudited token was left active")
	}

	if saved.RevokedBy == nil || *saved.RevokedBy != owner.ID {
		t.Fatalf("compensating revoke RevokedBy = %v, want %v", saved.RevokedBy, owner.ID)
	}

	if saved.RevokedAt == nil || !saved.RevokedAt.Equal(frozen) {
		t.Fatalf("compensating revoke RevokedAt = %v, want %v", saved.RevokedAt, frozen)
	}
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
	if !errors.Is(err, sinkDown) {
		t.Fatalf("err = %v, want it to wrap the audit failure", err)
	}

	if !strings.Contains(err.Error(), saveDown.Error()) {
		t.Fatalf("err = %v, want it to name the failed compensating write too", err)
	}

	if secret != "" {
		t.Fatal("a secret was handed out for an unaudited token")
	}
	// A live row no audit record describes is the one outcome an operator must fix by
	// hand, so the error string handed to the caller cannot be its only trace.
	for _, want := range []string{stored.ID.String(), owner.ID.String(), sinkDown.Error(), saveDown.Error()} {
		if !strings.Contains(warned, want) {
			t.Fatalf("warning %q does not name %q", warned, want)
		}
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
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if stored.ID != issued.ID || stored.UserID != owner.ID || stored.Label != "laptop" {
		t.Fatalf("persisted token = %+v, want the issued record owned by %v", stored, owner.ID)
	}

	if stored.Hash != credentials.HashSecret(secret) {
		t.Fatal("the persisted hash does not verify the returned secret")
	}

	if !stored.CreatedAt.Equal(frozen) {
		t.Fatalf("CreatedAt = %v, want the injected clock %v", stored.CreatedAt, frozen)
	}

	if !stored.Active() {
		t.Fatal("a freshly issued token must be active")
	}

	tokens.EXPECT().ListByUser(mock.Anything, owner.ID).RunAndReturn(func(_ context.Context, _ uuid.UUID) ([]credentials.Token, error) {
		return []credentials.Token{stored}, nil
	})

	listed, err := svc.List(ctx, owner, owner.ID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	if len(listed) != 1 || listed[0].ID != issued.ID {
		t.Fatalf("List returned %+v, want the issued token", listed)
	}

	tokens.EXPECT().ByID(mock.Anything, issued.ID).RunAndReturn(func(_ context.Context, _ uuid.UUID) (credentials.Token, error) {
		return stored, nil
	})

	var saved credentials.Token

	tokens.EXPECT().Save(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, tok credentials.Token) error {
		saved = tok

		return nil
	})

	if err := svc.Revoke(ctx, owner, issued.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	if saved.Active() {
		t.Fatal("the saved token is still active after Revoke")
	}

	if saved.RevokedBy == nil || *saved.RevokedBy != owner.ID {
		t.Fatalf("RevokedBy = %v, want the actor %v", saved.RevokedBy, owner.ID)
	}

	if saved.RevokedAt == nil || !saved.RevokedAt.Equal(frozen) {
		t.Fatalf("RevokedAt = %v, want the injected clock %v", saved.RevokedAt, frozen)
	}
}

func TestListForOtherUserRequiresAdmin(t *testing.T) {
	users, tokens, clock := mocks.NewUserRepo(t), mocks.NewTokenRepo(t), mocks.NewClock(t)
	svc := app.NewTokenService(users, tokens, nopAudit{}, clock, discardLogger{})

	actor := identity.User{ID: uuid.New(), Kind: identity.KindHuman, Role: identity.RoleUser}
	if _, err := svc.List(context.Background(), actor, uuid.New()); !isExactly(err, app.ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
}

// An actor nobody populated is nobody: without the nil guard its zero id matches an
// equally empty owner and the ownership rule turns into an allow.
func TestUnpopulatedActorIsForbidden(t *testing.T) {
	users, tokens, clock := mocks.NewUserRepo(t), mocks.NewTokenRepo(t), mocks.NewClock(t)
	svc := app.NewTokenService(users, tokens, nopAudit{}, clock, discardLogger{})

	ctx := context.Background()
	if _, _, err := svc.Issue(ctx, identity.User{}, uuid.Nil, "ghost"); !isExactly(err, app.ErrForbidden) {
		t.Fatalf("Issue: err = %v, want ErrForbidden", err)
	}

	if _, err := svc.List(ctx, identity.User{}, uuid.Nil); !isExactly(err, app.ErrForbidden) {
		t.Fatalf("List: err = %v, want ErrForbidden", err)
	}

	orphan, _, err := credentials.Generate(uuid.Nil, "ghost")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	tokens.EXPECT().ByID(mock.Anything, orphan.ID).Return(orphan, nil)

	if err := svc.Revoke(ctx, identity.User{}, orphan.ID); !isExactly(err, app.ErrForbidden) {
		t.Fatalf("Revoke: err = %v, want ErrForbidden", err)
	}
}

func TestRevokeOtherUsersTokenIsForbidden(t *testing.T) {
	users, tokens, clock := mocks.NewUserRepo(t), mocks.NewTokenRepo(t), mocks.NewClock(t)
	svc := app.NewTokenService(users, tokens, nopAudit{}, clock, discardLogger{})

	victim := uuid.New()

	tok, _, err := credentials.Generate(victim, "laptop")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	tokens.EXPECT().ByID(mock.Anything, tok.ID).Return(tok, nil)

	actor := identity.User{ID: uuid.New(), Kind: identity.KindHuman, Role: identity.RoleUser}
	if err := svc.Revoke(context.Background(), actor, tok.ID); !isExactly(err, app.ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
	// No Save expectation: a refused revocation must not touch the record.
}

func TestAdminRevokesAnotherUsersToken(t *testing.T) {
	users, tokens, clock := mocks.NewUserRepo(t), mocks.NewTokenRepo(t), mocks.NewClock(t)
	svc := app.NewTokenService(users, tokens, nopAudit{}, clock, discardLogger{})
	clock.EXPECT().Now().Return(frozen)

	tok, _, err := credentials.Generate(uuid.New(), "laptop")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	tokens.EXPECT().ByID(mock.Anything, tok.ID).Return(tok, nil)

	var saved credentials.Token

	tokens.EXPECT().Save(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, got credentials.Token) error {
		saved = got

		return nil
	})

	admin := identity.User{ID: uuid.New(), Kind: identity.KindHuman, Role: identity.RoleAdmin}
	if err := svc.Revoke(context.Background(), admin, tok.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	if saved.RevokedBy == nil || *saved.RevokedBy != admin.ID {
		t.Fatalf("RevokedBy = %v, want the admin %v", saved.RevokedBy, admin.ID)
	}
}

func TestRevokeUnknownTokenIsNotFound(t *testing.T) {
	users, tokens, clock := mocks.NewUserRepo(t), mocks.NewTokenRepo(t), mocks.NewClock(t)
	svc := app.NewTokenService(users, tokens, nopAudit{}, clock, discardLogger{})

	id := uuid.New()
	tokens.EXPECT().ByID(mock.Anything, id).Return(credentials.Token{}, app.ErrNotFound)

	actor := identity.User{ID: uuid.New(), Kind: identity.KindHuman, Role: identity.RoleAdmin}
	if err := svc.Revoke(context.Background(), actor, id); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestRevokeTwiceFails(t *testing.T) {
	users, tokens, clock := mocks.NewUserRepo(t), mocks.NewTokenRepo(t), mocks.NewClock(t)
	svc := app.NewTokenService(users, tokens, nopAudit{}, clock, discardLogger{})
	clock.EXPECT().Now().Return(frozen)

	owner := identity.User{ID: uuid.New(), Kind: identity.KindHuman, Role: identity.RoleUser}

	stored, _, err := credentials.Generate(owner.ID, "laptop")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	tokens.EXPECT().ByID(mock.Anything, stored.ID).RunAndReturn(func(_ context.Context, _ uuid.UUID) (credentials.Token, error) {
		return stored, nil
	})
	tokens.EXPECT().Save(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, got credentials.Token) error {
		stored = got

		return nil
	})

	ctx := context.Background()
	if err := svc.Revoke(ctx, owner, stored.ID); err != nil {
		t.Fatalf("first Revoke: %v", err)
	}
	// The second attempt must fail against the state the first one wrote, and must
	// not write again — Save is expected but the mock records every call.
	if err := svc.Revoke(ctx, owner, stored.ID); !errors.Is(err, credentials.ErrAlreadyRevoked) {
		t.Fatalf("second Revoke: err = %v, want ErrAlreadyRevoked", err)
	}

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
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

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

	if err := svc.Revoke(context.Background(), owner, tok.ID); err != nil {
		t.Fatalf("Revoke: err = %v, want nil for a revocation that was saved", err)
	}

	if saved.Active() {
		t.Fatal("the token was not revoked")
	}

	if !strings.Contains(warned, tok.ID.String()) {
		t.Fatalf("warning %q does not name the token whose audit record was lost", warned)
	}
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
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	tokens.EXPECT().ByID(mock.Anything, issued.ID).RunAndReturn(func(_ context.Context, _ uuid.UUID) (credentials.Token, error) {
		return stored, nil
	})
	tokens.EXPECT().Save(mock.Anything, mock.Anything).Return(nil)

	if err := svc.Revoke(ctx, owner, issued.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	if len(events) != 2 {
		t.Fatalf("recorded %d audit events, want one for the issue and one for the revoke", len(events))
	}

	wantActions := []string{"token.issue", "token.revoke"}
	for idx, event := range events {
		if event.Action != wantActions[idx] {
			t.Fatalf("event %d action = %q, want %q", idx, event.Action, wantActions[idx])
		}

		if event.ActorID != owner.ID {
			t.Fatalf("event %d actor = %v, want %v", idx, event.ActorID, owner.ID)
		}

		if !event.At.Equal(frozen) {
			t.Fatalf("event %d At = %v, want the injected clock %v", idx, event.At, frozen)
		}

		rendered := renderEvent(event)
		if strings.Contains(rendered, secret) {
			t.Fatalf("audit event %d carried the token secret: %s", idx, rendered)
		}

		if strings.Contains(rendered, stored.Hash) {
			t.Fatalf("audit event %d carried the token hash: %s", idx, rendered)
		}

		if !strings.Contains(rendered, issued.ID.String()) {
			t.Fatalf("audit event %d does not identify the token: %s", idx, rendered)
		}
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

	if _, _, err := svc.Issue(ctx, owner, owner.ID, "laptop"); err == nil {
		t.Fatal("Issue succeeded although the issuance was never recorded")
	}

	assertCompensationContext(t, saveCtx)
}
