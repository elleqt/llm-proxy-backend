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
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type providersFixture struct {
	accounts *mocks.VendorAccounts
	logins   *mocks.VendorLogins
	quota    *mocks.VendorQuota
	metrics  *mocks.AccountMetrics
	audit    *mocks.AuditSink
	svc      *app.Providers
	events   []app.AuditEvent
}

func newProvidersFixture(t *testing.T) *providersFixture {
	t.Helper()

	fixture := &providersFixture{
		accounts: mocks.NewVendorAccounts(t),
		logins:   mocks.NewVendorLogins(t),
		quota:    mocks.NewVendorQuota(t),
		metrics:  mocks.NewAccountMetrics(t),
		audit:    mocks.NewAuditSink(t),
	}
	fixture.svc = app.NewProviders(fixture.accounts, fixture.logins, fixture.quota, fixture.metrics, fixture.audit, systemClock{}, discardLogger{})

	return fixture
}

// recordAudits accepts every audit write and keeps it.
func (f *providersFixture) recordAudits() {
	f.audit.EXPECT().Record(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, e app.AuditEvent) error {
		f.events = append(f.events, e)

		return nil
	})
}

func providerAdmin() identity.User {
	return identity.User{ID: uuid.New(), Kind: identity.KindHuman, Role: identity.RoleAdmin, Status: identity.StatusActive}
}

// codexAccount is a Codex account as the gateway lists it: under its policy
// name.
var codexAccount = app.VendorAccount{ID: "codex-ops.json", Provider: "chatgpt", Status: "active"}

// TestProvidersRefuseAnyoneButAnActiveAdmin: every method refuses a
// non-administrator, a blocked administrator and one who still has to change a
// temporary password, before it touches the gateway (the strict mocks carry
// no expectations).
func TestProvidersRefuseAnyoneButAnActiveAdmin(t *testing.T) {
	admin := providerAdmin()
	blocked := admin
	blocked.Status = identity.StatusBlocked
	restricted := admin
	restricted.MustChangePassword = true
	user := admin
	user.Role = identity.RoleUser

	for name, actor := range map[string]identity.User{"user": user, "blocked admin": blocked, "restricted admin": restricted, "nobody": {}} {
		t.Run(name, func(t *testing.T) {
			fixture := newProvidersFixture(t)
			ctx := context.Background()
			calls := map[string]error{}
			_, calls["List"] = fixture.svc.List(ctx, actor)
			_, calls["StartLogin"] = fixture.svc.StartLogin(ctx, actor, "claude")
			_, calls["CompleteLogin"] = fixture.svc.CompleteLogin(ctx, actor, "session", "http://localhost/callback?code=c&state=s")
			_, calls["SetDisabled"] = fixture.svc.SetDisabled(ctx, actor, codexAccount.ID, true)

			calls["Remove"] = fixture.svc.Remove(ctx, actor, codexAccount.ID)
			for method, err := range calls {
				assert.ErrorIs(t, err, app.ErrForbidden, method)
			}
		})
	}
}

// TestProvidersListCarriesEachAccountsQuota: each account gets the quota
// windows reported for it and no other account's.
func TestProvidersListCarriesEachAccountsQuota(t *testing.T) {
	fixture := newProvidersFixture(t)
	claude := app.VendorAccount{ID: "claude-a.json", Provider: "claude", Status: "active"}
	fixture.accounts.EXPECT().Accounts().Return([]app.VendorAccount{codexAccount, claude})

	reset := time.Date(2026, 9, 23, 5, 0, 0, 0, time.UTC)
	fiveHours := app.QuotaSignal{Account: codexAccount.ID, Provider: "chatgpt", Window: "5h", UsedRatio: 0.25, ResetAt: reset}
	week := app.QuotaSignal{Account: codexAccount.ID, Provider: "chatgpt", Window: "7d", UsedRatio: 0.5}
	fixture.quota.EXPECT().QuotaSignals().Return([]app.QuotaSignal{fiveHours, week})

	got, err := fixture.svc.List(context.Background(), providerAdmin())
	require.NoError(t, err, "List")
	require.Len(t, got, 2, "List: want both accounts")
	require.Equal(t, "chatgpt", got[0].Provider, "codex account provider")
	require.Len(t, got[0].Quota, 2, "codex account: want its 5h and 7d windows")
	require.Equal(t, fiveHours, got[0].Quota[0], "codex 5h window")
	require.Equal(t, week, got[0].Quota[1], "codex 7d window")
	require.Empty(t, got[1].Quota, "claude account: want no quota: none was reported for it")
}

// TestProvidersSetDisabledGoesThroughTheGateway: the change is the gateway's,
// the metric follows under the policy name, and it is audited.
func TestProvidersSetDisabledGoesThroughTheGateway(t *testing.T) {
	fixture := newProvidersFixture(t)
	disabled := codexAccount
	disabled.Disabled, disabled.Status = true, "disabled"

	fixture.accounts.EXPECT().Accounts().Return([]app.VendorAccount{codexAccount}).Once()
	fixture.accounts.EXPECT().SetAccountDisabled(mock.Anything, codexAccount.ID, true).Return(nil).Once()
	fixture.accounts.EXPECT().Accounts().Return([]app.VendorAccount{disabled}).Once()
	fixture.quota.EXPECT().QuotaSignals().Return(nil)
	fixture.metrics.EXPECT().SetAccountDisabled(codexAccount.ID, "chatgpt", true).Once()
	fixture.recordAudits()

	actor := providerAdmin()

	got, err := fixture.svc.SetDisabled(context.Background(), actor, codexAccount.ID, true)
	require.NoError(t, err, "SetDisabled")
	require.True(t, got.Disabled, "SetDisabled returned %+v, want the account as it now is: disabled", got)
	require.Len(t, fixture.events, 1, "audit: want one provider.account_disable")

	event := fixture.events[0]
	require.Equal(t, "provider.account_disable", event.Action, "audit action")
	require.Equal(t, actor.ID, event.ActorID, "audit actor")

	auditedDisabled, isBool := event.Detail["disabled"].(bool)
	require.True(t, isBool, "audit detail disabled = %v, want a bool", event.Detail["disabled"])
	require.True(t, auditedDisabled, "audit detail disabled")
	require.Equal(t, "chatgpt", event.Detail["provider"], "audit detail provider")
}

// TestProvidersRemoveForgetsTheAccount: removal goes through the gateway, then
// the quota snapshot and the metric series of the account go too, under its
// policy name, and it is audited.
func TestProvidersRemoveForgetsTheAccount(t *testing.T) {
	fixture := newProvidersFixture(t)
	fixture.accounts.EXPECT().Accounts().Return([]app.VendorAccount{codexAccount})
	fixture.accounts.EXPECT().RemoveAccount(mock.Anything, codexAccount.ID).Return(nil).Once()
	fixture.quota.EXPECT().ForgetAccount(codexAccount.ID).Once()
	fixture.metrics.EXPECT().ForgetAccount(codexAccount.ID, "chatgpt").Once()
	fixture.recordAudits()

	err := fixture.svc.Remove(context.Background(), providerAdmin(), codexAccount.ID)
	require.NoError(t, err, "Remove")
	require.Len(t, fixture.events, 1, "audit: want one provider.account_remove")
	require.Equal(t, "provider.account_remove", fixture.events[0].Action, "audit action")
	require.Equal(t, "provider_account/"+codexAccount.ID, fixture.events[0].Target, "audit target")
}

// TestProvidersRemoveThatFailsForgetsNothing: an account the gateway could not
// remove is still there, so its quota and metrics stay, and nothing is audited.
func TestProvidersRemoveThatFailsForgetsNothing(t *testing.T) {
	fixture := newProvidersFixture(t)
	fixture.accounts.EXPECT().Accounts().Return([]app.VendorAccount{codexAccount})

	failure := errors.New("credential not deleted")
	fixture.accounts.EXPECT().RemoveAccount(mock.Anything, codexAccount.ID).Return(failure)

	err := fixture.svc.Remove(context.Background(), providerAdmin(), codexAccount.ID)
	require.ErrorIs(t, err, failure, "Remove: want the gateway's error")
}

// TestProvidersUnknownAccountIsNotFound: an id the gateway does not hold is
// ErrNotFound, and no change is attempted.
func TestProvidersUnknownAccountIsNotFound(t *testing.T) {
	fixture := newProvidersFixture(t)
	fixture.accounts.EXPECT().Accounts().Return([]app.VendorAccount{codexAccount})

	err := fixture.svc.Remove(context.Background(), providerAdmin(), "no-such.json")
	require.ErrorIs(t, err, app.ErrNotFound, "Remove(unknown)")

	_, err = fixture.svc.SetDisabled(context.Background(), providerAdmin(), "no-such.json", true)
	require.ErrorIs(t, err, app.ErrNotFound, "SetDisabled(unknown)")
}

// TestProvidersLoginAuditCarriesNoSecret: the wizard's audit records name the
// provider and the account added, and nowhere hold the callback URL, the
// authorisation code or state in it, or the session id that with a callback
// completes a login.
func TestProvidersLoginAuditCarriesNoSecret(t *testing.T) {
	fixture := newProvidersFixture(t)

	const (
		sessionID = "SESSION-ID-9f8e7d"
		code      = "AUTH-CODE-SECRET-1234"
		state     = "STATE-SECRET-5678"
	)

	callback := "http://localhost:1455/auth/callback?code=" + code + "&state=" + state
	fixture.logins.EXPECT().StartLogin(mock.Anything, "chatgpt").
		Return(app.VendorLogin{SessionID: sessionID, AuthURL: "https://auth.example/authorize?state=" + state, ExpiresAt: time.Now().Add(5 * time.Minute)}, nil)
	fixture.logins.EXPECT().CompleteLogin(mock.Anything, sessionID, callback).Return(codexAccount, nil)
	fixture.quota.EXPECT().QuotaSignals().Return(nil)
	fixture.recordAudits()

	actor := providerAdmin()

	login, err := fixture.svc.StartLogin(context.Background(), actor, "chatgpt")
	require.NoError(t, err, "StartLogin")

	account, err := fixture.svc.CompleteLogin(context.Background(), actor, login.SessionID, callback)
	require.NoError(t, err, "CompleteLogin")
	require.Equal(t, codexAccount.ID, account.ID, "CompleteLogin: want the added account")

	require.Len(t, fixture.events, 2, "audit: want login_start then account_add")
	require.Equal(t, "provider.login_start", fixture.events[0].Action, "first audit action")
	require.Equal(t, "provider.account_add", fixture.events[1].Action, "second audit action")
	require.Equal(t, codexAccount.ID, fixture.events[1].Detail["account_id"], "account_add detail account_id")
	require.Equal(t, "chatgpt", fixture.events[1].Detail["provider"], "account_add detail provider")

	for _, e := range fixture.events {
		rendered := fmt.Sprintf("%s %s %v %s %s", e.Action, e.Target, e.Detail, e.IP, e.UserAgent)
		for _, secret := range []string{callback, code, state, sessionID} {
			require.NotContains(t, rendered, secret, "audit event carries a secret")
		}
	}
}

// TestProvidersFailedLoginIsNotAudited: a refused completion adds nothing and
// records no account_add.
func TestProvidersFailedLoginIsNotAudited(t *testing.T) {
	f := newProvidersFixture(t)
	f.logins.EXPECT().CompleteLogin(mock.Anything, "session", "cb").Return(app.VendorAccount{}, app.ErrLoginExpired)

	_, err := f.svc.CompleteLogin(context.Background(), providerAdmin(), "session", "cb")
	require.ErrorIs(t, err, app.ErrLoginExpired, "CompleteLogin")
}

// TestProvidersWithdrawsAnAccountWhoseAuditFails: a vendor account must not
// enter service unrecorded, so an added account whose account_add audit fails
// is removed through the gateway and the audit error returned.
func TestProvidersWithdrawsAnAccountWhoseAuditFails(t *testing.T) {
	fixture := newProvidersFixture(t)
	fixture.logins.EXPECT().CompleteLogin(mock.Anything, "session", "cb").Return(codexAccount, nil)

	auditDown := errors.New("audit store down")
	fixture.audit.EXPECT().Record(mock.Anything, mock.Anything).Return(auditDown)
	fixture.accounts.EXPECT().RemoveAccount(mock.Anything, codexAccount.ID).Return(nil).Once()

	_, err := fixture.svc.CompleteLogin(context.Background(), providerAdmin(), "session", "cb")
	require.ErrorIs(t, err, auditDown, "CompleteLogin with a failing audit: want the audit error")
}

// TestProvidersReportsAnUnauditedAccountItCouldNotWithdraw: when the removal
// fails too, the account is live and unaudited; the caller gets an error and
// an operator gets a warning naming the account.
func TestProvidersReportsAnUnauditedAccountItCouldNotWithdraw(t *testing.T) {
	accounts, logins := mocks.NewVendorAccounts(t), mocks.NewVendorLogins(t)
	audit, logger := mocks.NewAuditSink(t), mocks.NewLogger(t)
	svc := app.NewProviders(accounts, logins, mocks.NewVendorQuota(t), mocks.NewAccountMetrics(t), audit, systemClock{}, logger)
	logins.EXPECT().CompleteLogin(mock.Anything, "session", "cb").Return(codexAccount, nil)

	auditDown := errors.New("audit store down")
	audit.EXPECT().Record(mock.Anything, mock.Anything).Return(auditDown)
	accounts.EXPECT().RemoveAccount(mock.Anything, codexAccount.ID).Return(errors.New("credential not deleted"))

	var warned string

	logger.EXPECT().Warn(mock.Anything, mock.Anything).
		Run(func(msg string, attrs ...slog.Attr) { warned = fmt.Sprint(msg, attrs) })

	_, err := svc.CompleteLogin(context.Background(), providerAdmin(), "session", "cb")
	require.ErrorIs(t, err, auditDown, "CompleteLogin: want the audit error")
	require.Contains(t, warned, codexAccount.ID, "warning does not name the stranded account")
}
