package app_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/app/mocks"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
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
	f := &providersFixture{
		accounts: mocks.NewVendorAccounts(t),
		logins:   mocks.NewVendorLogins(t),
		quota:    mocks.NewVendorQuota(t),
		metrics:  mocks.NewAccountMetrics(t),
		audit:    mocks.NewAuditSink(t),
	}
	f.svc = app.NewProviders(f.accounts, f.logins, f.quota, f.metrics, f.audit, systemClock{}, discardLogger{})
	return f
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
			f := newProvidersFixture(t)
			ctx := context.Background()
			calls := map[string]error{}
			_, calls["List"] = f.svc.List(ctx, actor)
			_, calls["StartLogin"] = f.svc.StartLogin(ctx, actor, "claude")
			_, calls["CompleteLogin"] = f.svc.CompleteLogin(ctx, actor, "session", "http://localhost/callback?code=c&state=s")
			_, calls["SetDisabled"] = f.svc.SetDisabled(ctx, actor, codexAccount.ID, true)
			calls["Remove"] = f.svc.Remove(ctx, actor, codexAccount.ID)
			for method, err := range calls {
				if !errors.Is(err, app.ErrForbidden) {
					t.Errorf("%s = %v, want ErrForbidden", method, err)
				}
			}
		})
	}
}

// TestProvidersListCarriesEachAccountsQuota: each account gets the quota
// windows reported for it and no other account's.
func TestProvidersListCarriesEachAccountsQuota(t *testing.T) {
	f := newProvidersFixture(t)
	claude := app.VendorAccount{ID: "claude-a.json", Provider: "claude", Status: "active"}
	f.accounts.EXPECT().Accounts().Return([]app.VendorAccount{codexAccount, claude})
	reset := time.Date(2026, 9, 23, 5, 0, 0, 0, time.UTC)
	fiveHours := app.QuotaSignal{Account: codexAccount.ID, Provider: "chatgpt", Window: "5h", UsedRatio: 0.25, ResetAt: reset}
	week := app.QuotaSignal{Account: codexAccount.ID, Provider: "chatgpt", Window: "7d", UsedRatio: 0.5}
	f.quota.EXPECT().QuotaSignals().Return([]app.QuotaSignal{fiveHours, week})

	got, err := f.svc.List(context.Background(), providerAdmin())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("List = %+v, want both accounts", got)
	}
	if got[0].Provider != "chatgpt" || len(got[0].Quota) != 2 || got[0].Quota[0] != fiveHours || got[0].Quota[1] != week {
		t.Fatalf("codex account = %+v, want provider chatgpt with its 5h and 7d windows", got[0])
	}
	if len(got[1].Quota) != 0 {
		t.Fatalf("claude account = %+v, want no quota: none was reported for it", got[1])
	}
}

// TestProvidersSetDisabledGoesThroughTheGateway: the change is the gateway's,
// the metric follows under the policy name, and it is audited.
func TestProvidersSetDisabledGoesThroughTheGateway(t *testing.T) {
	f := newProvidersFixture(t)
	disabled := codexAccount
	disabled.Disabled, disabled.Status = true, "disabled"
	f.accounts.EXPECT().Accounts().Return([]app.VendorAccount{codexAccount}).Once()
	f.accounts.EXPECT().SetAccountDisabled(mock.Anything, codexAccount.ID, true).Return(nil).Once()
	f.accounts.EXPECT().Accounts().Return([]app.VendorAccount{disabled}).Once()
	f.quota.EXPECT().QuotaSignals().Return(nil)
	f.metrics.EXPECT().SetAccountDisabled(codexAccount.ID, "chatgpt", true).Once()
	f.recordAudits()

	actor := providerAdmin()
	got, err := f.svc.SetDisabled(context.Background(), actor, codexAccount.ID, true)
	if err != nil {
		t.Fatalf("SetDisabled: %v", err)
	}
	if !got.Disabled {
		t.Fatalf("SetDisabled returned %+v, want the account as it now is: disabled", got)
	}
	if len(f.events) != 1 || f.events[0].Action != "provider.account_disable" || f.events[0].ActorID != actor.ID ||
		f.events[0].Detail["disabled"] != true || f.events[0].Detail["provider"] != "chatgpt" {
		t.Fatalf("audit = %+v, want one provider.account_disable by the actor naming chatgpt", f.events)
	}
}

// TestProvidersRemoveForgetsTheAccount: removal goes through the gateway, then
// the quota snapshot and the metric series of the account go too, under its
// policy name, and it is audited.
func TestProvidersRemoveForgetsTheAccount(t *testing.T) {
	f := newProvidersFixture(t)
	f.accounts.EXPECT().Accounts().Return([]app.VendorAccount{codexAccount})
	f.accounts.EXPECT().RemoveAccount(mock.Anything, codexAccount.ID).Return(nil).Once()
	f.quota.EXPECT().ForgetAccount(codexAccount.ID).Once()
	f.metrics.EXPECT().ForgetAccount(codexAccount.ID, "chatgpt").Once()
	f.recordAudits()

	if err := f.svc.Remove(context.Background(), providerAdmin(), codexAccount.ID); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if len(f.events) != 1 || f.events[0].Action != "provider.account_remove" || f.events[0].Target != "provider_account/"+codexAccount.ID {
		t.Fatalf("audit = %+v, want one provider.account_remove of the account", f.events)
	}
}

// TestProvidersRemoveThatFailsForgetsNothing: an account the gateway could not
// remove is still there, so its quota and metrics stay, and nothing is audited.
func TestProvidersRemoveThatFailsForgetsNothing(t *testing.T) {
	f := newProvidersFixture(t)
	f.accounts.EXPECT().Accounts().Return([]app.VendorAccount{codexAccount})
	failure := errors.New("credential not deleted")
	f.accounts.EXPECT().RemoveAccount(mock.Anything, codexAccount.ID).Return(failure)

	if err := f.svc.Remove(context.Background(), providerAdmin(), codexAccount.ID); !errors.Is(err, failure) {
		t.Fatalf("Remove = %v, want the gateway's error", err)
	}
}

// TestProvidersUnknownAccountIsNotFound: an id the gateway does not hold is
// ErrNotFound, and no change is attempted.
func TestProvidersUnknownAccountIsNotFound(t *testing.T) {
	f := newProvidersFixture(t)
	f.accounts.EXPECT().Accounts().Return([]app.VendorAccount{codexAccount})

	if err := f.svc.Remove(context.Background(), providerAdmin(), "no-such.json"); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("Remove(unknown) = %v, want ErrNotFound", err)
	}
	if _, err := f.svc.SetDisabled(context.Background(), providerAdmin(), "no-such.json", true); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("SetDisabled(unknown) = %v, want ErrNotFound", err)
	}
}

// TestProvidersLoginAuditCarriesNoSecret: the wizard's audit records name the
// provider and the account added, and nowhere hold the callback URL, the
// authorisation code or state in it, or the session id that with a callback
// completes a login.
func TestProvidersLoginAuditCarriesNoSecret(t *testing.T) {
	f := newProvidersFixture(t)
	const (
		sessionID = "SESSION-ID-9f8e7d"
		code      = "AUTH-CODE-SECRET-1234"
		state     = "STATE-SECRET-5678"
	)
	callback := "http://localhost:1455/auth/callback?code=" + code + "&state=" + state
	f.logins.EXPECT().StartLogin(mock.Anything, "chatgpt").
		Return(app.VendorLogin{SessionID: sessionID, AuthURL: "https://auth.example/authorize?state=" + state, ExpiresAt: time.Now().Add(5 * time.Minute)}, nil)
	f.logins.EXPECT().CompleteLogin(mock.Anything, sessionID, callback).Return(codexAccount, nil)
	f.quota.EXPECT().QuotaSignals().Return(nil)
	f.recordAudits()

	actor := providerAdmin()
	login, err := f.svc.StartLogin(context.Background(), actor, "chatgpt")
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}
	account, err := f.svc.CompleteLogin(context.Background(), actor, login.SessionID, callback)
	if err != nil {
		t.Fatalf("CompleteLogin: %v", err)
	}
	if account.ID != codexAccount.ID {
		t.Fatalf("CompleteLogin returned %+v, want the added account", account)
	}

	if len(f.events) != 2 || f.events[0].Action != "provider.login_start" || f.events[1].Action != "provider.account_add" ||
		f.events[1].Detail["account_id"] != codexAccount.ID || f.events[1].Detail["provider"] != "chatgpt" {
		t.Fatalf("audit = %+v, want login_start then account_add naming the chatgpt account", f.events)
	}
	for _, e := range f.events {
		rendered := fmt.Sprintf("%s %s %v %s %s", e.Action, e.Target, e.Detail, e.IP, e.UserAgent)
		for _, secret := range []string{callback, code, state, sessionID} {
			if strings.Contains(rendered, secret) {
				t.Fatalf("audit event %q carries %q", rendered, secret)
			}
		}
	}
}

// TestProvidersFailedLoginIsNotAudited: a refused completion adds nothing and
// records no account_add.
func TestProvidersFailedLoginIsNotAudited(t *testing.T) {
	f := newProvidersFixture(t)
	f.logins.EXPECT().CompleteLogin(mock.Anything, "session", "cb").Return(app.VendorAccount{}, app.ErrLoginExpired)

	if _, err := f.svc.CompleteLogin(context.Background(), providerAdmin(), "session", "cb"); !errors.Is(err, app.ErrLoginExpired) {
		t.Fatalf("CompleteLogin = %v, want ErrLoginExpired", err)
	}
}

// TestProvidersWithdrawsAnAccountWhoseAuditFails: a vendor account must not
// enter service unrecorded, so an added account whose account_add audit fails
// is removed through the gateway and the audit error returned.
func TestProvidersWithdrawsAnAccountWhoseAuditFails(t *testing.T) {
	f := newProvidersFixture(t)
	f.logins.EXPECT().CompleteLogin(mock.Anything, "session", "cb").Return(codexAccount, nil)
	auditDown := errors.New("audit store down")
	f.audit.EXPECT().Record(mock.Anything, mock.Anything).Return(auditDown)
	f.accounts.EXPECT().RemoveAccount(mock.Anything, codexAccount.ID).Return(nil).Once()

	if _, err := f.svc.CompleteLogin(context.Background(), providerAdmin(), "session", "cb"); !errors.Is(err, auditDown) {
		t.Fatalf("CompleteLogin with a failing audit = %v, want the audit error", err)
	}
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
	logger.EXPECT().Warnf(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(format string, args ...any) { warned = fmt.Sprintf(format, args...) })

	if _, err := svc.CompleteLogin(context.Background(), providerAdmin(), "session", "cb"); !errors.Is(err, auditDown) {
		t.Fatalf("CompleteLogin = %v, want the audit error", err)
	}
	if !strings.Contains(warned, codexAccount.ID) {
		t.Fatalf("warning %q does not name the stranded account", warned)
	}
}
