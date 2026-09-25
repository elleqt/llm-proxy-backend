package app

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
)

// Providers is the administrator's view of the gateway's vendor accounts: the
// list with quota signals, the login wizard, disabling and removal.
//
// Every account change goes through the gateway (VendorAccounts, VendorLogins),
// never the core auth manager. Every mutation is audited; an audit detail holds
// account ids, provider names and flags, never a callback URL, code, token or
// login session id (which, with a callback URL, completes a login).
// An added account whose audit record fails is withdrawn again and the error
// returned, as TokenService.Issue retracts an unaudited token: a credential
// must not enter service unrecorded. For the other changes a failed audit
// write is logged rather than returned, like a token revocation: taking
// back a disable or a removal would put a credential the administrator is
// withdrawing back into service.
type Providers struct {
	accounts VendorAccounts
	logins   VendorLogins
	quota    VendorQuota
	metrics  AccountMetrics
	audit    AuditSink
	clock    Clock
	logger   Logger
}

// The audit detail keys every vendor account change records.
const (
	auditProvider  = "provider"
	auditAccountID = "account_id"
)

func NewProviders(
	accounts VendorAccounts, logins VendorLogins, quota VendorQuota, metrics AccountMetrics, audit AuditSink, clock Clock, logger Logger,
) *Providers {
	return &Providers{accounts: accounts, logins: logins, quota: quota, metrics: metrics, audit: audit, clock: clock, logger: logger}
}

// List returns every account the gateway holds with the latest quota windows
// its vendor reported.
func (s *Providers) List(_ context.Context, actor identity.User) ([]VendorAccount, error) {
	if err := requireAdmin(actor); err != nil {
		return nil, err
	}

	byAccount := make(map[string][]QuotaSignal)
	for _, q := range s.quota.QuotaSignals() {
		byAccount[q.Account] = append(byAccount[q.Account], q)
	}

	accounts := s.accounts.Accounts()
	for i := range accounts {
		accounts[i].Quota = byAccount[accounts[i].ID]
	}

	return accounts, nil
}

// StartLogin begins a vendor sign-in for provider, a policy-facing name.
func (s *Providers) StartLogin(ctx context.Context, actor identity.User, provider string) (VendorLogin, error) {
	if err := requireAdmin(actor); err != nil {
		return VendorLogin{}, err
	}

	login, err := s.logins.StartLogin(ctx, provider)
	if err != nil {
		return VendorLogin{}, fmt.Errorf("app: start vendor login: %w", err)
	}

	s.record(ctx, actor, "provider.login_start", "provider/"+provider,
		map[string]any{auditProvider: provider})

	return login, nil
}

// CompleteLogin finishes a pending sign-in with the URL the vendor sign-in
// ended on and returns the account it added. The URL carries the vendor's
// authorisation code: it goes to the gateway and nowhere else.
func (s *Providers) CompleteLogin(ctx context.Context, actor identity.User, sessionID, callbackURL string) (VendorAccount, error) {
	if err := requireAdmin(actor); err != nil {
		return VendorAccount{}, err
	}

	account, err := s.logins.CompleteLogin(ctx, sessionID, callbackURL)
	if err != nil {
		return VendorAccount{}, fmt.Errorf("app: complete vendor login: %w", err)
	}

	if err := s.audit.Record(ctx, AuditEvent{
		At:      s.clock.Now().UTC(),
		ActorID: actor.ID,
		Action:  "provider.account_add",
		Target:  "provider_account/" + account.ID,
		Detail:  map[string]any{auditAccountID: account.ID, auditProvider: account.Provider},
	}); err != nil {
		return VendorAccount{}, s.withdraw(ctx, account, err)
	}

	return s.withQuota(account), nil
}

// SetDisabled disables or re-enables account id and returns it as it now is.
func (s *Providers) SetDisabled(ctx context.Context, actor identity.User, id string, disabled bool) (VendorAccount, error) {
	if err := requireAdmin(actor); err != nil {
		return VendorAccount{}, err
	}

	if _, err := s.find(id); err != nil {
		return VendorAccount{}, err
	}

	if err := s.accounts.SetAccountDisabled(ctx, id, disabled); err != nil {
		return VendorAccount{}, fmt.Errorf("app: set vendor account disabled: %w", err)
	}

	account, err := s.find(id)
	if err != nil {
		return VendorAccount{}, err
	}

	s.metrics.SetAccountDisabled(account.ID, account.Provider, disabled)
	s.record(ctx, actor, "provider.account_disable", "provider_account/"+account.ID,
		map[string]any{auditAccountID: account.ID, auditProvider: account.Provider, "disabled": disabled})

	return s.withQuota(account), nil
}

// Remove removes account id from the gateway and its storage, then forgets its
// quota snapshot and metric series.
func (s *Providers) Remove(ctx context.Context, actor identity.User, id string) error {
	if err := requireAdmin(actor); err != nil {
		return err
	}

	account, err := s.find(id)
	if err != nil {
		return err
	}

	if err := s.accounts.RemoveAccount(ctx, id); err != nil {
		return fmt.Errorf("app: remove vendor account: %w", err)
	}

	s.quota.ForgetAccount(account.ID)
	s.metrics.ForgetAccount(account.ID, account.Provider)
	s.record(ctx, actor, "provider.account_remove", "provider_account/"+account.ID,
		map[string]any{auditAccountID: account.ID, auditProvider: account.Provider})

	return nil
}

// withdraw removes an added account whose audit record failed and returns
// the audit error. If the removal fails too, the account is live and
// unaudited: that is logged for an operator, who has to remove it by hand.
func (s *Providers) withdraw(ctx context.Context, account VendorAccount, cause error) error {
	cctx, cancel := compensationContext(ctx)
	defer cancel()

	if err := s.accounts.RemoveAccount(cctx, account.ID); err != nil {
		s.logger.Warn("vendor account is live but unaudited — remove it by hand",
			slog.String("account", account.ID), slog.Any("audit_err", cause), slog.Any("remove_err", err))

		//nolint:errorlint // The removal failure is reported, not wrapped: callers match the cause alone.
		return fmt.Errorf("app: added vendor account not audited (%w); removing it failed: %v", cause, err)
	}

	return fmt.Errorf("app: added vendor account not audited, account removed: %w", cause)
}

// find returns the account the gateway holds as id, or ErrNotFound.
func (s *Providers) find(id string) (VendorAccount, error) {
	for _, a := range s.accounts.Accounts() {
		if a.ID == id {
			return a, nil
		}
	}

	return VendorAccount{}, fmt.Errorf("%w: provider account %q", ErrNotFound, id)
}

func (s *Providers) withQuota(account VendorAccount) VendorAccount {
	for _, q := range s.quota.QuotaSignals() {
		if q.Account == account.ID {
			account.Quota = append(account.Quota, q)
		}
	}

	return account
}

func (s *Providers) record(ctx context.Context, actor identity.User, action, target string, detail map[string]any) {
	if err := s.audit.Record(ctx, AuditEvent{
		At:      s.clock.Now().UTC(),
		ActorID: actor.ID,
		Action:  action,
		Target:  target,
		Detail:  detail,
	}); err != nil {
		s.logger.Warn("audit record failed after a completed action",
			slog.String("action", action), slog.String("target", target), slog.Any("err", err))
	}
}
