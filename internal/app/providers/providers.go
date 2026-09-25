// Package providers is the administrator's view of the gateway's vendor accounts:
// the list with quota signals, the login wizard, disabling and removal.
package providers

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
)

// Service is the administrator's view of the gateway's vendor accounts: the
// list with quota signals, the login wizard, disabling and removal.
//
// Every account change goes through the gateway (VendorAccounts, VendorLogins),
// never the core auth manager. Every mutation is audited; an audit detail holds
// account ids, provider names and flags, never a callback URL, code, token or
// login session id (which, with a callback URL, completes a login).
// An added account whose audit record fails is withdrawn again and the error
// returned, as tokens.Service.Issue retracts an unaudited token: a credential
// must not enter service unrecorded. For the other changes a failed audit
// write is logged rather than returned, like a token revocation: taking
// back a disable or a removal would put a credential the administrator is
// withdrawing back into service.
type Service struct {
	accounts app.VendorAccounts
	logins   app.VendorLogins
	quota    app.VendorQuota
	metrics  app.AccountMetrics
	audit    app.AuditSink
	clock    app.Clock
	logger   app.Logger
}

// The audit detail keys every vendor account change records.
const (
	auditProvider  = "provider"
	auditAccountID = "account_id"
)

func New(
	accounts app.VendorAccounts, logins app.VendorLogins, quota app.VendorQuota, metrics app.AccountMetrics, audit app.AuditSink,
	clock app.Clock, logger app.Logger,
) *Service {
	return &Service{accounts: accounts, logins: logins, quota: quota, metrics: metrics, audit: audit, clock: clock, logger: logger}
}

// List returns every account the gateway holds with the latest quota windows
// its vendor reported.
func (s *Service) List(_ context.Context, actor identity.User) ([]app.VendorAccount, error) {
	if err := app.RequireAdmin(actor); err != nil {
		return nil, err
	}

	byAccount := make(map[string][]app.QuotaSignal)
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
func (s *Service) StartLogin(ctx context.Context, actor identity.User, provider string) (app.VendorLogin, error) {
	if err := app.RequireAdmin(actor); err != nil {
		return app.VendorLogin{}, err
	}

	login, err := s.logins.StartLogin(ctx, provider)
	if err != nil {
		return app.VendorLogin{}, fmt.Errorf("app: start vendor login: %w", err)
	}

	s.record(ctx, actor, "provider.login_start", "provider/"+provider,
		map[string]any{auditProvider: provider})

	return login, nil
}

// CompleteLogin finishes a pending sign-in with the URL the vendor sign-in
// ended on and returns the account it added. The URL carries the vendor's
// authorisation code: it goes to the gateway and nowhere else.
func (s *Service) CompleteLogin(ctx context.Context, actor identity.User, sessionID, callbackURL string) (app.VendorAccount, error) {
	if err := app.RequireAdmin(actor); err != nil {
		return app.VendorAccount{}, err
	}

	account, err := s.logins.CompleteLogin(ctx, sessionID, callbackURL)
	if err != nil {
		return app.VendorAccount{}, fmt.Errorf("app: complete vendor login: %w", err)
	}

	if err := s.audit.Record(ctx, app.AuditEvent{
		At:      s.clock.Now().UTC(),
		ActorID: actor.ID,
		Action:  "provider.account_add",
		Target:  "provider_account/" + account.ID,
		Detail:  map[string]any{auditAccountID: account.ID, auditProvider: account.Provider},
	}); err != nil {
		return app.VendorAccount{}, s.withdraw(ctx, account, err)
	}

	return s.withQuota(account), nil
}

// SetDisabled disables or re-enables account id and returns it as it now is.
func (s *Service) SetDisabled(ctx context.Context, actor identity.User, id string, disabled bool) (app.VendorAccount, error) {
	if err := app.RequireAdmin(actor); err != nil {
		return app.VendorAccount{}, err
	}

	if _, err := s.find(id); err != nil {
		return app.VendorAccount{}, err
	}

	if err := s.accounts.SetAccountDisabled(ctx, id, disabled); err != nil {
		return app.VendorAccount{}, fmt.Errorf("app: set vendor account disabled: %w", err)
	}

	account, err := s.find(id)
	if err != nil {
		return app.VendorAccount{}, err
	}

	s.metrics.SetAccountDisabled(account.ID, account.Provider, disabled)
	s.record(ctx, actor, "provider.account_disable", "provider_account/"+account.ID,
		map[string]any{auditAccountID: account.ID, auditProvider: account.Provider, "disabled": disabled})

	return s.withQuota(account), nil
}

// Remove removes account id from the gateway and its storage, then forgets its
// quota snapshot and metric series.
func (s *Service) Remove(ctx context.Context, actor identity.User, id string) error {
	if err := app.RequireAdmin(actor); err != nil {
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
func (s *Service) withdraw(ctx context.Context, account app.VendorAccount, cause error) error {
	cctx, cancel := app.CompensationContext(ctx)
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
func (s *Service) find(id string) (app.VendorAccount, error) {
	for _, a := range s.accounts.Accounts() {
		if a.ID == id {
			return a, nil
		}
	}

	return app.VendorAccount{}, fmt.Errorf("%w: provider account %q", app.ErrNotFound, id)
}

func (s *Service) withQuota(account app.VendorAccount) app.VendorAccount {
	for _, q := range s.quota.QuotaSignals() {
		if q.Account == account.ID {
			account.Quota = append(account.Quota, q)
		}
	}

	return account
}

func (s *Service) record(ctx context.Context, actor identity.User, action, target string, detail map[string]any) {
	if err := s.audit.Record(ctx, app.AuditEvent{
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
