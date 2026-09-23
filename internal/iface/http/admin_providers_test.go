package http

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/iface/http/api"
)

func TestListProviderAccountsWithTheirQuota(t *testing.T) {
	e := newEnv(t)
	refreshed := e.clock.Now().Add(-time.Hour)
	reset := e.clock.Now().Add(4 * time.Hour)
	e.accounts.EXPECT().Accounts().Return([]app.VendorAccount{
		{ID: "claude-a.json", Provider: "claude", Label: "team", Email: "a@example.com", Status: "active", LastRefreshedAt: refreshed},
		{ID: "codex-b.json", Provider: "chatgpt", Status: "error", Disabled: true, LastError: "refresh failed"},
	})
	e.quota.EXPECT().QuotaSignals().Return([]app.QuotaSignal{
		{Account: "claude-a.json", Provider: "claude", Window: "5h", UsedRatio: 0.25, ResetAt: reset, ObservedAt: refreshed},
	})
	var got []api.ProviderAccount
	decodeBody(t, e.do(http.MethodGet, "/api/admin/providers", "", withCookie(e.signedIn(admin()))), http.StatusOK, &got)
	if len(got) != 2 {
		t.Fatalf("accounts = %+v", got)
	}
	a, b := got[0], got[1]
	if a.Id != "claude-a.json" || a.Label == nil || *a.Label != "team" || a.Email == nil || a.LastError != nil ||
		a.LastRefreshedAt == nil || !a.LastRefreshedAt.Equal(refreshed) || len(a.Quota) != 1 ||
		a.Quota[0].Window != "5h" || a.Quota[0].UsedRatio != 0.25 || a.Quota[0].ResetAt == nil || !a.Quota[0].ResetAt.Equal(reset) {
		t.Fatalf("claude account = %+v", a)
	}
	if !b.Disabled || b.LastError == nil || *b.LastError != "refresh failed" || b.Label != nil || b.Email != nil ||
		b.LastRefreshedAt != nil || b.Quota == nil || len(b.Quota) != 0 {
		t.Fatalf("chatgpt account = %+v, want absent optionals and an empty (not null) quota", b)
	}
}

func TestStartingAProviderLogin(t *testing.T) {
	t.Run("started", func(t *testing.T) {
		e := newEnv(t)
		expires := e.clock.Now().Add(5 * time.Minute)
		e.logins.EXPECT().StartLogin(mock.Anything, "claude").
			Return(app.VendorLogin{SessionID: "s1", AuthURL: "https://vendor.example.com/auth?state=x", ExpiresAt: expires}, nil)
		var got api.ProviderLoginSession
		decodeBody(t, e.do(http.MethodPost, "/api/admin/providers/login/start", `{"provider":"claude"}`, withCookie(e.signedIn(admin()))),
			http.StatusCreated, &got)
		if got.SessionId != "s1" || got.AuthURL != "https://vendor.example.com/auth?state=x" || !got.ExpiresAt.Equal(expires) {
			t.Fatalf("session = %+v", got)
		}
	})
	for name, c := range map[string]struct {
		err    error
		status int
		code   string
	}{
		"busy":        {app.ErrLoginsBusy, http.StatusConflict, codeLoginBusy},
		"unsupported": {app.ErrUnsupportedProvider, http.StatusUnprocessableEntity, codeUnsupportedProvider},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.logins.EXPECT().StartLogin(mock.Anything, "gemini").Return(app.VendorLogin{}, c.err)
			apiError(t, e.do(http.MethodPost, "/api/admin/providers/login/start", `{"provider":"gemini"}`, withCookie(e.signedIn(admin()))),
				c.status, c.code)
		})
	}
}

// The pasted callback URL carries the vendor's authorisation code: it reaches the
// gateway and no response, whether the login succeeds or fails.
func TestCompletingAProviderLoginNeverEchoesTheCallback(t *testing.T) {
	const code = "AUTHCODE-4f2a9c"
	const body = `{"sessionId":"s1","callbackURL":"https://console.example.com/cb?code=` + code + `&state=x"}`
	t.Run("added", func(t *testing.T) {
		e := newEnv(t)
		e.logins.EXPECT().CompleteLogin(mock.Anything, "s1", "https://console.example.com/cb?code="+code+"&state=x").
			Return(app.VendorAccount{ID: "claude-new.json", Provider: "claude", Status: "active"}, nil)
		e.quota.EXPECT().QuotaSignals().Return(nil)
		rec := e.do(http.MethodPost, "/api/admin/providers/login/complete", body, withCookie(e.signedIn(admin())))
		var got api.ProviderAccount
		decodeBody(t, rec, http.StatusCreated, &got)
		if got.Id != "claude-new.json" || got.Provider != "claude" || strings.Contains(rec.Body.String(), code) {
			t.Fatalf("answer %s: want the added account and not the code", rec.Body)
		}
	})
	for name, c := range map[string]struct {
		err    error
		status int
		code   string
	}{
		"expired": {app.ErrLoginExpired, http.StatusGone, codeLoginExpired},
		"refused": {app.ErrLoginFailed, http.StatusUnprocessableEntity, codeLoginFailed},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.logins.EXPECT().CompleteLogin(mock.Anything, "s1", mock.Anything).Return(app.VendorAccount{}, c.err)
			rec := e.do(http.MethodPost, "/api/admin/providers/login/complete", body, withCookie(e.signedIn(admin())))
			apiError(t, rec, c.status, c.code)
			if strings.Contains(rec.Body.String(), code) {
				t.Fatalf("the refusal echoes the code: %s", rec.Body)
			}
		})
	}
}

// Completing a login outlasts the server's write timeout: the route extends its own
// deadline, so the answer still reaches the client.
func TestCompletingAProviderLoginOutlastsTheWriteTimeout(t *testing.T) {
	e := newEnv(t)
	const slow = 300 * time.Millisecond
	e.logins.EXPECT().CompleteLogin(mock.Anything, "s1", mock.Anything).
		RunAndReturn(func(context.Context, string, string) (app.VendorAccount, error) {
			time.Sleep(slow)
			return app.VendorAccount{ID: "claude-new.json", Provider: "claude"}, nil
		})
	e.quota.EXPECT().QuotaSignals().Return(nil)
	srv := httptest.NewUnstartedServer(e.handler)
	srv.Config.WriteTimeout = slow / 3
	srv.Start()
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/admin/providers/login/complete",
		strings.NewReader(`{"sessionId":"s1","callbackURL":"https://console.example.com/cb?code=c&state=x"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(e.signedIn(admin()))
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("no answer after %s with a %s write timeout: %v", slow, srv.Config.WriteTimeout, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, body %s; want 201", resp.StatusCode, b)
	}
}

func TestDisablingAProviderAccount(t *testing.T) {
	const id = "claude-a.json"
	path := "/api/admin/providers/" + id
	t.Run("disabled", func(t *testing.T) {
		e := newEnv(t)
		e.accounts.EXPECT().Accounts().Return([]app.VendorAccount{{ID: id, Provider: "claude", Disabled: true, Status: "disabled"}})
		e.accounts.EXPECT().SetAccountDisabled(mock.Anything, id, true).Return(nil)
		e.acctMet.EXPECT().SetAccountDisabled(id, "claude", true).Return()
		e.quota.EXPECT().QuotaSignals().Return(nil)
		var got api.ProviderAccount
		decodeBody(t, e.do(http.MethodPatch, path, `{"disabled":true}`, withCookie(e.signedIn(admin()))), http.StatusOK, &got)
		if got.Id != id || !got.Disabled {
			t.Fatalf("account = %+v", got)
		}
	})
	// Without `disabled` the request says nothing; it must not re-enable the account
	// (the gateway mock expects no call).
	for _, body := range []string{`{}`, `{"disabled":null}`, `{"disabled":"yes"}`} {
		t.Run(body, func(t *testing.T) {
			e := newEnv(t)
			rec := e.do(http.MethodPatch, path, body, withCookie(e.signedIn(admin())))
			wantField(t, apiError(t, rec, http.StatusUnprocessableEntity, codeInvalidInput), "disabled")
		})
	}
	t.Run("unknown account", func(t *testing.T) {
		e := newEnv(t)
		e.accounts.EXPECT().Accounts().Return(nil)
		apiError(t, e.do(http.MethodPatch, path, `{"disabled":true}`, withCookie(e.signedIn(admin()))), http.StatusNotFound, codeNotFound)
	})
}

func TestRemovingAProviderAccount(t *testing.T) {
	const id = "claude-a.json"
	t.Run("removed", func(t *testing.T) {
		e := newEnv(t)
		e.accounts.EXPECT().Accounts().Return([]app.VendorAccount{{ID: id, Provider: "claude"}})
		e.accounts.EXPECT().RemoveAccount(mock.Anything, id).Return(nil)
		e.quota.EXPECT().ForgetAccount(id).Return()
		e.acctMet.EXPECT().ForgetAccount(id, "claude").Return()
		rec := e.do(http.MethodDelete, "/api/admin/providers/"+id, "", withCookie(e.signedIn(admin())))
		if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
			t.Fatalf("status = %d, body %s; want 204", rec.Code, rec.Body)
		}
	})
	t.Run("unknown account", func(t *testing.T) {
		e := newEnv(t)
		e.accounts.EXPECT().Accounts().Return(nil)
		apiError(t, e.do(http.MethodDelete, "/api/admin/providers/"+id, "", withCookie(e.signedIn(admin()))), http.StatusNotFound, codeNotFound)
	})
}
