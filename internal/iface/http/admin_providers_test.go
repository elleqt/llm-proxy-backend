package http

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/iface/http/api"
	"github.com/stretchr/testify/mock"
)

func TestListProviderAccountsWithTheirQuota(t *testing.T) {
	env := newEnv(t)
	refreshed := env.clock.Now().Add(-time.Hour)
	reset := env.clock.Now().Add(4 * time.Hour)
	env.accounts.EXPECT().Accounts().Return([]app.VendorAccount{
		{ID: "claude-a.json", Provider: "claude", Label: "team", Email: "a@example.com", Status: "active", LastRefreshedAt: refreshed},
		{ID: "codex-b.json", Provider: "chatgpt", Status: "error", Disabled: true, LastError: "refresh failed"},
	})
	env.quota.EXPECT().QuotaSignals().Return([]app.QuotaSignal{
		{Account: "claude-a.json", Provider: "claude", Window: "5h", UsedRatio: 0.25, ResetAt: reset, ObservedAt: refreshed},
	})

	var got []api.ProviderAccount
	decodeBody(t, env.do(http.MethodGet, "/api/admin/providers", "", withCookie(env.signedIn(admin()))), http.StatusOK, &got)

	if len(got) != 2 {
		t.Fatalf("accounts = %+v", got)
	}

	claude, chatgpt := got[0], got[1]
	if claude.Id != "claude-a.json" || claude.Label == nil || *claude.Label != "team" || claude.Email == nil || claude.LastError != nil ||
		claude.LastRefreshedAt == nil || !claude.LastRefreshedAt.Equal(refreshed) || len(claude.Quota) != 1 ||
		claude.Quota[0].Window != "5h" || claude.Quota[0].UsedRatio != 0.25 || claude.Quota[0].ResetAt == nil || !claude.Quota[0].ResetAt.Equal(reset) {
		t.Fatalf("claude account = %+v", claude)
	}

	if !chatgpt.Disabled || chatgpt.LastError == nil || *chatgpt.LastError != "refresh failed" || chatgpt.Label != nil || chatgpt.Email != nil ||
		chatgpt.LastRefreshedAt != nil || chatgpt.Quota == nil || len(chatgpt.Quota) != 0 {
		t.Fatalf("chatgpt account = %+v, want absent optionals and an empty (not null) quota", chatgpt)
	}
}

func TestStartingAProviderLogin(t *testing.T) {
	t.Run("started", func(t *testing.T) {
		env := newEnv(t)
		expires := env.clock.Now().Add(5 * time.Minute)
		env.logins.EXPECT().StartLogin(mock.Anything, "claude").
			Return(app.VendorLogin{SessionID: "s1", AuthURL: "https://vendor.example.com/auth?state=x", ExpiresAt: expires}, nil)

		var got api.ProviderLoginSession
		decodeBody(t, env.do(http.MethodPost, "/api/admin/providers/login/start", `{"provider":"claude"}`, withCookie(env.signedIn(admin()))),
			http.StatusCreated, &got)

		if got.SessionId != "s1" || got.AuthURL != "https://vendor.example.com/auth?state=x" || !got.ExpiresAt.Equal(expires) {
			t.Fatalf("session = %+v", got)
		}
	})

	for name, tc := range map[string]struct {
		err    error
		status int
		code   string
	}{
		"busy":        {app.ErrLoginsBusy, http.StatusConflict, codeLoginBusy},
		"unsupported": {app.ErrUnsupportedProvider, http.StatusUnprocessableEntity, codeUnsupportedProvider},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.logins.EXPECT().StartLogin(mock.Anything, "gemini").Return(app.VendorLogin{}, tc.err)
			apiError(t, e.do(http.MethodPost, "/api/admin/providers/login/start", `{"provider":"gemini"}`, withCookie(e.signedIn(admin()))),
				tc.status, tc.code)
		})
	}
}

// The pasted callback URL carries the vendor's authorisation code: it reaches the
// gateway and no response, whether the login succeeds or fails.
func TestCompletingAProviderLoginNeverEchoesTheCallback(t *testing.T) {
	const (
		code = "AUTHCODE-4f2a9c"
		body = `{"sessionId":"s1","callbackURL":"https://console.example.com/cb?code=` + code + `&state=x"}`
	)

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

	for name, tc := range map[string]struct {
		err    error
		status int
		code   string
	}{
		"expired": {app.ErrLoginExpired, http.StatusGone, codeLoginExpired},
		"refused": {app.ErrLoginFailed, http.StatusUnprocessableEntity, codeLoginFailed},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.logins.EXPECT().CompleteLogin(mock.Anything, "s1", mock.Anything).Return(app.VendorAccount{}, tc.err)
			rec := e.do(http.MethodPost, "/api/admin/providers/login/complete", body, withCookie(e.signedIn(admin())))
			apiError(t, rec, tc.status, tc.code)

			if strings.Contains(rec.Body.String(), code) {
				t.Fatalf("the refusal echoes the code: %s", rec.Body)
			}
		})
	}
}

// Completing a login outlasts the server's write timeout: the route extends its own
// deadline, so the answer still reaches the client.
func TestCompletingAProviderLoginOutlastsTheWriteTimeout(t *testing.T) {
	env := newEnv(t)

	const slow = 300 * time.Millisecond

	env.logins.EXPECT().CompleteLogin(mock.Anything, "s1", mock.Anything).
		RunAndReturn(func(context.Context, string, string) (app.VendorAccount, error) {
			time.Sleep(slow)

			return app.VendorAccount{ID: "claude-new.json", Provider: "claude"}, nil
		})
	env.quota.EXPECT().QuotaSignals().Return(nil)
	srv := httptest.NewUnstartedServer(env.handler)
	srv.Config.WriteTimeout = slow / 3
	srv.Start()
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/api/admin/providers/login/complete",
		strings.NewReader(`{"sessionId":"s1","callbackURL":"https://console.example.com/cb?code=c&state=x"}`))
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(env.signedIn(admin()))

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
		env := newEnv(t)
		env.accounts.EXPECT().Accounts().Return([]app.VendorAccount{{ID: id, Provider: "claude", Disabled: true, Status: "disabled"}})
		env.accounts.EXPECT().SetAccountDisabled(mock.Anything, id, true).Return(nil)
		env.acctMet.EXPECT().SetAccountDisabled(id, "claude", true).Return()
		env.quota.EXPECT().QuotaSignals().Return(nil)

		var got api.ProviderAccount
		decodeBody(t, env.do(http.MethodPatch, path, `{"disabled":true}`, withCookie(env.signedIn(admin()))), http.StatusOK, &got)

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
		env := newEnv(t)
		env.accounts.EXPECT().Accounts().Return([]app.VendorAccount{{ID: id, Provider: "claude"}})
		env.accounts.EXPECT().RemoveAccount(mock.Anything, id).Return(nil)
		env.quota.EXPECT().ForgetAccount(id).Return()
		env.acctMet.EXPECT().ForgetAccount(id, "claude").Return()

		rec := env.do(http.MethodDelete, "/api/admin/providers/"+id, "", withCookie(env.signedIn(admin())))
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
