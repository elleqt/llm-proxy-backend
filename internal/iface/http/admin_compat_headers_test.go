package http

import (
	"net/http"
	"testing"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestCompatHeaderInjectionIsAFieldError(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		t.Run(method, func(t *testing.T) {
			env := newEnv(t)

			path := "/api/admin/providers/compat"
			if method == http.MethodPut {
				path += "/openai-compatible-acme"
			}

			rec := env.do(method, path,
				`{"name":"acme","baseURL":"https://api.example.com/v1","models":[{"name":"m"}],"headers":{"x-test":"secret-value\r\nInjected: bad"}}`,
				withCookie(env.signedIn(admin())))
			apiError(t, rec, http.StatusUnprocessableEntity, codeInvalidInput)
			require.NotContains(t, rec.Body.String(), "secret-value")
			require.Contains(t, rec.Body.String(), `"field":"headers"`)
		})
	}
}

func TestCompatResponseNeverReturnsHeaderValues(t *testing.T) {
	env := newEnv(t)
	account := compatWireAccount
	account.Priority = 7
	account.Compat = &app.CompatDetails{
		Name: "acme", BaseURL: "https://api.example.com/v1",
		HeaderNames: []string{"x-token"}, Models: []app.CompatModel{{Name: "m"}},
	}
	env.accounts.EXPECT().AddCompatProvider(mock.Anything, mock.Anything).Return(account, nil)
	rec := env.do(http.MethodPost, "/api/admin/providers/compat",
		`{"name":"acme","baseURL":"https://api.example.com/v1","models":[{"name":"m"}],"priority":7,"headers":{"x-token":"secret-header-value"}}`,
		withCookie(env.signedIn(admin())))
	require.Equal(t, http.StatusCreated, rec.Code)
	require.NotContains(t, rec.Body.String(), "secret-header-value")
	require.NotContains(t, rec.Body.String(), `"headers"`)
	require.Contains(t, rec.Body.String(), `"headerNames":["x-token"]`)
}
