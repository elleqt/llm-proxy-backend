package http

import (
	"net/http"
	"slices"
	"testing"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/iface/http/api"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const compatWireKey = "sk-compat-wire-5e1d"

var compatWireAccount = app.VendorAccount{
	ID: "openai-compatible-acme", Provider: "acme", Status: "active", Label: "acme",
	Compat: &app.CompatDetails{
		Name: "acme", BaseURL: "https://api.example.com/v1", HasAPIKey: true,
		Models: []app.CompatModel{{Name: "m", Alias: "m-fast"}},
	},
}

// TestCreateCompatProviderTakesTheKeyAndNeverShowsIt: the request's key
// reaches the gateway, and the answer says a key is stored without it.
func TestCreateCompatProviderTakesTheKeyAndNeverShowsIt(t *testing.T) {
	env := newEnv(t)
	env.accounts.EXPECT().AddCompatProvider(mock.Anything, app.CompatProvider{
		Name: "acme", BaseURL: "https://api.example.com/v1", APIKey: compatWireKey,
		Models: []app.CompatModel{{Name: "m", Alias: "m-fast"}},
	}).Return(compatWireAccount, nil)

	rec := env.do(http.MethodPost, "/api/admin/providers/compat",
		`{"name":"acme","baseURL":"https://api.example.com/v1","apiKey":"`+compatWireKey+`","models":[{"name":"m","alias":"m-fast"}]}`,
		withCookie(env.signedIn(admin())))

	require.NotContains(t, rec.Body.String(), compatWireKey, "the answer carries the key")

	var got api.ProviderAccount
	decodeBody(t, rec, http.StatusCreated, &got)
	require.Equal(t, "acme", got.Provider)
	require.NotNil(t, got.Compat)
	require.True(t, got.Compat.HasApiKey)
	require.Equal(t, "https://api.example.com/v1", got.Compat.BaseURL)
	require.Len(t, got.Compat.Models, 1)
	require.Equal(t, "m-fast", *got.Compat.Models[0].Alias)
}

// TestCreateCompatProviderTakesTheProxy: the request's proxy reaches the gateway.
func TestCreateCompatProviderTakesTheProxy(t *testing.T) {
	env := newEnv(t)
	env.accounts.EXPECT().AddCompatProvider(mock.Anything, app.CompatProvider{
		Name: "acme", BaseURL: "https://api.example.com/v1",
		Models: []app.CompatModel{{Name: "m"}}, Proxy: &app.ProxyChoice{Mode: app.ProxyDirect},
	}).Return(compatWireAccount, nil)

	rec := env.do(http.MethodPost, "/api/admin/providers/compat",
		`{"name":"acme","baseURL":"https://api.example.com/v1","models":[{"name":"m"}],"proxy":{"mode":"direct"}}`,
		withCookie(env.signedIn(admin())))
	require.Equal(t, http.StatusCreated, rec.Code, "body %s", rec.Body)
}

func TestCreateCompatProviderRefusals(t *testing.T) {
	body := `{"name":"acme","baseURL":"https://api.example.com/v1","models":[{"name":"m"}]}`

	t.Run("taken name", func(t *testing.T) {
		env := newEnv(t)
		env.accounts.EXPECT().AddCompatProvider(mock.Anything, mock.Anything).Return(app.VendorAccount{}, app.ErrConflict)
		apiError(t, env.do(http.MethodPost, "/api/admin/providers/compat", body, withCookie(env.signedIn(admin()))),
			http.StatusConflict, codeConflict)
	})

	t.Run("reserved name", func(t *testing.T) {
		env := newEnv(t)
		env.accounts.EXPECT().AddCompatProvider(mock.Anything, mock.Anything).
			Return(app.VendorAccount{}, &app.InvalidInputError{Field: "name"})
		apiError(t, env.do(http.MethodPost, "/api/admin/providers/compat", body, withCookie(env.signedIn(admin()))),
			http.StatusUnprocessableEntity, codeInvalidInput)
	})
}

// TestUpdateCompatProviderKeyIntent: an absent key keeps the stored one,
// clearApiKey removes it, and a key replaces it.
func TestUpdateCompatProviderKeyIntent(t *testing.T) {
	const models = `"models":[{"name":"m"}]`

	empty, replaced := "", "sk-new"

	for name, tc := range map[string]struct {
		body string
		want *string
	}{
		"kept":     {`{"baseURL":"https://api.example.com/v1",` + models + `}`, nil},
		"cleared":  {`{"baseURL":"https://api.example.com/v1","clearApiKey":true,` + models + `}`, &empty},
		"replaced": {`{"baseURL":"https://api.example.com/v1","apiKey":"sk-new","clearApiKey":true,` + models + `}`, &replaced},
	} {
		t.Run(name, func(t *testing.T) {
			env := newEnv(t)
			env.quota.EXPECT().QuotaSignals().Return(nil)
			env.accounts.EXPECT().UpdateCompatProvider(mock.Anything, compatWireAccount.ID, mock.MatchedBy(func(update app.CompatProviderUpdate) bool {
				if tc.want == nil {
					// No proxy in the request keeps the stored one.
					return update.APIKey == nil && update.Proxy == nil
				}

				return update.APIKey != nil && *update.APIKey == *tc.want
			})).Return(compatWireAccount, nil)

			rec := env.do(http.MethodPut, "/api/admin/providers/compat/"+compatWireAccount.ID, tc.body, withCookie(env.signedIn(admin())))
			require.Equal(t, http.StatusOK, rec.Code, "body %s", rec.Body)
		})
	}
}

func TestDiscoverCompatModels(t *testing.T) {
	body := `{"baseURL":"https://api.example.com/v1","apiKey":"` + compatWireKey + `"}`

	t.Run("listed", func(t *testing.T) {
		env := newEnv(t)
		env.accounts.EXPECT().DiscoverModels(mock.Anything, "https://api.example.com/v1", compatWireKey, "", (*app.ProxyChoice)(nil)).
			Return([]string{"m", "shared"}, nil)
		env.accounts.EXPECT().Accounts().Return(nil)
		env.catalog.EXPECT().Models().Return(map[string][]string{"other": {"shared"}})

		var got api.CompatDiscoverResult
		decodeBody(t, env.do(http.MethodPost, "/api/admin/providers/compat/discover", body, withCookie(env.signedIn(admin()))),
			http.StatusOK, &got)
		require.Equal(t, []string{"m", "shared"}, got.Models)
		require.Equal(t, map[string][]string{"shared": {"other"}}, got.Conflicts)
	})

	t.Run("through the named proxy", func(t *testing.T) {
		env := newEnv(t)
		env.accounts.EXPECT().DiscoverModels(mock.Anything, "https://api.example.com/v1", compatWireKey, "", &app.ProxyChoice{Mode: app.ProxyInherit}).
			Return([]string{"m"}, nil)
		env.accounts.EXPECT().Accounts().Return(nil)
		env.catalog.EXPECT().Models().Return(nil)

		inherit := `{"baseURL":"https://api.example.com/v1","apiKey":"` + compatWireKey + `","proxy":{"mode":"inherit"}}`
		rec := env.do(http.MethodPost, "/api/admin/providers/compat/discover", inherit, withCookie(env.signedIn(admin())))
		require.Equal(t, http.StatusOK, rec.Code, "body %s", rec.Body)
	})

	for name, tc := range map[string]struct {
		err    error
		status int
		code   string
	}{
		"unreachable":  {app.ErrProviderUnreachable, http.StatusBadGateway, codeProviderUnreachable},
		"key refused":  {app.ErrProviderAuthFailed, http.StatusUnprocessableEntity, codeProviderAuthFailed},
		"bad base URL": {&app.InvalidInputError{Field: "baseURL"}, http.StatusUnprocessableEntity, codeInvalidInput},
	} {
		t.Run(name, func(t *testing.T) {
			env := newEnv(t)
			env.accounts.EXPECT().DiscoverModels(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, tc.err)
			rec := env.do(http.MethodPost, "/api/admin/providers/compat/discover", body, withCookie(env.signedIn(admin())))
			apiError(t, rec, tc.status, tc.code)
			require.NotContains(t, rec.Body.String(), compatWireKey)
		})
	}
}

// TestCompatReasoningLevelsOnTheWire: a model's own list reaches the gateway on
// create and update, an absent one stays nil, and the answer carries the list.
func TestCompatReasoningLevelsOnTheWire(t *testing.T) {
	own := app.VendorAccount{
		ID: compatWireAccount.ID, Provider: "acme", Status: "active", Label: "acme",
		Compat: &app.CompatDetails{
			Name: "acme", BaseURL: "https://api.example.com/v1",
			Models: []app.CompatModel{{Name: "m", ReasoningLevels: []string{"low", "max"}}, {Name: "n"}},
		},
	}
	models := []app.CompatModel{{Name: "m", ReasoningLevels: []string{"low", "max"}}, {Name: "n"}}
	modelsJSON := `"models":[{"name":"m","reasoningLevels":["low","max"]},{"name":"n"}]`

	t.Run("create", func(t *testing.T) {
		env := newEnv(t)
		env.accounts.EXPECT().AddCompatProvider(mock.Anything, app.CompatProvider{
			Name: "acme", BaseURL: "https://api.example.com/v1", Models: models,
		}).Return(own, nil)

		rec := env.do(http.MethodPost, "/api/admin/providers/compat",
			`{"name":"acme","baseURL":"https://api.example.com/v1",`+modelsJSON+`}`, withCookie(env.signedIn(admin())))

		var got api.ProviderAccount
		decodeBody(t, rec, http.StatusCreated, &got)
		require.NotNil(t, got.Compat)
		require.Len(t, got.Compat.Models, 2)
		require.NotNil(t, got.Compat.Models[0].ReasoningLevels)
		require.Equal(t, []string{"low", "max"}, *got.Compat.Models[0].ReasoningLevels)
		require.Nil(t, got.Compat.Models[1].ReasoningLevels, "the default set is not echoed")
	})

	t.Run("update", func(t *testing.T) {
		env := newEnv(t)
		env.quota.EXPECT().QuotaSignals().Return(nil)
		env.accounts.EXPECT().UpdateCompatProvider(mock.Anything, own.ID, mock.MatchedBy(func(update app.CompatProviderUpdate) bool {
			return len(update.Models) == 2 &&
				slices.Equal(update.Models[0].ReasoningLevels, []string{"low", "max"}) && update.Models[1].ReasoningLevels == nil
		})).Return(own, nil)

		rec := env.do(http.MethodPut, "/api/admin/providers/compat/"+own.ID,
			`{"baseURL":"https://api.example.com/v1",`+modelsJSON+`}`, withCookie(env.signedIn(admin())))
		require.Equal(t, http.StatusOK, rec.Code, "body %s", rec.Body)
	})

	t.Run("refused list", func(t *testing.T) {
		env := newEnv(t)
		rec := env.do(http.MethodPost, "/api/admin/providers/compat",
			`{"name":"acme","baseURL":"https://api.example.com/v1","models":[{"name":"m","reasoningLevels":["low","low"]}]}`,
			withCookie(env.signedIn(admin())))
		apiError(t, rec, http.StatusUnprocessableEntity, codeInvalidInput)
		require.Contains(t, rec.Body.String(), `"models"`)
	})
}

func TestGetCompatDefaults(t *testing.T) {
	t.Run("admin", func(t *testing.T) {
		env := newEnv(t)

		var got api.CompatDefaults
		decodeBody(t, env.do(http.MethodGet, "/api/admin/providers/compat/defaults", "", withCookie(env.signedIn(admin()))),
			http.StatusOK, &got)
		require.Equal(t, app.DefaultReasoningLevels, got.ReasoningLevels)
	})

	t.Run("user", func(t *testing.T) {
		env := newEnv(t)
		apiError(t, env.do(http.MethodGet, "/api/admin/providers/compat/defaults", "",
			withCookie(env.signedIn(person("someone@example.com")))), http.StatusNotFound, codeNotFound)
	})
}
