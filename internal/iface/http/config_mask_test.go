package http

import (
	"net/http"
	"testing"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/iface/http/api"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestAdminMaskingPreferencePreservesExplicitOffAcrossOtherUpdates(t *testing.T) {
	env := newEnv(t)
	cookie := withCookie(env.signedIn(admin()))

	var initial api.AdminConfig
	decodeBody(t, env.do(http.MethodGet, "/api/admin/config", "", cookie), http.StatusOK, &initial)
	require.True(t, initial.MaskUnknownErrors)
	env.settings.EXPECT().SetDisplayConfig(mock.Anything, app.DisplayConfig{MaskUnknownErrors: false}, mock.Anything, env.clock.Now()).Return(nil).Once()

	var off api.AdminConfig
	decodeBody(t, env.do(http.MethodPut, "/api/admin/config", `{"maskUnknownErrors":false}`, cookie), http.StatusOK, &off)
	require.False(t, off.MaskUnknownErrors)
	require.False(t, off.CostsVisible)
	require.False(t, env.deps.Display.MaskUnknownErrors())
	env.settings.EXPECT().SetDisplayConfig(mock.Anything, app.DisplayConfig{CostsVisible: true, MaskUnknownErrors: false}, mock.Anything, env.clock.Now()).Return(nil).Once()

	var changed api.AdminConfig
	decodeBody(t, env.do(http.MethodPut, "/api/admin/config", `{"costsVisible":true}`, cookie), http.StatusOK, &changed)
	require.True(t, changed.CostsVisible)
	require.False(t, changed.MaskUnknownErrors)

	var reloaded api.AdminConfig
	decodeBody(t, env.do(http.MethodGet, "/api/admin/config", "", cookie), http.StatusOK, &reloaded)
	require.False(t, reloaded.MaskUnknownErrors)
	require.True(t, reloaded.CostsVisible)
	apiError(t, env.do(http.MethodPut, "/api/admin/config", `{}`, cookie), http.StatusUnprocessableEntity, codeInvalidInput)
}
