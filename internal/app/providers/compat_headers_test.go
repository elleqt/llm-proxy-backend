package providers_test

import (
	"testing"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/stretchr/testify/require"
)

func TestCompatRejectsUnsafeHeaders(t *testing.T) {
	cases := map[string]map[string]string{
		"injected value":      {"x-test": "secret\r\nInjected: bad"},
		"invalid name":        {"bad header": "value"},
		"duplicate name":      {"X-Test": "one", "x-test": "two"},
		"authorization":       {"Authorization": "Bearer must-not-override"},
		"proxy authorization": {"Proxy-Authorization": "secret"},
		"host":                {"Host": "elsewhere.example.com"},
		"framing":             {"Content-Length": "7"},
		"empty value":         {"x-test": "  "},
		"control byte":        {"x-test": "secret\x00value"},
	}
	for name, headers := range cases {
		t.Run(name, func(t *testing.T) {
			for _, update := range []bool{false, true} {
				fixture := newProvidersFixture(t)

				var err error
				if update {
					_, err = fixture.svc.UpdateCompat(t.Context(), providerAdmin(), compatAccount.ID, app.CompatProviderUpdate{
						BaseURL: "https://api.example.com/v1", Models: []app.CompatModel{{Name: "m"}}, Headers: headers,
					})
				} else {
					_, err = fixture.svc.CreateCompat(t.Context(), providerAdmin(), app.CompatProvider{
						Name: "acme", BaseURL: "https://api.example.com/v1", Models: []app.CompatModel{{Name: "m"}}, Headers: headers,
					})
				}

				var invalid *app.InvalidInputError
				require.ErrorAs(t, err, &invalid)
				require.Equal(t, "headers", invalid.Field)
			}
		})
	}
}
