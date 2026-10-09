package app_test

import (
	"strings"
	"testing"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/stretchr/testify/require"
)

// TestProxyChoiceValidate: the three modes and nothing else; a URL only for
// custom, with a scheme upstream dials, a host and a real port. Accepted
// choices come back normalised: trimmed, and no URL beside inherit or direct.
func TestProxyChoiceValidate(t *testing.T) {
	for name, tc := range map[string]struct {
		in    app.ProxyChoice
		want  app.ProxyChoice
		field string
	}{
		"inherit":              {in: app.ProxyChoice{Mode: app.ProxyInherit}, want: app.ProxyChoice{Mode: app.ProxyInherit}},
		"direct":               {in: app.ProxyChoice{Mode: app.ProxyDirect}, want: app.ProxyChoice{Mode: app.ProxyDirect}},
		"custom http":          {in: app.ProxyChoice{Mode: app.ProxyCustom, URL: " http://proxy.example.com:3128 "}, want: app.ProxyChoice{Mode: app.ProxyCustom, URL: "http://proxy.example.com:3128"}},
		"custom with userinfo": {in: app.ProxyChoice{Mode: app.ProxyCustom, URL: "socks5://u:p@proxy.example.com:1080"}, want: app.ProxyChoice{Mode: app.ProxyCustom, URL: "socks5://u:p@proxy.example.com:1080"}},
		"custom https no port": {in: app.ProxyChoice{Mode: app.ProxyCustom, URL: "https://proxy.example.com"}, want: app.ProxyChoice{Mode: app.ProxyCustom, URL: "https://proxy.example.com"}},
		"custom socks5h":       {in: app.ProxyChoice{Mode: app.ProxyCustom, URL: "socks5h://proxy.example.com:1080"}, want: app.ProxyChoice{Mode: app.ProxyCustom, URL: "socks5h://proxy.example.com:1080"}},
		"empty mode":           {in: app.ProxyChoice{}, field: app.FieldProxyMode},
		"unknown mode":         {in: app.ProxyChoice{Mode: "none"}, field: app.FieldProxyMode},
		"inherit with url":     {in: app.ProxyChoice{Mode: app.ProxyInherit, URL: "http://proxy.example.com"}, field: app.FieldProxyURL},
		"direct with url":      {in: app.ProxyChoice{Mode: app.ProxyDirect, URL: "http://proxy.example.com"}, field: app.FieldProxyURL},
		"custom without url":   {in: app.ProxyChoice{Mode: app.ProxyCustom, URL: "  "}, field: app.FieldProxyURL},
		"custom bad scheme":    {in: app.ProxyChoice{Mode: app.ProxyCustom, URL: "ftp://proxy.example.com"}, field: app.FieldProxyURL},
		"custom no scheme":     {in: app.ProxyChoice{Mode: app.ProxyCustom, URL: "proxy.example.com:3128"}, field: app.FieldProxyURL},
		"custom no host":       {in: app.ProxyChoice{Mode: app.ProxyCustom, URL: "http://:3128"}, field: app.FieldProxyURL},
		"custom port 0":        {in: app.ProxyChoice{Mode: app.ProxyCustom, URL: "http://proxy.example.com:0"}, field: app.FieldProxyURL},
		"custom port 65536":    {in: app.ProxyChoice{Mode: app.ProxyCustom, URL: "http://proxy.example.com:65536"}, field: app.FieldProxyURL},
		"custom too long":      {in: app.ProxyChoice{Mode: app.ProxyCustom, URL: "http://proxy.example.com/" + strings.Repeat("a", 2048)}, field: app.FieldProxyURL},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := tc.in.Validate()
			if tc.field == "" {
				require.NoError(t, err)
				require.Equal(t, tc.want, got)

				return
			}

			var invalid *app.InvalidInputError
			require.ErrorAs(t, err, &invalid)
			require.Equal(t, tc.field, invalid.Field)
			require.NotContains(t, err.Error(), "proxy.example.com", "the error names the URL")
		})
	}
}
