package app

import (
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// The request fields a proxy choice is refused on.
const (
	FieldProxyMode = "proxy.mode"
	FieldProxyURL  = "proxy.url"
)

// maxProxyURL bounds what an administrator types as a proxy URL.
const maxProxyURL = 2048

// proxySchemes are the schemes upstream dials a proxy with
// (sdk/proxyutil Parse).
var proxySchemes = []string{"http", "https", "socks5", "socks5h"}

// Validate checks c and returns it normalised: a custom URL trimmed, no URL
// beside inherit or direct. It accepts what upstream's proxyutil.Parse reads
// as a proxy, and refuses a port outside 1-65535 it would only fail to dial.
// The refusal names the field, never the URL: it may carry a password.
func (c ProxyChoice) Validate() (ProxyChoice, error) {
	switch c.Mode {
	case ProxyInherit, ProxyDirect:
		if strings.TrimSpace(c.URL) != "" {
			return ProxyChoice{}, &InvalidInputError{Field: FieldProxyURL}
		}

		return ProxyChoice{Mode: c.Mode}, nil
	case ProxyCustom:
		raw := strings.TrimSpace(c.URL)

		u, err := url.Parse(raw)
		if raw == "" || len(raw) > maxProxyURL || err != nil || !slices.Contains(proxySchemes, u.Scheme) ||
			u.Hostname() == "" || !validProxyPort(u.Port()) {
			return ProxyChoice{}, &InvalidInputError{Field: FieldProxyURL}
		}

		return ProxyChoice{Mode: ProxyCustom, URL: raw}, nil
	default:
		return ProxyChoice{}, &InvalidInputError{Field: FieldProxyMode}
	}
}

// validProxyPort accepts no port (the scheme's default) or 1-65535.
func validProxyPort(port string) bool {
	if port == "" {
		return true
	}

	n, err := strconv.Atoi(port)

	return err == nil && n >= 1 && n <= 65535
}
