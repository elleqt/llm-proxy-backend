package providers

import (
	"regexp"
	"strings"

	"github.com/elleqt/llm-proxy-backend/internal/app"
)

var compatHeaderName = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9a-z-]+$")

// validCompatHeaders keeps omission distinct from removing every stored header.
// Values are secrets, so validation errors identify only the whole field.
func validCompatHeaders(in map[string]string) (map[string]string, error) {
	if in == nil {
		return nil, nil //nolint:nilnil // nil preserves the stored map.
	}

	out := make(map[string]string, len(in))
	for rawName, rawValue := range in {
		name := strings.ToLower(strings.TrimSpace(rawName))

		value := strings.TrimSpace(rawValue)
		if strings.ContainsAny(rawName, "\r\n") || !compatHeaderName.MatchString(name) ||
			forbiddenCompatHeader(name) || value == "" || !validCompatHeaderValue(rawValue) {
			return nil, &app.InvalidInputError{Field: "headers"}
		}

		if _, exists := out[name]; exists {
			return nil, &app.InvalidInputError{Field: "headers"}
		}

		out[name] = value
	}

	return out, nil
}

// forbiddenCompatHeader keeps credential selection and HTTP framing authoritative.
func forbiddenCompatHeader(name string) bool {
	switch name {
	case "authorization", "proxy-authorization", "host", "content-length", "transfer-encoding",
		"connection", "proxy-connection", "keep-alive", "te", "trailer", "upgrade":
		return true
	default:
		return false
	}
}

func validCompatHeaderValue(value string) bool {
	for i := range len(value) {
		b := value[i]
		if b == 127 || (b < 32 && b != '\t') {
			return false
		}
	}

	return true
}
