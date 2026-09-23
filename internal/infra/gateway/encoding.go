package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// Upstream decodes a request's Content-Encoding in two places, both without
// a bound: handlers.ReadRequestBody (sdk/api/handlers/request_body.go) and the
// request logger (internal/api/middleware/request_logging.go
// decodeCapturedRequestBody), which runs on every non-GET request the gate
// passes on, before any handler. So no encoded body leaves the gate: on the
// routes whose handler decodes one, the gate decodes it once, under a bound,
// and hands the handler the identity-encoded result; everywhere else it
// refuses it. Upstream's handlers read an identity body as sent, and the
// executors build their own requests to vendors — the client's
// Content-Encoding is dropped with the header, and upstream strips it from
// forwarded headers anyway (handlers/header_filter.go).

// Decoding limits. A decoded body may be at most maxJSONBody. The decoder's
// window, and so its history buffers, is capped at maxDecodeWindow: an
// encoder at its default settings uses far less. What decoding holds is
// charged to bodyBudget (body_budget.go).
const maxDecodeWindow = 8 << 20

// Decoding outcomes the gate answers.
var (
	errDecodedTooLarge = errors.New("gateway: decoded request body too large")
	errUnreadableBody  = errors.New("gateway: request body cannot be decoded")
)

// contentEncoding is every coding the request's Content-Encoding header lines
// name, joined, and whether any of them is not identity.
func contentEncoding(r *http.Request) (string, bool) {
	values := r.Header.Values("Content-Encoding")
	encoded := false
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			if p := strings.TrimSpace(part); p != "" && !strings.EqualFold(p, "identity") {
				encoded = true
			}
		}
	}
	return strings.Join(values, ","), encoded
}

// setBody makes body the request's body, identity-encoded.
func setBody(r *http.Request, body []byte) {
	r.Header.Del("Content-Encoding")
	r.Header.Set("Content-Length", strconv.Itoa(len(body)))
	r.ContentLength = int64(len(body))
	r.Body = io.NopCloser(bytes.NewReader(body))
}

// decodeRequestBody decodes raw, the body as sent, which held charges. It
// mirrors upstream's decodeRequestBody — codings undone last first, empty and
// identity ones skipped, zstd decoded, any other an error, and a body that
// fails to decode but is valid JSON as sent used as sent — with the decoding
// bounded, and charged a whole maxJSONBody more to held while it runs (or
// errBodyBusy when that is not granted). On success held charges the decoded
// body instead of raw; on error it may charge more, until released.
func decodeRequestBody(ctx context.Context, raw []byte, encoding string, held *bodyCharge) ([]byte, error) {
	if err := held.grow(ctx, maxJSONBody); err != nil {
		return nil, err
	}
	decoded, err := decodeBody(raw, encoding, maxJSONBody)
	switch {
	case errors.Is(err, errDecodedTooLarge):
		return nil, err
	case err != nil && json.Valid(raw):
		decoded = raw
	case err != nil:
		return nil, errUnreadableBody
	}
	held.shrinkTo(int64(cap(decoded)))
	return decoded, nil
}

// decodeBody undoes encoding on raw, no layer decoding to more than limit
// bytes.
func decodeBody(raw []byte, encoding string, limit int64) ([]byte, error) {
	parts := strings.Split(encoding, ",")
	body := raw
	for i := len(parts) - 1; i >= 0; i-- {
		switch coding := strings.ToLower(strings.TrimSpace(parts[i])); coding {
		case "", "identity":
		case "zstd":
			decoded, err := decodeZstd(body, limit)
			if err != nil {
				return nil, err
			}
			body = decoded
		default:
			return nil, fmt.Errorf("gateway: unsupported request content encoding %q", coding)
		}
	}
	return body, nil
}

// decodeZstd decodes one zstd layer, refusing a window beyond
// maxDecodeWindow or an output beyond limit before allocating for it.
func decodeZstd(in []byte, limit int64) ([]byte, error) {
	dec, err := zstd.NewReader(bytes.NewReader(in),
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderLowmem(true),
		zstd.WithDecoderMaxWindow(maxDecodeWindow),
		zstd.WithDecoderMaxMemory(uint64(limit)))
	if err != nil {
		return nil, err
	}
	defer dec.Close()
	out, err := io.ReadAll(io.LimitReader(dec, limit+1))
	switch {
	case errors.Is(err, zstd.ErrWindowSizeExceeded), errors.Is(err, zstd.ErrDecoderSizeExceeded):
		return nil, errDecodedTooLarge
	case err != nil:
		return nil, err
	case int64(len(out)) > limit:
		return nil, errDecodedTooLarge
	}
	return out, nil
}
