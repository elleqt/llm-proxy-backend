package gateway

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"testing/iotest"
)

// padding streams n bytes of 'x' without holding them.
func padding(n int64) io.Reader {
	return io.LimitReader(repeatByte('x'), n)
}

type repeatByte byte

func (b repeatByte) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(b)
	}
	return len(p), nil
}

// jsonBodyOf is a chat request naming model, padded to exactly size bytes.
func jsonBodyOf(model string, size int64) io.Reader {
	head, tail := `{"model":"`+model+`","messages":[],"pad":"`, `"}`
	return io.MultiReader(strings.NewReader(head), padding(size-int64(len(head)+len(tail))), strings.NewReader(tail))
}

// imageEditOf is a multipart image edit naming model whose image makes the
// whole body exactly size bytes, and its Content-Type.
func imageEditOf(t *testing.T, model string, size int64) (io.Reader, string) {
	t.Helper()
	var head bytes.Buffer
	w := multipart.NewWriter(&head)
	if err := w.WriteField("model", model); err != nil {
		t.Fatalf("write field: %v", err)
	}
	if _, err := w.CreateFormFile("image", "cat.png"); err != nil {
		t.Fatalf("create file: %v", err)
	}
	tail := "\r\n--" + w.Boundary() + "--\r\n"
	return io.MultiReader(bytes.NewReader(head.Bytes()), padding(size-int64(head.Len()+len(tail))), strings.NewReader(tail)), w.FormDataContentType()
}

// TestModelRouteBodiesAreCapped: a body at its route's limit is decided on;
// one byte more is refused with 413 before any model is read or the handler
// runs — 64 MiB on JSON routes, 256 MiB on multipart image edits — and so is
// one declaring a length over the limit, before it is read.
func TestModelRouteBodiesAreCapped(t *testing.T) {
	// A large multipart upload spills to temporary files.
	t.Setenv("TMPDIR", t.TempDir())
	catalog := fixedCatalog(map[string][]string{"gpt-5.6": {"chatgpt"}, "gpt-image-2": {"chatgpt"}})
	engine, reached := gated(staticResolver(gateSecret, gatePrincipal, "chatgpt:*"), catalog)

	send := func(path, contentType string, body io.Reader, length int64) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, body)
		req.ContentLength = length
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("Authorization", "Bearer "+gateSecret)
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)
		return rec
	}
	const tooLarge = `{"error":{"message":"request body too large","type":"invalid_request_error"}}`

	for _, tc := range []struct {
		what, path string
		limit      int64
		body       func(size int64) (io.Reader, string)
	}{
		{"a JSON chat request", "/v1/chat/completions", 64 << 20, func(size int64) (io.Reader, string) {
			return jsonBodyOf("gpt-5.6", size), "application/json"
		}},
		{"a multipart image edit", "/v1/images/edits", 256 << 20, func(size int64) (io.Reader, string) {
			return imageEditOf(t, "gpt-image-2", size)
		}},
	} {
		*reached = false
		body, contentType := tc.body(tc.limit)
		if rec := send(tc.path, contentType, body, -1); rec.Code != http.StatusOK || !*reached {
			t.Fatalf("%s of exactly %d bytes = %d %s (reached %t), want 200", tc.what, tc.limit, rec.Code, rec.Body, *reached)
		}
		*reached = false
		body, contentType = tc.body(tc.limit + 1)
		if rec := send(tc.path, contentType, body, -1); rec.Code != http.StatusRequestEntityTooLarge || rec.Body.String() != tooLarge || *reached {
			t.Fatalf("%s of %d bytes = %d %s (reached %t), want 413 %s", tc.what, tc.limit+1, rec.Code, rec.Body, *reached, tooLarge)
		}
		// A body that declares its length is refused on it, unread: any
		// read of this one fails the request some other way.
		if rec := send(tc.path, contentType, iotest.ErrReader(io.ErrUnexpectedEOF), tc.limit+1); rec.Code != http.StatusRequestEntityTooLarge || rec.Body.String() != tooLarge || *reached {
			t.Fatalf("%s declaring %d bytes = %d %s (reached %t), want 413 %s", tc.what, tc.limit+1, rec.Code, rec.Body, *reached, tooLarge)
		}
	}
}

// zstdFrame is a zstd frame (RFC 8878) with a window of 2^windowLog bytes,
// no content size and no checksum, whose blocks are raw bytes or runs of one
// byte. Hand-built, so a frame decoding to gigabytes costs kilobytes.
type zstdFrame struct {
	out bytes.Buffer
	// lastHeader is where the latest block's header starts.
	lastHeader int
}

func newZstdFrame(windowLog uint) *zstdFrame {
	f := &zstdFrame{}
	f.out.Write([]byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, byte((windowLog - 10) << 3)})
	return f
}

// block appends a block header of kind and size, then content.
func (f *zstdFrame) block(kind byte, size int, content []byte) {
	f.lastHeader = f.out.Len()
	h := uint32(size)<<3 | uint32(kind)<<1
	f.out.Write([]byte{byte(h), byte(h >> 8), byte(h >> 16)})
	f.out.Write(content)
}

// raw appends s as one raw block.
func (f *zstdFrame) raw(s string) *zstdFrame {
	f.block(0, len(s), []byte(s))
	return f
}

// run appends n copies of b as run-length blocks of at most 128 KiB.
func (f *zstdFrame) run(b byte, n int64) *zstdFrame {
	for n > 0 {
		size := min(n, 128<<10)
		f.block(1, int(size), []byte{b})
		n -= size
	}
	return f
}

// last returns the frame with its latest block marked as the final one.
func (f *zstdFrame) last() []byte {
	b := f.out.Bytes()
	b[f.lastHeader] |= 1
	return b
}

// chatDecodingTo is a zstd frame decoding to a chat request naming model,
// exactly size bytes long.
func chatDecodingTo(model string, size int64) []byte {
	head, tail := `{"model":"`+model+`","messages":[],"pad":"`, `"}`
	return newZstdFrame(17).raw(head).run('x', size-int64(len(head)+len(tail))).raw(tail).last()
}

// TestZstdBodiesAreCappedDecoded: the gate decodes a zstd body before any
// policy is read, so the decoded size is capped too, not only the bytes sent:
// a frame decoding to the limit is decided on; one decoding a byte beyond
// it, a kilobyte-sized frame decoding to a gigabyte, and a frame claiming a
// 512 MiB window are refused with 413 before the handler, without the
// allocation they ask for.
func TestZstdBodiesAreCappedDecoded(t *testing.T) {
	catalog := fixedCatalog(map[string][]string{"gpt-5.6": {"chatgpt"}})
	engine, reached := gated(staticResolver(gateSecret, gatePrincipal, "chatgpt:*"), catalog)
	send := func(frame []byte) (*httptest.ResponseRecorder, uint64) {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(frame))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Encoding", "zstd")
		req.Header.Set("Authorization", "Bearer "+gateSecret)
		rec := httptest.NewRecorder()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		engine.ServeHTTP(rec, req)
		runtime.ReadMemStats(&after)
		return rec, after.TotalAlloc - before.TotalAlloc
	}
	const limit = 64 << 20
	const tooLarge = `{"error":{"message":"request body too large","type":"invalid_request_error"}}`

	*reached = false
	if rec, _ := send(chatDecodingTo("gpt-5.6", limit)); rec.Code != http.StatusOK || !*reached {
		t.Fatalf("a frame decoding to exactly %d bytes = %d %s (reached %t), want 200", limit, rec.Code, rec.Body, *reached)
	}
	for _, tc := range []struct {
		what  string
		frame []byte
	}{
		{"a frame decoding to one byte more", chatDecodingTo("gpt-5.6", limit+1)},
		{"a frame decoding to 1 GiB", chatDecodingTo("gpt-5.6", 1<<30)},
		{"a frame claiming a 512 MiB window", newZstdFrame(29).raw(`{"model":"gpt-5.6"}`).last()},
	} {
		*reached = false
		rec, allocated := send(tc.frame)
		if rec.Code != http.StatusRequestEntityTooLarge || rec.Body.String() != tooLarge || *reached {
			t.Errorf("%s (%d bytes sent) = %d %s (reached %t), want 413 %s", tc.what, len(tc.frame), rec.Code, rec.Body, *reached, tooLarge)
		}
		// Reading up to the limit costs a few times the limit as the buffer
		// grows (more under the race detector); decoding the gigabyte, many
		// times more.
		if allocated > 8*limit {
			t.Errorf("%s allocated %d MiB, want at most %d", tc.what, allocated>>20, 8*limit>>20)
		}
	}
}
