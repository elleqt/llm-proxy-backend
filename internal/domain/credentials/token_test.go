package credentials

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestGenerateReturnsSecretMatchingStoredHash(t *testing.T) {
	owner := uuid.New()
	tok, secret, err := Generate(owner, "laptop")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.HasPrefix(secret, "sk-") {
		t.Fatalf("secret %q must start with sk-", secret)
	}
	if tok.Hash != HashSecret(secret) {
		t.Fatal("stored hash does not match the issued secret")
	}
	assertRecordDoesNotLeakSecret(t, tok, secret)
}

// maxPrefixLen bounds what the stored record may disclose. The prefix exists so a
// key can be recognised in a list; anything longer is body the record has no reason
// to keep.
const maxPrefixLen = 8

// assertRecordDoesNotLeakSecret bounds the disclosure rather than merely checking
// that Prefix is not the whole secret: a length bound is what actually fails for an
// over-long prefix such as secret[:20], and the body probe states the rule directly.
func assertRecordDoesNotLeakSecret(t *testing.T, tok Token, secret string) {
	t.Helper()

	if len(tok.Prefix) > maxPrefixLen {
		t.Fatalf("Prefix is %d characters, want at most %d: the record discloses more of the secret than it needs to",
			len(tok.Prefix), maxPrefixLen)
	}
	if !strings.HasPrefix(secret, tok.Prefix) {
		t.Fatalf("Prefix %q is not a prefix of the issued secret", tok.Prefix)
	}

	// The body is everything after the "sk-" marker. No field of the stored record
	// may carry a recognisable run of it.
	body := secret[len("sk-"):]
	probe := body[:maxPrefixLen]
	for name, field := range map[string]string{
		"Prefix": tok.Prefix,
		"Hash":   tok.Hash,
		"Label":  tok.Label,
	} {
		if strings.Contains(field, probe) {
			t.Fatalf("%s carries the secret body", name)
		}
	}
}

func TestGenerateProducesDistinctSecrets(t *testing.T) {
	owner := uuid.New()
	_, a, _ := Generate(owner, "a")
	_, b, _ := Generate(owner, "b")
	if a == b {
		t.Fatal("two generated secrets are identical")
	}
}

func TestRevokeIsIdempotentlyRejected(t *testing.T) {
	tok, _, _ := Generate(uuid.New(), "laptop")
	admin := uuid.New()
	if err := tok.Revoke(admin, time.Now()); err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	if tok.Active() {
		t.Fatal("revoked token must not be active")
	}
	if err := tok.Revoke(admin, time.Now()); err == nil {
		t.Fatal("revoking twice must fail")
	}
}

func TestNewTokenIsActive(t *testing.T) {
	tok, _, err := Generate(uuid.New(), "laptop")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !tok.Active() {
		t.Fatal("a freshly generated token must be active")
	}
}

// Revocation is an audited action: who revoked it and when must survive on the
// record, normalised to UTC.
func TestRevokeRecordsActorAndInstant(t *testing.T) {
	tok, _, _ := Generate(uuid.New(), "laptop")
	admin := uuid.New()
	at := time.Date(2026, time.September, 22, 10, 0, 0, 0, time.FixedZone("test", 3*60*60))

	if err := tok.Revoke(admin, at); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if tok.RevokedBy == nil || *tok.RevokedBy != admin {
		t.Fatalf("RevokedBy = %v, want %v", tok.RevokedBy, admin)
	}
	if tok.RevokedAt == nil || !tok.RevokedAt.Equal(at) {
		t.Fatalf("RevokedAt = %v, want %v", tok.RevokedAt, at)
	}
	if tok.RevokedAt.Location() != time.UTC {
		t.Fatalf("RevokedAt location = %v, want UTC", tok.RevokedAt.Location())
	}
}

// The label rule is enforced by Generate, the one door every issuance goes through.
// The boundary is counted in runes, not bytes: 64 two-byte letters are a valid label.
func TestGenerateRefusesLabelsTheRuleForbids(t *testing.T) {
	for _, c := range []struct {
		name, label string
		ok          bool
	}{
		{"64 runes", strings.Repeat("é", MaxLabelRunes), true},
		{"65 runes", strings.Repeat("é", MaxLabelRunes+1), false},
		{"empty", "", false},
		{"newline", "lap\ntop", false},
		{"escape", "lap\x1b[2Jtop", false},
		{"invalid UTF-8", "lap\xfftop", false},
		{"printable", "мой ноутбук", true},
	} {
		tok, secret, err := Generate(uuid.New(), c.label)
		if c.ok {
			if err != nil || secret == "" || tok.Label != c.label {
				t.Errorf("%s: Generate = %q / %v, want the label accepted", c.name, tok.Label, err)
			}
			continue
		}
		if !errors.Is(err, ErrInvalidLabel) {
			t.Errorf("%s: err = %v, want ErrInvalidLabel", c.name, err)
		}
		if secret != "" {
			t.Errorf("%s: a secret was minted for a refused label", c.name)
		}
	}
}
