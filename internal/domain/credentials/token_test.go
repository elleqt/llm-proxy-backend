package credentials

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateReturnsSecretMatchingStoredHash(t *testing.T) {
	owner := uuid.New()

	tok, secret, err := Generate(owner, "laptop")
	require.NoError(t, err, "Generate")
	require.True(t, strings.HasPrefix(secret, "sk-"), "secret %q must start with sk-", secret)
	require.Equal(t, HashSecret(secret), tok.Hash, "stored hash does not match the issued secret")

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

	require.LessOrEqual(t, len(tok.Prefix), maxPrefixLen,
		"Prefix length: the record discloses more of the secret than it needs to")
	require.True(t, strings.HasPrefix(secret, tok.Prefix), "Prefix %q is not a prefix of the issued secret", tok.Prefix)

	// The body is everything after the "sk-" marker. No field of the stored record
	// may carry a recognisable run of it.
	body := secret[len("sk-"):]

	probe := body[:maxPrefixLen]
	for name, field := range map[string]string{
		"Prefix": tok.Prefix,
		"Hash":   tok.Hash,
		"Label":  tok.Label,
	} {
		require.NotContains(t, field, probe, "%s carries the secret body", name)
	}
}

func TestGenerateProducesDistinctSecrets(t *testing.T) {
	owner := uuid.New()
	_, a, _ := Generate(owner, "a")

	_, b, _ := Generate(owner, "b")
	require.NotEqual(t, a, b, "two generated secrets are identical")
}

func TestRevokeIsIdempotentlyRejected(t *testing.T) {
	tok, _, _ := Generate(uuid.New(), "laptop")

	admin := uuid.New()
	require.NoError(t, tok.Revoke(admin, time.Now()), "first revoke")
	require.False(t, tok.Active(), "revoked token must not be active")
	require.Error(t, tok.Revoke(admin, time.Now()), "revoking twice must fail")
}

func TestNewTokenIsActive(t *testing.T) {
	tok, _, err := Generate(uuid.New(), "laptop")
	require.NoError(t, err, "Generate")
	require.True(t, tok.Active(), "a freshly generated token must be active")
}

// Revocation is an audited action: who revoked it and when must survive on the
// record, normalised to UTC.
func TestRevokeRecordsActorAndInstant(t *testing.T) {
	tok, _, _ := Generate(uuid.New(), "laptop")
	admin := uuid.New()
	at := time.Date(2026, time.September, 22, 10, 0, 0, 0, time.FixedZone("test", 3*60*60))

	require.NoError(t, tok.Revoke(admin, at), "Revoke")
	require.NotNil(t, tok.RevokedBy, "RevokedBy")
	require.Equal(t, admin, *tok.RevokedBy, "RevokedBy")
	require.NotNil(t, tok.RevokedAt, "RevokedAt")
	require.True(t, tok.RevokedAt.Equal(at), "RevokedAt = %v, want %v", tok.RevokedAt, at)
	require.Same(t, time.UTC, tok.RevokedAt.Location(), "RevokedAt location, want UTC")
}

// The label rule is enforced by Generate, the one door every issuance goes through.
// The boundary is counted in runes, not bytes: 64 two-byte letters are a valid label.
func TestGenerateRefusesLabelsTheRuleForbids(t *testing.T) {
	for _, tc := range []struct {
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
		t.Run(tc.name, func(t *testing.T) {
			tok, secret, err := Generate(uuid.New(), tc.label)
			if tc.ok {
				assert.NotEmpty(t, secret, "want a secret minted")
				assert.Equal(t, tc.label, tok.Label, "want the label accepted")
				require.NoError(t, err, "want the label accepted")

				return
			}

			assert.Empty(t, secret, "a secret was minted for a refused label")
			require.ErrorIs(t, err, ErrInvalidLabel)
		})
	}
}
