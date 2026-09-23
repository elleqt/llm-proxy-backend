package credentials

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

const secretBytes = 32

// MaxLabelRunes bounds a token label. The label is owner-chosen text that is copied
// into lists, audit details and a metrics label value, so it is short and printable.
const MaxLabelRunes = 64

var (
	ErrAlreadyRevoked = errors.New("credentials: token already revoked")
	ErrInvalidLabel   = errors.New("credentials: invalid token label")
)

// ValidateLabel accepts 1 to MaxLabelRunes runes of valid UTF-8 with no control
// characters. A newline or an escape sequence in a label forges lines in every log
// and terminal it is printed to; an unbounded one is a free write into every place
// the label is copied.
func ValidateLabel(label string) error {
	if label == "" || !utf8.ValidString(label) {
		return ErrInvalidLabel
	}
	n := 0
	for _, r := range label {
		n++
		if n > MaxLabelRunes || unicode.IsControl(r) {
			return ErrInvalidLabel
		}
	}
	return nil
}

type Token struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	Label      string
	Hash       string
	Prefix     string
	CreatedAt  time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
	RevokedBy  *uuid.UUID
}

// Generate returns the record to store and the secret to show exactly once.
// The secret is never recoverable from the record. A label ValidateLabel refuses is
// ErrInvalidLabel: every issuance comes through here, so no path mints a key under
// a label the rule forbids.
func Generate(owner uuid.UUID, label string) (Token, string, error) {
	if err := ValidateLabel(label); err != nil {
		return Token{}, "", err
	}
	raw := make([]byte, secretBytes)
	if _, err := rand.Read(raw); err != nil {
		return Token{}, "", fmt.Errorf("credentials: entropy: %w", err)
	}
	secret := "sk-" + base64.RawURLEncoding.EncodeToString(raw)
	return Token{
		ID:        uuid.New(),
		UserID:    owner,
		Label:     label,
		Hash:      HashSecret(secret),
		Prefix:    secret[:7],
		CreatedAt: time.Now().UTC(),
	}, secret, nil
}

func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func (t Token) Active() bool { return t.RevokedAt == nil }

func (t *Token) Revoke(by uuid.UUID, at time.Time) error {
	if t.RevokedAt != nil {
		return ErrAlreadyRevoked
	}
	when := at.UTC()
	t.RevokedAt = &when
	t.RevokedBy = &by
	return nil
}
