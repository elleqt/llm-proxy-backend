package identity

import (
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestPasswordRoundTrip(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !VerifyPassword(hash, "correct horse battery staple") {
		t.Fatal("correct password rejected")
	}
	if VerifyPassword(hash, "wrong") {
		t.Fatal("wrong password accepted")
	}
}

func TestHashesAreSalted(t *testing.T) {
	a, _ := HashPassword("same")
	b, _ := HashPassword("same")
	if a == b {
		t.Fatal("identical hashes for the same password: salt is missing")
	}
}

// The stored string has to carry every parameter, or raising the cost later locks out
// everyone whose hash was written under the old one. A hash encoded with a different
// configuration must still verify.
func TestVerifyUsesTheParametersInTheHash(t *testing.T) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("read salt: %v", err)
	}
	const (
		otherMemory  uint32 = 12288
		otherTime    uint32 = 3
		otherThreads uint8  = 1
	)
	key := argon2.IDKey([]byte("legacy secret"), salt, otherTime, otherMemory, otherThreads, argonKeyLen)
	hash := encodeHash(otherMemory, otherTime, otherThreads, salt, key)

	if !VerifyPassword(hash, "legacy secret") {
		t.Fatal("hash written with other cost parameters rejected")
	}
	if VerifyPassword(hash, "not it") {
		t.Fatal("wrong password accepted against a hash with other cost parameters")
	}
}

// The current configuration is a security floor taken from OWASP. Lowering it is a
// change that must be argued for, not one that slips in.
func TestCurrentHashRecordsTheRecommendedParameters(t *testing.T) {
	hash, err := HashPassword("whatever")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("hash = %q, want the OWASP m=19456,t=2,p=1 argon2id encoding", hash)
	}
}

// A corrupt, truncated or foreign row must fail closed rather than panic or match.
func TestVerifyRejectsUnusableHashes(t *testing.T) {
	good, err := HashPassword("secret")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	for name, hash := range map[string]string{
		"empty":            "",
		"not phc":          "secret",
		"wrong algorithm":  "$argon2i$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2E$a2V5",
		"wrong version":    "$argon2id$v=16$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2E$a2V5",
		"zero memory":      "$argon2id$v=19$m=0,t=2,p=1$c2FsdHNhbHRzYWx0c2E$a2V5",
		"zero iterations":  "$argon2id$v=19$m=19456,t=0,p=1$c2FsdHNhbHRzYWx0c2E$a2V5",
		"no parallelism":   "$argon2id$v=19$m=19456,t=2,p=0$c2FsdHNhbHRzYWx0c2E$a2V5",
		"unparseable salt": "$argon2id$v=19$m=19456,t=2,p=1$!!!!$a2V5",
		"empty key":        "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2E$",
		"truncated":        good[:len(good)-4],
	} {
		if VerifyPassword(hash, "secret") {
			t.Fatalf("%s: unusable hash %q accepted the password", name, hash)
		}
	}
}

// An empty password is the absence of a credential. Hashing it would let a user row
// whose password was never set look exactly like one whose password is "".
func TestHashPasswordRejectsTheEmptyString(t *testing.T) {
	if _, err := HashPassword(""); !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("err = %v, want ErrEmptyPassword", err)
	}
}
