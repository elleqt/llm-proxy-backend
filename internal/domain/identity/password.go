package identity

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters, from the OWASP Password Storage Cheat Sheet, section
// "Argon2id": the recommended configurations are m=47104/t=1, m=19456/t=2,
// m=12288/t=3, m=9216/t=4 and m=7168/t=5, all with p=1, and the sheet states they
// "provide an equal level of defense, and the only difference is a trade off between
// CPU and RAM usage". m=19456 (19 MiB), t=2, p=1 is the configuration the same sheet
// names as the minimum in its summary, and it is the one taken here: 19 MiB per
// concurrent sign-in is affordable for a gateway that also holds request bodies in
// memory, where the 46 MiB variant would not be.
//
// These are a floor, not a constant of nature. Every one of them is written into the
// encoded hash, so raising them later needs no migration: VerifyPassword keeps
// accepting the old encoding, and the sign-in path can rehash with the new values the
// next time it sees the plaintext.
const (
	argonMemory  uint32 = 19456 // KiB
	argonTime    uint32 = 2
	argonThreads uint8  = 1
	argonKeyLen  uint32 = 32
	argonSaltLen        = 16
)

// ErrEmptyPassword rejects the empty string before it is hashed. An empty password is
// not a weak credential, it is the absence of one, and storing a hash of it would make
// "has no password" indistinguishable from "has a password nobody has to know".
var ErrEmptyPassword = errors.New("identity: empty password")

// b64 is the unpadded encoding the argon2 reference implementation uses in its PHC
// strings, so the values stored here are readable by standard tooling.
var b64 = base64.RawStdEncoding

// HashPassword derives an argon2id hash of plain with a fresh 16-byte random salt and
// returns it in PHC string format:
//
//	$argon2id$v=19$m=19456,t=2,p=1$<salt>$<key>
//
// Every parameter needed to verify the result is inside the string. Two calls with the
// same plaintext return different strings; that is the salt doing its job.
func HashPassword(plain string) (string, error) {
	if plain == "" {
		return "", ErrEmptyPassword
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("identity: read salt: %w", err)
	}
	key := argon2.IDKey([]byte(plain), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return encodeHash(argonMemory, argonTime, argonThreads, salt, key), nil
}

func encodeHash(memory, time uint32, threads uint8, salt, key []byte) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memory, time, threads,
		b64.EncodeToString(salt), b64.EncodeToString(key))
}

// VerifyPassword reports whether plain is the password behind hash.
//
// It reads the cost parameters out of hash rather than assuming the current ones, so a
// stored hash written under an older configuration still verifies. A hash that does
// not parse is a false, never a panic and never a match: a corrupt or truncated row
// must fail closed.
func VerifyPassword(hash, plain string) bool {
	memory, time, threads, salt, want, ok := decodeHash(hash)
	if !ok {
		return false
	}
	got := argon2.IDKey([]byte(plain), salt, time, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func decodeHash(hash string) (memory, time uint32, threads uint8, salt, key []byte, ok bool) {
	parts := strings.Split(hash, "$")
	// "", "argon2id", "v=19", "m=..,t=..,p=..", salt, key
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return 0, 0, 0, nil, nil, false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return 0, 0, 0, nil, nil, false
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return 0, 0, 0, nil, nil, false
	}
	// Zero parameters are not merely unusual, they make argon2.IDKey panic. A stored
	// row is untrusted input here.
	if memory == 0 || time == 0 || threads == 0 {
		return 0, 0, 0, nil, nil, false
	}
	salt, err := b64.DecodeString(parts[4])
	if err != nil || len(salt) == 0 {
		return 0, 0, 0, nil, nil, false
	}
	key, err = b64.DecodeString(parts[5])
	if err != nil || len(key) == 0 {
		return 0, 0, 0, nil, nil, false
	}
	return memory, time, threads, salt, key, true
}
