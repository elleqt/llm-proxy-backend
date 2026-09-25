package app

import "crypto/subtle"

// Answers reports whether a callback carrying state answers this challenge, in
// constant time. An empty value on either side is a mismatch: two empty strings are
// equal, and a transport that lost its cookie must not thereby accept a callback
// that carries no state either.
func (ch Challenge) Answers(state string) bool {
	if state == "" || ch.State == "" {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(state), []byte(ch.State)) == 1
}
