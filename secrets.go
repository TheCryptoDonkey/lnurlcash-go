package lnurlcash

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// HashK1 returns a note's id: the h (or h2) a wallet discloses on a rotate,
// split or merge, and the key a service stores the note under. Never the
// secret itself.
func HashK1(k1 string) (string, error) {
	raw, err := hex.DecodeString(k1)
	if err != nil {
		return "", &ProtocolError{Detail: "k1 is not hex"}
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// GenerateNoteSecret draws a fresh 32-byte note secret from the OS CSPRNG.
//
// Per LUD-25 the wallet - never the service - generates the replacement note's
// secret and discloses only its hash. The same size a Lightning payment
// preimage is, though nothing is ever paid for it.
func GenerateNoteSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("could not draw a note secret: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// SecretSource supplies replacement note secrets. Substitute for a hardware
// RNG, or for a deterministic test.
//
// A caller substituting this takes responsibility for an unpredictable 32
// bytes: anything guessable is a note anyone can spend.
type SecretSource func() (string, error)

// IsPreimage reports whether a value is 32 bytes of hex - a payment preimage,
// and therefore a note secret.
func IsPreimage(value string) bool {
	trimmed := trimSpace(value)
	if len(trimmed) != 64 {
		return false
	}
	for i := 0; i < len(trimmed); i++ {
		c := trimmed[i]
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return false
		}
	}
	return true
}
