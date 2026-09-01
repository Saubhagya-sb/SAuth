// Package otp generates one-time passcodes and hashes them for storage.
//
// A 6-digit code has very little entropy, so a plain digest would be trivially
// brute-forced from a database dump. Instead the code is stored as an
// HMAC-SHA256 keyed with a server-side secret: without the key a dump is
// useless, and verification stays fast and constant-time.
package otp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
)

// Digits is the passcode length.
const Digits = 6

// Hasher keys an HMAC with a subkey derived from the app's master secret.
type Hasher struct{ key []byte }

func NewHasher(master []byte) *Hasher {
	sum := sha256.Sum256(append([]byte("sauth/otp/v1\x00"), master...))
	return &Hasher{key: sum[:]}
}

func (h *Hasher) Hash(code string) string {
	m := hmac.New(sha256.New, h.key)
	m.Write([]byte(code))
	return hex.EncodeToString(m.Sum(nil))
}

// Equal reports whether code matches the stored hex hash, in constant time.
func (h *Hasher) Equal(code, storedHex string) bool {
	want, err := hex.DecodeString(storedHex)
	if err != nil {
		return false
	}
	m := hmac.New(sha256.New, h.key)
	m.Write([]byte(code))
	return hmac.Equal(m.Sum(nil), want)
}

// Generate returns a cryptographically random, zero-padded numeric code.
func Generate() (string, error) {
	upper := big.NewInt(1)
	ten := big.NewInt(10)
	for i := 0; i < Digits; i++ {
		upper.Mul(upper, ten)
	}
	n, err := rand.Int(rand.Reader, upper)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*d", Digits, n), nil
}
