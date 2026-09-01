// Package password hashes and verifies end-user / admin passwords with bcrypt.
//
// bcrypt (deliberately slow, salted) is the right tool for low-entropy secrets
// like passwords. High-entropy random tokens (refresh tokens, OTP codes) are
// hashed with SHA-256 instead — see package token.
package password

import (
	"errors"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

// Cost is the bcrypt work factor. 12 is ~150-300ms per hash on current
// hardware — expensive enough to slow credential stuffing, cheap enough for
// interactive login.
const Cost = 12

// MaxLen is bcrypt's hard input limit; longer inputs are silently truncated by
// the algorithm, so we reject them explicitly.
const MaxLen = 72

var (
	ErrMismatch  = errors.New("password does not match")
	ErrTooLong   = errors.New("password exceeds 72 bytes")
	ErrTooShort  = errors.New("password must be at least 8 characters")
)

// Hash returns the bcrypt hash of plain.
func Hash(plain string) (string, error) {
	if len(plain) < 8 {
		return "", ErrTooShort
	}
	if len(plain) > MaxLen {
		return "", ErrTooLong
	}
	b, err := bcrypt.GenerateFromPassword([]byte(plain), Cost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// dummyHash is a real bcrypt hash computed once, used by VerifyDummy to spend
// roughly the same CPU as a genuine Verify when there is no user to check.
var dummyHash = sync.OnceValue(func() string {
	h, _ := bcrypt.GenerateFromPassword([]byte("timing-equalizer-not-a-real-password"), Cost)
	return string(h)
})

// VerifyDummy runs a throwaway comparison to blunt user-enumeration timing
// attacks on the login path. The result is intentionally discarded.
func VerifyDummy(plain string) {
	_ = bcrypt.CompareHashAndPassword([]byte(dummyHash()), []byte(plain))
}

// Verify reports whether plain matches hash. It returns ErrMismatch on a clean
// non-match so callers can distinguish "wrong password" from an internal error.
func Verify(hash, plain string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain))
	switch {
	case err == nil:
		return nil
	case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
		return ErrMismatch
	default:
		return err
	}
}
