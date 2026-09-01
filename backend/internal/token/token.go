// Package token issues and verifies the two credential types the auth API
// hands out:
//
//   - Access token: a short-lived HS256 JWT carrying the user's roles and
//     permissions as claims, so resource servers can authorize without a DB hit.
//   - Refresh token: an opaque 256-bit random string. Only its SHA-256 hash is
//     stored server-side; it is rotated on every use so a replayed old token is
//     detectable as theft.
package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// AccessClaims is the payload of an access-token JWT.
type AccessClaims struct {
	ProjectID   string   `json:"project_id"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	jwt.RegisteredClaims
}

// Issuer signs and verifies access tokens with a shared HMAC secret.
type Issuer struct {
	secret    []byte
	issuer    string
	accessTTL time.Duration
}

func NewIssuer(secret []byte, issuer string, accessTTL time.Duration) *Issuer {
	return &Issuer{secret: secret, issuer: issuer, accessTTL: accessTTL}
}

// IssueAccess mints a signed access token for the given user/project.
func (i *Issuer) IssueAccess(userID, projectID string, roles, permissions []string) (string, time.Time, error) {
	now := time.Now()
	exp := now.Add(i.accessTTL)
	claims := AccessClaims{
		ProjectID:   projectID,
		Roles:       roles,
		Permissions: permissions,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    i.issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
			ID:        uuid.NewString(),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(i.secret)
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, exp, nil
}

// ParseAccess verifies signature, method, issuer and expiry, returning the claims.
func (i *Issuer) ParseAccess(raw string) (*AccessClaims, error) {
	var claims AccessClaims
	_, err := jwt.ParseWithClaims(raw, &claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return i.secret, nil
	}, jwt.WithIssuer(i.issuer), jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil {
		return nil, err
	}
	return &claims, nil
}

// NewRefreshToken returns a fresh opaque refresh token and its storage hash.
// Persist only the hash; return raw to the client once.
func NewRefreshToken() (raw, hash string, err error) {
	b := make([]byte, 32) // 256 bits
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	return raw, HashRefreshToken(raw), nil
}

// HashRefreshToken is the deterministic hash used for refresh-token lookups.
// SHA-256 is appropriate here (unlike passwords) because the input is
// full-entropy random — no need for a slow KDF, and we want O(1) index lookups.
func HashRefreshToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
