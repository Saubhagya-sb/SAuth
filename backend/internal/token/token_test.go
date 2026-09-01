package token

import (
	"testing"
	"time"
)

func newTestIssuer(ttl time.Duration) *Issuer {
	return NewIssuer([]byte("test-secret-at-least-32-bytes-long!!"), "sauth-test", ttl)
}

func TestAccessTokenRoundTrip(t *testing.T) {
	t.Parallel()
	iss := newTestIssuer(15 * time.Minute)

	raw, exp, err := iss.IssueAccess("user-1", "proj-1", []string{"admin"}, []string{"users:write"})
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	if time.Until(exp) <= 0 {
		t.Fatal("expiry should be in the future")
	}

	claims, err := iss.ParseAccess(raw)
	if err != nil {
		t.Fatalf("ParseAccess: %v", err)
	}
	if claims.Subject != "user-1" || claims.ProjectID != "proj-1" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if len(claims.Roles) != 1 || claims.Roles[0] != "admin" {
		t.Fatalf("roles not preserved: %+v", claims.Roles)
	}
}

func TestAccessTokenRejectsExpired(t *testing.T) {
	t.Parallel()
	iss := newTestIssuer(-1 * time.Minute) // already expired

	raw, _, err := iss.IssueAccess("user-1", "proj-1", nil, nil)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	if _, err := iss.ParseAccess(raw); err == nil {
		t.Fatal("expired token must not parse")
	}
}

func TestAccessTokenRejectsWrongSecret(t *testing.T) {
	t.Parallel()
	raw, _, _ := newTestIssuer(time.Minute).IssueAccess("u", "p", nil, nil)

	other := NewIssuer([]byte("a-completely-different-secret-32b!!!!"), "sauth-test", time.Minute)
	if _, err := other.ParseAccess(raw); err == nil {
		t.Fatal("token signed with a different secret must not parse")
	}
}

func TestRefreshTokenHashing(t *testing.T) {
	t.Parallel()
	raw, hash, err := NewRefreshToken()
	if err != nil {
		t.Fatalf("NewRefreshToken: %v", err)
	}
	if raw == hash {
		t.Fatal("raw token must not equal its hash")
	}
	if HashRefreshToken(raw) != hash {
		t.Fatal("HashRefreshToken must be deterministic")
	}

	raw2, _, _ := NewRefreshToken()
	if raw2 == raw {
		t.Fatal("refresh tokens must be unique per call")
	}
}
