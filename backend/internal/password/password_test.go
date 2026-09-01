package password

import (
	"errors"
	"strings"
	"testing"
)

func TestHashVerifyRoundTrip(t *testing.T) {
	t.Parallel()
	hash, err := Hash("correct horse battery")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if err := Verify(hash, "correct horse battery"); err != nil {
		t.Fatalf("Verify should succeed: %v", err)
	}
	if err := Verify(hash, "wrong password"); !errors.Is(err, ErrMismatch) {
		t.Fatalf("want ErrMismatch, got %v", err)
	}
}

func TestHashSaltsPerCall(t *testing.T) {
	t.Parallel()
	a, _ := Hash("same-password-1")
	b, _ := Hash("same-password-1")
	if a == b {
		t.Fatal("two hashes of the same password must differ (per-call salt)")
	}
}

func TestHashRejectsBounds(t *testing.T) {
	t.Parallel()
	if _, err := Hash("short"); !errors.Is(err, ErrTooShort) {
		t.Fatalf("want ErrTooShort, got %v", err)
	}
	if _, err := Hash(strings.Repeat("x", 73)); !errors.Is(err, ErrTooLong) {
		t.Fatalf("want ErrTooLong, got %v", err)
	}
}
