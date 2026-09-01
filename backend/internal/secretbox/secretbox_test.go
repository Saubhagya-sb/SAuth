package secretbox

import (
	"strings"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	t.Parallel()
	b, err := New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	enc, err := b.Seal("my-google-client-secret")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(enc, "my-google-client-secret") {
		t.Fatal("ciphertext leaks plaintext")
	}
	got, err := b.Open(enc)
	if err != nil || got != "my-google-client-secret" {
		t.Fatalf("Open = %q, %v", got, err)
	}
}

func TestSealIsNonDeterministic(t *testing.T) {
	t.Parallel()
	b, _ := New([]byte("0123456789abcdef0123456789abcdef"))
	a, _ := b.Seal("x")
	c, _ := b.Seal("x")
	if a == c {
		t.Fatal("Seal must use a random nonce each call")
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	t.Parallel()
	a, _ := New([]byte("0123456789abcdef0123456789abcdef"))
	other, _ := New([]byte("FFFFFFFFFFFFFFFF0123456789abcdef"))
	enc, _ := a.Seal("secret")
	if _, err := other.Open(enc); err == nil {
		t.Fatal("Open with the wrong key must fail")
	}
}

func TestNewRejectsShortKey(t *testing.T) {
	t.Parallel()
	if _, err := New([]byte("too-short")); err == nil {
		t.Fatal("want error for non-32-byte key")
	}
}
