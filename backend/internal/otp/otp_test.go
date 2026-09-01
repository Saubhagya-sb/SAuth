package otp

import (
	"regexp"
	"testing"
)

func TestGenerateFormat(t *testing.T) {
	t.Parallel()
	re := regexp.MustCompile(`^\d{6}$`)
	seen := map[string]int{}
	for i := 0; i < 200; i++ {
		c, err := Generate()
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if !re.MatchString(c) {
			t.Fatalf("code %q is not 6 digits", c)
		}
		seen[c]++
	}
	if len(seen) < 150 {
		t.Fatalf("Generate looks non-random: only %d distinct of 200", len(seen))
	}
}

func TestHashEqual(t *testing.T) {
	t.Parallel()
	h := NewHasher([]byte("master-secret"))

	stored := h.Hash("123456")
	if !h.Equal("123456", stored) {
		t.Fatal("correct code should verify")
	}
	if h.Equal("654321", stored) {
		t.Fatal("wrong code must not verify")
	}
	if h.Equal("123456", "not-hex") {
		t.Fatal("malformed stored hash must not verify")
	}
}

func TestHashKeySeparation(t *testing.T) {
	t.Parallel()
	a := NewHasher([]byte("key-a"))
	b := NewHasher([]byte("key-b"))
	if a.Hash("123456") == b.Hash("123456") {
		t.Fatal("different master keys must produce different hashes")
	}
	if b.Equal("123456", a.Hash("123456")) {
		t.Fatal("a code hashed under key A must not verify under key B")
	}
}
