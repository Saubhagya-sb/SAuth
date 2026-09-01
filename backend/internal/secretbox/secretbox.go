// Package secretbox encrypts small secrets (e.g. a project's Google OAuth
// client secret) for storage, using AES-256-GCM with a random nonce prepended
// to the ciphertext. Output is base64 for a text column.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

type Box struct{ aead cipher.AEAD }

func New(key []byte) (*Box, error) {
	if len(key) != 32 {
		return nil, errors.New("secretbox: key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

func (b *Box) Seal(plaintext string) (string, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := b.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

func (b *Box) Open(encoded string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	ns := b.aead.NonceSize()
	if len(raw) < ns {
		return "", errors.New("secretbox: ciphertext too short")
	}
	pt, err := b.aead.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}
