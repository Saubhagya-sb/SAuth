// Package config loads and validates runtime configuration from the
// environment (and an optional .env file in development).
package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	HTTPAddr        string
	Env             string
	DatabaseURL     string
	PublicBaseURL   string // externally reachable base URL, for OAuth callbacks
	JWTSecret       []byte
	JWTIssuer       string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	EncryptionKey   []byte // AES-256 key for provider secrets at rest; optional in dev
}

// Load reads configuration from the environment. It loads a .env file first
// if one exists, but never overrides variables already set in the environment.
func Load() (*Config, error) {
	_ = godotenv.Load() // best-effort; absent .env is fine

	c := &Config{
		HTTPAddr:      envOr("SAUTH_HTTP_ADDR", ":8080"),
		Env:           envOr("SAUTH_ENV", "development"),
		DatabaseURL:   os.Getenv("SAUTH_DATABASE_URL"),
		PublicBaseURL: envOr("SAUTH_PUBLIC_BASE_URL", "http://localhost:8080"),
		JWTIssuer:     envOr("SAUTH_JWT_ISSUER", "sauth"),
	}

	if c.DatabaseURL == "" {
		return nil, fmt.Errorf("SAUTH_DATABASE_URL is required")
	}

	secret := os.Getenv("SAUTH_JWT_SECRET")
	if len(secret) < 32 {
		return nil, fmt.Errorf("SAUTH_JWT_SECRET must be at least 32 characters (got %d)", len(secret))
	}
	c.JWTSecret = []byte(secret)

	var err error
	if c.AccessTokenTTL, err = envDuration("SAUTH_ACCESS_TOKEN_TTL", 15*time.Minute); err != nil {
		return nil, err
	}
	if c.RefreshTokenTTL, err = envDuration("SAUTH_REFRESH_TOKEN_TTL", 720*time.Hour); err != nil {
		return nil, err
	}

	if enc := os.Getenv("SAUTH_ENCRYPTION_KEY"); enc != "" {
		key, err := base64.StdEncoding.DecodeString(enc)
		if err != nil {
			return nil, fmt.Errorf("SAUTH_ENCRYPTION_KEY: not valid base64: %w", err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("SAUTH_ENCRYPTION_KEY must decode to 32 bytes (got %d)", len(key))
		}
		c.EncryptionKey = key
	}

	return c, nil
}

func (c *Config) IsProduction() bool { return c.Env == "production" }

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envDuration(key string, fallback time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return d, nil
}
