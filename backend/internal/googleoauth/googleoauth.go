// Package googleoauth wraps the Google OAuth2 authorization-code flow behind a
// small interface so the auth service can be tested without hitting Google.
package googleoauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// Config is the per-project Google client configuration.
type Config struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string // our /v1/auth/oauth/google/callback, as registered with Google
}

// Identity is the subset of the Google profile we care about.
type Identity struct {
	Sub           string
	Email         string
	EmailVerified bool
	Name          string
}

// Provider is the surface the auth service depends on.
type Provider interface {
	AuthCodeURL(cfg Config, state string) string
	Exchange(ctx context.Context, cfg Config, code string) (*Identity, error)
}

type Client struct{ httpClient *http.Client }

func NewClient() *Client {
	return &Client{httpClient: &http.Client{Timeout: 10 * time.Second}}
}

func (c *Client) oauth2Config(cfg Config) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     google.Endpoint,
		Scopes: []string{
			"openid",
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
	}
}

func (c *Client) AuthCodeURL(cfg Config, state string) string {
	return c.oauth2Config(cfg).AuthCodeURL(
		state,
		oauth2.AccessTypeOnline,
		oauth2.SetAuthURLParam("prompt", "select_account"),
	)
}

func (c *Client) Exchange(ctx context.Context, cfg Config, code string) (*Identity, error) {
	oc := c.oauth2Config(cfg)
	ctx = context.WithValue(ctx, oauth2.HTTPClient, c.httpClient)

	tok, err := oc.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://www.googleapis.com/oauth2/v2/userinfo", nil)
	if err != nil {
		return nil, err
	}
	resp, err := oc.Client(ctx, tok).Do(req)
	if err != nil {
		return nil, fmt.Errorf("userinfo request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo: unexpected status %d", resp.StatusCode)
	}

	var body struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		VerifiedEmail bool   `json:"verified_email"`
		Name          string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode userinfo: %w", err)
	}
	if body.ID == "" || body.Email == "" {
		return nil, fmt.Errorf("userinfo: missing id or email")
	}
	return &Identity{
		Sub:           body.ID,
		Email:         body.Email,
		EmailVerified: body.VerifiedEmail,
		Name:          body.Name,
	}, nil
}
