package auth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/saubhagyabhadhouria/sauth/internal/db"
	"github.com/saubhagyabhadhouria/sauth/internal/googleoauth"
	"github.com/saubhagyabhadhouria/sauth/internal/token"
)

const (
	oauthProvider  = "google"
	oauthStateTTL  = 10 * time.Minute
	authCodeTTL    = 60 * time.Second
	authCodeBytes  = 32
	oauthStateSize = 24
)

// StartGoogleOAuth validates the caller's redirect target, records a one-time
// CSRF state, and returns the Google consent URL to redirect the browser to.
func (s *Service) StartGoogleOAuth(ctx context.Context, projectID uuid.UUID, appRedirectURI string) (string, error) {
	project, err := s.q.GetProjectByID(ctx, projectID)
	if err != nil {
		return "", err
	}
	gcfg, err := s.googleConfigFor(project)
	if err != nil {
		return "", err
	}
	if err := validateAppRedirect(project, appRedirectURI); err != nil {
		return "", err
	}

	state, err := token.RandomToken(oauthStateSize)
	if err != nil {
		return "", err
	}
	if err := s.q.CreateOAuthState(ctx, db.CreateOAuthStateParams{
		State:       state,
		ProjectID:   projectID,
		Provider:    oauthProvider,
		RedirectUri: appRedirectURI,
		ExpiresAt:   tsFrom(time.Now().Add(oauthStateTTL)),
	}); err != nil {
		return "", err
	}
	return s.google.AuthCodeURL(gcfg, state), nil
}

// HandleGoogleCallback consumes the state, exchanges the code with Google,
// links or creates the user, and mints a short-lived auth_code. It returns the
// app redirect URI even on most failures so the handler can bounce the browser
// back with an ?error=.
func (s *Service) HandleGoogleCallback(ctx context.Context, code, state string) (appRedirectURI, authCode string, err error) {
	if strings.TrimSpace(state) == "" {
		return "", "", ErrOAuthStateInvalid
	}
	st, err := s.q.TakeOAuthState(ctx, state)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrOAuthStateInvalid
	}
	if err != nil {
		return "", "", err
	}
	if st.ExpiresAt.Time.Before(time.Now()) {
		return st.RedirectUri, "", ErrOAuthStateInvalid
	}

	project, err := s.q.GetProjectByID(ctx, st.ProjectID)
	if err != nil {
		return st.RedirectUri, "", err
	}
	gcfg, err := s.googleConfigFor(project)
	if err != nil {
		return st.RedirectUri, "", err
	}

	ident, err := s.google.Exchange(ctx, gcfg, code)
	if err != nil {
		return st.RedirectUri, "", ErrOAuthExchangeFailed
	}

	rawCode, err := token.RandomToken(authCodeBytes)
	if err != nil {
		return st.RedirectUri, "", err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return st.RedirectUri, "", err
	}
	defer tx.Rollback(ctx)
	qtx := s.q.WithTx(tx)

	user, err := s.resolveOAuthUser(ctx, qtx, project, ident)
	if err != nil {
		return st.RedirectUri, "", err
	}
	if err := qtx.CreateAuthExchangeCode(ctx, db.CreateAuthExchangeCodeParams{
		CodeHash:  token.HashRefreshToken(rawCode),
		UserID:    user.ID,
		ProjectID: project.ID,
		ExpiresAt: tsFrom(time.Now().Add(authCodeTTL)),
	}); err != nil {
		return st.RedirectUri, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return st.RedirectUri, "", err
	}
	return st.RedirectUri, rawCode, nil
}

// ExchangeAuthCode swaps the post-callback auth_code for a real token pair.
func (s *Service) ExchangeAuthCode(ctx context.Context, projectID uuid.UUID, rawCode string) (*Result, error) {
	if strings.TrimSpace(rawCode) == "" {
		return nil, ErrAuthCodeInvalid
	}
	rec, err := s.q.TakeAuthExchangeCode(ctx, db.TakeAuthExchangeCodeParams{
		CodeHash:  token.HashRefreshToken(rawCode),
		ProjectID: projectID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAuthCodeInvalid
	}
	if err != nil {
		return nil, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	qtx := s.q.WithTx(tx)

	user, err := qtx.GetUserByIDOnly(ctx, rec.UserID)
	if err != nil {
		return nil, err
	}
	if user.Banned {
		return nil, ErrUserBanned
	}
	res, err := s.issue(ctx, qtx, user)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return res, nil
}

// ---------- helpers ----------

// resolveOAuthUser implements the link/create rules:
//  1. a matching oauth_accounts row wins;
//  2. otherwise, if Google vouches the email is verified and a local user has
//     that email, link the provider to it;
//  3. otherwise create a fresh user + default role.
func (s *Service) resolveOAuthUser(ctx context.Context, q *db.Queries, project db.Project, id *googleoauth.Identity) (db.User, error) {
	if acc, err := q.GetOAuthAccount(ctx, db.GetOAuthAccountParams{
		Provider: oauthProvider, ProviderUserID: id.Sub,
	}); err == nil {
		user, err := q.GetUserByIDOnly(ctx, acc.UserID)
		if err != nil {
			return db.User{}, err
		}
		if user.ProjectID != project.ID {
			return db.User{}, ErrOAuthAccountConflict
		}
		if user.Banned {
			return db.User{}, ErrUserBanned
		}
		return user, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return db.User{}, err
	}

	email := strings.ToLower(strings.TrimSpace(id.Email))

	if id.EmailVerified {
		if user, err := q.GetUserByEmail(ctx, db.GetUserByEmailParams{
			ProjectID: project.ID, Email: &email,
		}); err == nil {
			if user.Banned {
				return db.User{}, ErrUserBanned
			}
			if _, err := q.CreateOAuthAccount(ctx, db.CreateOAuthAccountParams{
				UserID: user.ID, Provider: oauthProvider, ProviderUserID: id.Sub,
			}); err != nil {
				return db.User{}, err
			}
			if !user.EmailVerified {
				if err := q.SetUserEmailVerified(ctx, user.ID); err != nil {
					return db.User{}, err
				}
			}
			return user, nil
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return db.User{}, err
		}
	}

	user, err := q.CreateUser(ctx, db.CreateUserParams{ProjectID: project.ID, Email: &email})
	if err != nil {
		return db.User{}, mapCreateUserErr(err)
	}
	if id.EmailVerified {
		if err := q.SetUserEmailVerified(ctx, user.ID); err != nil {
			return db.User{}, err
		}
		user.EmailVerified = true
	}
	if _, err := q.CreateOAuthAccount(ctx, db.CreateOAuthAccountParams{
		UserID: user.ID, Provider: oauthProvider, ProviderUserID: id.Sub,
	}); err != nil {
		return db.User{}, err
	}
	if role, err := q.GetDefaultRole(ctx, project.ID); err == nil {
		if err := q.AssignRoleToUser(ctx, db.AssignRoleToUserParams{
			UserID: user.ID, RoleID: role.ID, ProjectID: project.ID,
		}); err != nil {
			return db.User{}, err
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return db.User{}, err
	}
	return user, nil
}

func (s *Service) googleConfigFor(project db.Project) (googleoauth.Config, error) {
	if s.google == nil || s.box == nil {
		return googleoauth.Config{}, ErrOAuthNotConfigured
	}
	if project.GoogleOauthClientID == nil || *project.GoogleOauthClientID == "" ||
		project.GoogleOauthClientSecretEnc == nil || *project.GoogleOauthClientSecretEnc == "" {
		return googleoauth.Config{}, ErrOAuthNotConfigured
	}
	secret, err := s.box.Open(*project.GoogleOauthClientSecretEnc)
	if err != nil {
		return googleoauth.Config{}, fmt.Errorf("decrypt google client secret: %w", err)
	}
	redirect := strings.TrimRight(s.publicBaseURL, "/") + "/v1/auth/oauth/google/callback"
	if project.GoogleOauthRedirectUri != nil && *project.GoogleOauthRedirectUri != "" {
		redirect = *project.GoogleOauthRedirectUri
	}
	return googleoauth.Config{
		ClientID:     *project.GoogleOauthClientID,
		ClientSecret: secret,
		RedirectURL:  redirect,
	}, nil
}

func validateAppRedirect(project db.Project, raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !u.IsAbs() || u.Host == "" {
		return ErrRedirectInvalid
	}
	origin := strings.ToLower(u.Scheme + "://" + u.Host)
	for _, allowed := range project.AllowedOrigins {
		if strings.EqualFold(strings.TrimRight(allowed, "/"), origin) {
			return nil
		}
	}
	// Dev convenience: permit loopback when no origins are configured yet.
	if len(project.AllowedOrigins) == 0 {
		if h := u.Hostname(); h == "localhost" || h == "127.0.0.1" || h == "::1" {
			return nil
		}
	}
	return ErrRedirectNotAllowed
}
