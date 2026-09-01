package httpapi

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/saubhagyabhadhouria/sauth/internal/apierror"
	"github.com/saubhagyabhadhouria/sauth/internal/auth"
	"github.com/saubhagyabhadhouria/sauth/internal/password"
)

func (s *Server) authRouter() http.Handler {
	r := chi.NewRouter()
	r.Use(s.requireProject)

	r.Post("/signup", s.handleSignup)
	r.Post("/login", s.handleLogin)
	r.Post("/refresh", s.handleRefresh)
	r.Post("/logout", s.handleLogout)
	r.With(s.requireAccessToken).Get("/me", s.handleMe)

	return r
}

func (s *Server) handleSignup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email    string `json:"email"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, r, err)
		return
	}
	if in.Email == "" || in.Password == "" {
		writeError(w, r, apierror.InvalidRequest("email and password are required"))
		return
	}

	project := projectFrom(r.Context())
	res, err := s.auth.Signup(r.Context(), auth.SignupInput{
		ProjectID: project.ID,
		Email:     in.Email,
		Username:  in.Username,
		Password:  in.Password,
	})
	if err != nil {
		writeError(w, r, mapAuthErr(err))
		return
	}
	writeJSON(w, http.StatusCreated, res)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		EmailOrUsername string `json:"email_or_username"`
		Password        string `json:"password"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, r, err)
		return
	}

	project := projectFrom(r.Context())
	res, err := s.auth.Login(r.Context(), project.ID, in.EmailOrUsername, in.Password)
	if err != nil {
		writeError(w, r, mapAuthErr(err))
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, r, err)
		return
	}

	res, err := s.auth.Refresh(r.Context(), in.RefreshToken)
	if err != nil {
		writeError(w, r, mapAuthErr(err))
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, r, err)
		return
	}
	if err := s.auth.Logout(r.Context(), in.RefreshToken); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	project := projectFrom(r.Context())

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		writeError(w, r, apierror.Unauthorized("malformed subject in access token"))
		return
	}

	res, err := s.auth.Me(r.Context(), userID, project.ID)
	if err != nil {
		writeError(w, r, mapAuthErr(err))
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// mapAuthErr converts a domain error from the auth service into a wire error.
func mapAuthErr(err error) error {
	switch {
	case errors.Is(err, auth.ErrEmailTaken):
		return apierror.Conflict("email already registered")
	case errors.Is(err, auth.ErrUsernameTaken):
		return apierror.Conflict("username already taken")
	case errors.Is(err, auth.ErrInvalidEmail):
		return apierror.InvalidRequest("email is not valid")
	case errors.Is(err, password.ErrTooShort):
		return apierror.InvalidRequest("password must be at least 8 characters")
	case errors.Is(err, password.ErrTooLong):
		return apierror.InvalidRequest("password must be at most 72 bytes")
	case errors.Is(err, auth.ErrInvalidCredentials):
		return apierror.InvalidCredentials()
	case errors.Is(err, auth.ErrUserBanned):
		return apierror.New(http.StatusForbidden, "user_banned", "this account has been banned")
	case errors.Is(err, auth.ErrRefreshInvalid):
		return apierror.Unauthorized("invalid or expired refresh token")
	case errors.Is(err, auth.ErrRefreshReuse):
		return apierror.New(http.StatusUnauthorized, "refresh_token_reuse", "refresh token reuse detected; all sessions for this user have been revoked")
	case errors.Is(err, auth.ErrUserNotFound):
		return apierror.NotFound("user not found")
	default:
		return err // -> 500 via writeError
	}
}
