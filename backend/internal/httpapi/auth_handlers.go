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

	// Google redirects the browser here with no X-API-Key; the project is
	// recovered from the signed state, so this route sits outside requireProject.
	r.Get("/oauth/google/callback", s.handleGoogleCallback)

	r.Group(func(r chi.Router) {
		r.Use(s.requireProject)

		r.Post("/signup", s.handleSignup)
		r.Post("/login", s.handleLogin)
		r.Post("/otp/request", s.handleOTPRequest)
		r.Post("/otp/verify", s.handleOTPVerify)
		r.Get("/oauth/google/start", s.handleGoogleStart)
		r.Post("/oauth/exchange", s.handleOAuthExchange)
		r.Post("/refresh", s.handleRefresh)
		r.Post("/logout", s.handleLogout)
		r.With(s.requireAccessToken).Get("/me", s.handleMe)
	})

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

func (s *Server) handleOTPRequest(w http.ResponseWriter, r *http.Request) {
	var in struct {
		EmailOrPhone string `json:"email_or_phone"`
		Purpose      string `json:"purpose"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, r, err)
		return
	}
	if in.EmailOrPhone == "" {
		writeError(w, r, apierror.InvalidRequest("email_or_phone is required"))
		return
	}

	project := projectFrom(r.Context())
	res, err := s.auth.RequestOTP(r.Context(), auth.OTPRequestInput{
		ProjectID:   project.ID,
		OTPEnabled:  project.OtpEnabled,
		Destination: in.EmailOrPhone,
		Purpose:     in.Purpose,
	})
	if err != nil {
		writeError(w, r, mapAuthErr(err))
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleOTPVerify(w http.ResponseWriter, r *http.Request) {
	var in struct {
		OTPID string `json:"otp_id"`
		Code  string `json:"code"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, r, err)
		return
	}
	if in.OTPID == "" || in.Code == "" {
		writeError(w, r, apierror.InvalidRequest("otp_id and code are required"))
		return
	}

	project := projectFrom(r.Context())
	res, err := s.auth.VerifyOTP(r.Context(), project.ID, in.OTPID, in.Code)
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
	case errors.Is(err, auth.ErrOTPDisabled):
		return apierror.New(http.StatusForbidden, "otp_disabled", "OTP is not enabled for this project")
	case errors.Is(err, auth.ErrOTPBadPurpose):
		return apierror.InvalidRequest("purpose must be 'login' or 'signup'")
	case errors.Is(err, auth.ErrInvalidDestination):
		return apierror.InvalidRequest("email_or_phone is not a valid email or E.164 phone number")
	case errors.Is(err, auth.ErrOTPInvalid):
		return apierror.New(http.StatusUnauthorized, "otp_invalid", "the code is incorrect or no longer valid")
	case errors.Is(err, auth.ErrOTPExpired):
		return apierror.New(http.StatusUnauthorized, "otp_expired", "the code has expired; request a new one")
	case errors.Is(err, auth.ErrOTPTooManyAttempts):
		return apierror.New(http.StatusTooManyRequests, "otp_locked", "too many incorrect attempts; request a new code")
	case errors.Is(err, auth.ErrOTPThrottled):
		return apierror.New(http.StatusTooManyRequests, apierror.CodeRateLimited, "a code was just sent; wait before requesting another")
	case errors.Is(err, auth.ErrAccountExists):
		return apierror.Conflict("an account already exists for this email or phone")
	case errors.Is(err, auth.ErrOAuthNotConfigured):
		return apierror.New(http.StatusBadRequest, "oauth_not_configured", "Google OAuth is not configured for this project")
	case errors.Is(err, auth.ErrRedirectInvalid):
		return apierror.InvalidRequest("redirect_uri must be an absolute URL")
	case errors.Is(err, auth.ErrRedirectNotAllowed):
		return apierror.New(http.StatusForbidden, "redirect_not_allowed", "redirect_uri origin is not in the project's allowed origins")
	case errors.Is(err, auth.ErrOAuthStateInvalid):
		return apierror.New(http.StatusBadRequest, "oauth_state_invalid", "the OAuth state is missing, expired, or already used")
	case errors.Is(err, auth.ErrOAuthExchangeFailed):
		return apierror.New(http.StatusBadGateway, "oauth_exchange_failed", "Google rejected the authorization code")
	case errors.Is(err, auth.ErrAuthCodeInvalid):
		return apierror.New(http.StatusUnauthorized, "auth_code_invalid", "the auth_code is invalid, expired, or already used")
	case errors.Is(err, auth.ErrOAuthAccountConflict):
		return apierror.Conflict("this Google account is linked to another project")
	default:
		return err // -> 500 via writeError
	}
}
