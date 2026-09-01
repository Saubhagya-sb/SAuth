package auth

import "errors"

var (
	ErrEmailTaken         = errors.New("email already registered")
	ErrUsernameTaken      = errors.New("username already taken")
	ErrInvalidEmail       = errors.New("email is not valid")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserBanned         = errors.New("user is banned")
	ErrRefreshInvalid     = errors.New("invalid or expired refresh token")
	ErrRefreshReuse       = errors.New("refresh token reuse detected")
	ErrUserNotFound       = errors.New("user not found")

	// OTP
	ErrOTPDisabled        = errors.New("otp is not enabled for this project")
	ErrOTPBadPurpose      = errors.New("otp purpose must be 'login' or 'signup'")
	ErrInvalidDestination = errors.New("destination is not a valid email or E.164 phone")
	ErrOTPInvalid         = errors.New("otp code is invalid")
	ErrOTPExpired         = errors.New("otp code has expired")
	ErrOTPTooManyAttempts = errors.New("too many incorrect attempts")
	ErrOTPThrottled       = errors.New("an otp was requested too recently")
	ErrAccountExists      = errors.New("an account already exists for this destination")

	// OAuth
	ErrOAuthNotConfigured   = errors.New("google oauth is not configured for this project")
	ErrRedirectInvalid      = errors.New("redirect_uri is not a valid absolute URL")
	ErrRedirectNotAllowed   = errors.New("redirect_uri origin is not in the project's allowed origins")
	ErrOAuthStateInvalid    = errors.New("oauth state is missing, expired, or already used")
	ErrOAuthExchangeFailed  = errors.New("google rejected the authorization code")
	ErrAuthCodeInvalid      = errors.New("auth_code is invalid, expired, or already used")
	ErrOAuthAccountConflict = errors.New("this google account is linked to another project")
)
