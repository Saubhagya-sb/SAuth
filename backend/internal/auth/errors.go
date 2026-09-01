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
)
