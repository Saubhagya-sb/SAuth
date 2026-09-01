// Package apierror defines the wire error shape used by every endpoint:
//
//	{ "error": { "code": "...", "message": "...", "request_id": "..." } }
package apierror

import "net/http"

type Code string

const (
	CodeInvalidRequest     Code = "invalid_request"
	CodeInvalidCredentials Code = "invalid_credentials"
	CodeUnauthorized       Code = "unauthorized"
	CodeForbidden          Code = "forbidden"
	CodeNotFound           Code = "not_found"
	CodeConflict           Code = "conflict"
	CodeRateLimited        Code = "rate_limited"
	CodeInternal           Code = "internal_error"
)

// Error is an HTTP-aware error. Handlers return it (or wrap it) and the
// central writer renders it as JSON with the right status.
type Error struct {
	Status  int
	Code    Code
	Message string
}

func (e *Error) Error() string { return string(e.Code) + ": " + e.Message }

func New(status int, code Code, msg string) *Error {
	return &Error{Status: status, Code: code, Message: msg}
}

func InvalidRequest(msg string) *Error {
	return New(http.StatusBadRequest, CodeInvalidRequest, msg)
}

func InvalidCredentials() *Error {
	return New(http.StatusUnauthorized, CodeInvalidCredentials, "email or password is incorrect")
}

func Unauthorized(msg string) *Error {
	return New(http.StatusUnauthorized, CodeUnauthorized, msg)
}

func Forbidden(msg string) *Error {
	return New(http.StatusForbidden, CodeForbidden, msg)
}

func NotFound(msg string) *Error {
	return New(http.StatusNotFound, CodeNotFound, msg)
}

func Conflict(msg string) *Error {
	return New(http.StatusConflict, CodeConflict, msg)
}

func Internal() *Error {
	return New(http.StatusInternalServerError, CodeInternal, "an internal error occurred")
}
