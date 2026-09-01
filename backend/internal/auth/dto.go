package auth

import (
	"time"

	"github.com/saubhagyabhadhouria/sauth/internal/db"
)

// UserDTO is the public user shape returned by signup / login / me.
type UserDTO struct {
	ID            string    `json:"id"`
	Email         *string   `json:"email"`
	Username      *string   `json:"username"`
	Phone         *string   `json:"phone"`
	EmailVerified bool      `json:"email_verified"`
	Roles         []string  `json:"roles"`
	CreatedAt     time.Time `json:"created_at"`
}

// Result is the payload for the token-issuing endpoints.
type Result struct {
	AccessToken  string  `json:"access_token"`
	RefreshToken string  `json:"refresh_token"`
	TokenType    string  `json:"token_type"`
	ExpiresIn    int     `json:"expires_in"` // access-token lifetime, seconds
	User         UserDTO `json:"user"`
}

// MeResult is the /auth/me payload: profile plus the flattened permission set.
type MeResult struct {
	User        UserDTO  `json:"user"`
	Permissions []string `json:"permissions"`
}

func toUserDTO(u db.User, roles []string) UserDTO {
	return UserDTO{
		ID:            u.ID.String(),
		Email:         u.Email,
		Username:      u.Username,
		Phone:         u.Phone,
		EmailVerified: u.EmailVerified,
		Roles:         roles,
		CreatedAt:     u.CreatedAt.Time,
	}
}
