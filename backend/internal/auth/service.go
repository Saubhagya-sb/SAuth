// Package auth implements the end-user authentication flows for integrated
// projects: password signup/login, session issuance, refresh-token rotation
// with reuse detection, logout, and profile lookup.
package auth

import (
	"context"
	"errors"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/saubhagyabhadhouria/sauth/internal/db"
	"github.com/saubhagyabhadhouria/sauth/internal/password"
	"github.com/saubhagyabhadhouria/sauth/internal/token"
)

type Service struct {
	pool       *pgxpool.Pool
	q          *db.Queries
	tokens     *token.Issuer
	refreshTTL time.Duration
}

func NewService(pool *pgxpool.Pool, tokens *token.Issuer, refreshTTL time.Duration) *Service {
	return &Service{pool: pool, q: db.New(pool), tokens: tokens, refreshTTL: refreshTTL}
}

// ---------- Signup ----------

type SignupInput struct {
	ProjectID uuid.UUID
	Email     string
	Username  string // optional; "" means unset
	Password  string
}

func (s *Service) Signup(ctx context.Context, in SignupInput) (*Result, error) {
	email := strings.TrimSpace(strings.ToLower(in.Email))
	if _, err := mail.ParseAddress(email); err != nil {
		return nil, ErrInvalidEmail
	}
	hash, err := password.Hash(in.Password)
	if err != nil {
		return nil, err // ErrTooShort / ErrTooLong bubble up as validation errors
	}

	var username *string
	if u := strings.TrimSpace(in.Username); u != "" {
		username = &u
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	qtx := s.q.WithTx(tx)

	user, err := qtx.CreateUser(ctx, db.CreateUserParams{
		ProjectID:    in.ProjectID,
		Email:        &email,
		Username:     username,
		PasswordHash: &hash,
	})
	if err != nil {
		return nil, mapCreateUserErr(err)
	}

	// Attach the project's default role, if one is configured.
	if role, err := qtx.GetDefaultRole(ctx, in.ProjectID); err == nil {
		if err := qtx.AssignRoleToUser(ctx, db.AssignRoleToUserParams{
			UserID: user.ID, RoleID: role.ID, ProjectID: in.ProjectID,
		}); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
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

// ---------- Login ----------

func (s *Service) Login(ctx context.Context, projectID uuid.UUID, identifier, plainPassword string) (*Result, error) {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" || plainPassword == "" {
		return nil, ErrInvalidCredentials
	}
	lookup := strings.ToLower(identifier)

	user, err := s.q.GetUserByLogin(ctx, db.GetUserByLoginParams{
		ProjectID:  projectID,
		Identifier: &lookup,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		// Equalize timing so a missing user isn't distinguishable from a wrong password.
		password.VerifyDummy(plainPassword)
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}
	if user.PasswordHash == nil {
		password.VerifyDummy(plainPassword)
		return nil, ErrInvalidCredentials
	}
	if err := password.Verify(*user.PasswordHash, plainPassword); err != nil {
		if errors.Is(err, password.ErrMismatch) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}
	if user.Banned {
		return nil, ErrUserBanned
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	qtx := s.q.WithTx(tx)

	res, err := s.issue(ctx, qtx, user)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return res, nil
}

// ---------- Refresh (rotation + reuse detection) ----------

func (s *Service) Refresh(ctx context.Context, rawRefresh string) (*Result, error) {
	if strings.TrimSpace(rawRefresh) == "" {
		return nil, ErrRefreshInvalid
	}
	presented := token.HashRefreshToken(rawRefresh)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	qtx := s.q.WithTx(tx)

	sess, err := qtx.GetSessionByRefreshHash(ctx, presented)
	if errors.Is(err, pgx.ErrNoRows) {
		// Not a current token. If it's a rotated-away one, this is a replay:
		// revoke every session the owning user has and reject.
		if sid, e2 := qtx.FindSessionByUsedRefreshHash(ctx, presented); e2 == nil {
			if victim, e3 := qtx.GetSessionByID(ctx, sid); e3 == nil {
				_ = qtx.RevokeAllUserSessions(ctx, victim.UserID)
			}
			_ = tx.Commit(ctx)
			return nil, ErrRefreshReuse
		}
		return nil, ErrRefreshInvalid
	}
	if err != nil {
		return nil, err
	}
	if sess.RevokedAt.Valid || sess.ExpiresAt.Time.Before(time.Now()) {
		return nil, ErrRefreshInvalid
	}

	newRaw, newHash, err := token.NewRefreshToken()
	if err != nil {
		return nil, err
	}
	if err := qtx.RecordUsedRefreshHash(ctx, db.RecordUsedRefreshHashParams{
		TokenHash: presented, SessionID: sess.ID,
	}); err != nil {
		return nil, err
	}
	rotated, err := qtx.RotateSessionRefreshHash(ctx, db.RotateSessionRefreshHashParams{
		NewHash:   newHash,
		ExpiresAt: tsFrom(time.Now().Add(s.refreshTTL)),
		ID:        sess.ID,
	})
	if errors.Is(err, pgx.ErrNoRows) { // raced a revoke between SELECT and UPDATE
		return nil, ErrRefreshInvalid
	}
	if err != nil {
		return nil, err
	}

	user, err := qtx.GetUserByIDOnly(ctx, rotated.UserID)
	if err != nil {
		return nil, err
	}
	if user.Banned {
		return nil, ErrUserBanned
	}

	access, exp, roles, err := s.mintAccess(ctx, qtx, user)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &Result{
		AccessToken:  access,
		RefreshToken: newRaw,
		TokenType:    "Bearer",
		ExpiresIn:    int(time.Until(exp).Seconds()),
		User:         toUserDTO(user, roles),
	}, nil
}

// ---------- Logout ----------

func (s *Service) Logout(ctx context.Context, rawRefresh string) error {
	if strings.TrimSpace(rawRefresh) == "" {
		return nil
	}
	sess, err := s.q.GetSessionByRefreshHash(ctx, token.HashRefreshToken(rawRefresh))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // idempotent
	}
	if err != nil {
		return err
	}
	return s.q.RevokeSession(ctx, sess.ID)
}

// ---------- Me ----------

func (s *Service) Me(ctx context.Context, userID, projectID uuid.UUID) (*MeResult, error) {
	user, err := s.q.GetUserByID(ctx, db.GetUserByIDParams{ID: userID, ProjectID: projectID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	roles, err := s.q.GetUserRoleNames(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	perms, err := s.q.GetUserPermissionNames(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	return &MeResult{User: toUserDTO(user, roles), Permissions: perms}, nil
}

// ---------- helpers ----------

// issue creates a fresh session and returns a full token pair for user.
func (s *Service) issue(ctx context.Context, q *db.Queries, user db.User) (*Result, error) {
	access, exp, roles, err := s.mintAccess(ctx, q, user)
	if err != nil {
		return nil, err
	}
	rawRefresh, refreshHash, err := token.NewRefreshToken()
	if err != nil {
		return nil, err
	}
	if _, err := q.CreateSession(ctx, db.CreateSessionParams{
		UserID:           user.ID,
		RefreshTokenHash: refreshHash,
		ExpiresAt:        tsFrom(time.Now().Add(s.refreshTTL)),
	}); err != nil {
		return nil, err
	}
	return &Result{
		AccessToken:  access,
		RefreshToken: rawRefresh,
		TokenType:    "Bearer",
		ExpiresIn:    int(time.Until(exp).Seconds()),
		User:         toUserDTO(user, roles),
	}, nil
}

// mintAccess loads the user's roles/permissions and signs an access token.
func (s *Service) mintAccess(ctx context.Context, q *db.Queries, user db.User) (tokenStr string, exp time.Time, roles []string, err error) {
	roles, err = q.GetUserRoleNames(ctx, user.ID)
	if err != nil {
		return "", time.Time{}, nil, err
	}
	perms, err := q.GetUserPermissionNames(ctx, user.ID)
	if err != nil {
		return "", time.Time{}, nil, err
	}
	tokenStr, exp, err = s.tokens.IssueAccess(user.ID.String(), user.ProjectID.String(), roles, perms)
	if err != nil {
		return "", time.Time{}, nil, err
	}
	return tokenStr, exp, roles, nil
}

func tsFrom(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}

func mapCreateUserErr(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		switch pgErr.ConstraintName {
		case "uq_users_project_email":
			return ErrEmailTaken
		case "uq_users_project_username":
			return ErrUsernameTaken
		}
	}
	return err
}
