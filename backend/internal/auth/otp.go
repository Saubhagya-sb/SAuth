package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/saubhagyabhadhouria/sauth/internal/db"
	"github.com/saubhagyabhadhouria/sauth/internal/notify"
	"github.com/saubhagyabhadhouria/sauth/internal/otp"
)

const (
	otpTTL          = 5 * time.Minute
	otpMaxAttempts  = 5
	otpResendWindow = 30 * time.Second
)

// ---------- Request ----------

type OTPRequestInput struct {
	ProjectID   uuid.UUID
	OTPEnabled  bool
	Destination string // raw email_or_phone from the request
	Purpose     string // "login" | "signup"
}

type OTPRequestResult struct {
	OTPID     string    `json:"otp_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *Service) RequestOTP(ctx context.Context, in OTPRequestInput) (*OTPRequestResult, error) {
	if in.Purpose != "login" && in.Purpose != "signup" {
		return nil, ErrOTPBadPurpose
	}
	if !in.OTPEnabled {
		return nil, ErrOTPDisabled
	}
	channel, dest, err := classifyDestination(in.Destination)
	if err != nil {
		return nil, err
	}

	// Resend throttle.
	last, err := s.q.GetLatestOTPCreatedAt(ctx, db.GetLatestOTPCreatedAtParams{
		ProjectID: in.ProjectID, Destination: dest, Purpose: in.Purpose,
	})
	switch {
	case err == nil:
		if time.Since(last.Time) < otpResendWindow {
			return nil, ErrOTPThrottled
		}
	case errors.Is(err, pgx.ErrNoRows):
		// first request for this destination — fine
	default:
		return nil, err
	}

	// Anti-enumeration: always mint a row and return an otp_id, but only
	// actually deliver a code when it could lead somewhere.
	_, userErr := s.lookupUserByDestination(ctx, s.q, in.ProjectID, channel, dest)
	deliver := true
	switch in.Purpose {
	case "login":
		deliver = userErr == nil // silent if there's no such account
	case "signup":
		deliver = errors.Is(userErr, pgx.ErrNoRows) // silent if it already exists
	}
	if userErr != nil && !errors.Is(userErr, pgx.ErrNoRows) {
		return nil, userErr
	}

	code, err := otp.Generate()
	if err != nil {
		return nil, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	qtx := s.q.WithTx(tx)

	if err := qtx.InvalidateActiveOTPs(ctx, db.InvalidateActiveOTPsParams{
		ProjectID: in.ProjectID, Destination: dest, Purpose: in.Purpose,
	}); err != nil {
		return nil, err
	}
	row, err := qtx.CreateOTP(ctx, db.CreateOTPParams{
		ProjectID:   in.ProjectID,
		Destination: dest,
		CodeHash:    s.otpHasher.Hash(code),
		Purpose:     in.Purpose,
		ExpiresAt:   tsFrom(time.Now().Add(otpTTL)),
	})
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	if deliver {
		if err := s.sender.SendOTP(ctx, channel, dest, code, in.Purpose); err != nil {
			slog.Error("otp delivery failed", "err", err, "channel", channel, "destination", dest)
		}
	}
	return &OTPRequestResult{OTPID: row.ID.String(), ExpiresAt: row.ExpiresAt.Time}, nil
}

// ---------- Verify ----------

func (s *Service) VerifyOTP(ctx context.Context, projectID uuid.UUID, otpID, code string) (*Result, error) {
	id, err := uuid.Parse(strings.TrimSpace(otpID))
	if err != nil {
		return nil, ErrOTPInvalid
	}
	code = strings.TrimSpace(code)

	rec, err := s.q.GetOTPByID(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrOTPInvalid
	}
	if err != nil {
		return nil, err
	}
	if rec.ProjectID != projectID || rec.ConsumedAt.Valid {
		return nil, ErrOTPInvalid
	}
	if rec.ExpiresAt.Time.Before(time.Now()) {
		return nil, ErrOTPExpired
	}
	if rec.Attempts >= otpMaxAttempts {
		_ = s.q.ConsumeOTP(ctx, id)
		return nil, ErrOTPTooManyAttempts
	}
	if !s.otpHasher.Equal(code, rec.CodeHash) {
		n, incErr := s.q.IncrementOTPAttempts(ctx, id)
		if incErr == nil && n >= otpMaxAttempts {
			_ = s.q.ConsumeOTP(ctx, id)
		}
		return nil, ErrOTPInvalid
	}

	channel, dest, err := classifyDestination(rec.Destination)
	if err != nil {
		return nil, ErrOTPInvalid
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	qtx := s.q.WithTx(tx)

	if err := qtx.ConsumeOTP(ctx, id); err != nil {
		return nil, err
	}

	var user db.User
	switch rec.Purpose {
	case "login":
		user, err = s.lookupUserByDestination(ctx, qtx, projectID, channel, dest)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrOTPInvalid
		}
		if err != nil {
			return nil, err
		}
		if user.Banned {
			return nil, ErrUserBanned
		}
		if err := markVerified(ctx, qtx, user, channel); err != nil {
			return nil, err
		}

	case "signup":
		if _, e := s.lookupUserByDestination(ctx, qtx, projectID, channel, dest); e == nil {
			return nil, ErrAccountExists
		} else if !errors.Is(e, pgx.ErrNoRows) {
			return nil, e
		}
		params := db.CreateUserParams{ProjectID: projectID}
		if channel == notify.ChannelEmail {
			params.Email = &dest
		} else {
			params.Phone = &dest
		}
		user, err = qtx.CreateUser(ctx, params)
		if err != nil {
			return nil, mapCreateUserErr(err)
		}
		if err := markVerified(ctx, qtx, user, channel); err != nil {
			return nil, err
		}
		if role, e := qtx.GetDefaultRole(ctx, projectID); e == nil {
			if e := qtx.AssignRoleToUser(ctx, db.AssignRoleToUserParams{
				UserID: user.ID, RoleID: role.ID, ProjectID: projectID,
			}); e != nil {
				return nil, e
			}
		} else if !errors.Is(e, pgx.ErrNoRows) {
			return nil, e
		}

	default:
		return nil, ErrOTPInvalid
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

func (s *Service) lookupUserByDestination(ctx context.Context, q *db.Queries, projectID uuid.UUID, channel notify.Channel, dest string) (db.User, error) {
	if channel == notify.ChannelEmail {
		return q.GetUserByEmail(ctx, db.GetUserByEmailParams{ProjectID: projectID, Email: &dest})
	}
	return q.GetUserByPhone(ctx, db.GetUserByPhoneParams{ProjectID: projectID, Phone: &dest})
}

func markVerified(ctx context.Context, q *db.Queries, user db.User, channel notify.Channel) error {
	if channel == notify.ChannelEmail {
		if user.EmailVerified {
			return nil
		}
		return q.SetUserEmailVerified(ctx, user.ID)
	}
	if user.PhoneVerified {
		return nil
	}
	return q.SetUserPhoneVerified(ctx, user.ID)
}

// classifyDestination normalizes and classifies an email_or_phone value. Emails
// are lower-cased; phones must be E.164 (leading +, 7-15 digits).
func classifyDestination(raw string) (notify.Channel, string, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", "", ErrInvalidDestination
	}
	if strings.Contains(v, "@") {
		v = strings.ToLower(v)
		if _, err := mail.ParseAddress(v); err != nil {
			return "", "", ErrInvalidDestination
		}
		return notify.ChannelEmail, v, nil
	}
	p := normalizePhone(v)
	if p == "" {
		return "", "", ErrInvalidDestination
	}
	return notify.ChannelSMS, p, nil
}

func normalizePhone(v string) string {
	var b strings.Builder
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '+' && b.Len() == 0:
			b.WriteRune(r)
		}
	}
	s := b.String()
	if !strings.HasPrefix(s, "+") {
		return ""
	}
	if digits := len(s) - 1; digits < 7 || digits > 15 {
		return ""
	}
	return s
}
