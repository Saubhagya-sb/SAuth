-- name: CreateOTP :one
-- user_id is left NULL at creation; the account is resolved (login) or created
-- (signup) at verify time from `destination`.
INSERT INTO otp_codes (project_id, destination, code_hash, purpose, expires_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetOTPByID :one
SELECT * FROM otp_codes WHERE id = $1;

-- name: InvalidateActiveOTPs :exec
-- Burn any earlier un-consumed codes for this destination+purpose before a new
-- one is issued, so only the most recent code can ever verify.
UPDATE otp_codes SET consumed_at = now()
WHERE project_id = $1 AND destination = $2 AND purpose = $3 AND consumed_at IS NULL;

-- name: GetLatestOTPCreatedAt :one
-- Resend throttle.
SELECT created_at FROM otp_codes
WHERE project_id = $1 AND destination = $2 AND purpose = $3
ORDER BY created_at DESC
LIMIT 1;

-- name: IncrementOTPAttempts :one
UPDATE otp_codes SET attempts = attempts + 1 WHERE id = $1 RETURNING attempts;

-- name: ConsumeOTP :exec
UPDATE otp_codes SET consumed_at = now() WHERE id = $1;

-- name: DeleteExpiredOTPs :exec
DELETE FROM otp_codes WHERE expires_at < now();
