-- name: CreateSession :one
INSERT INTO sessions (user_id, refresh_token_hash, device_info, ip_address, expires_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetSessionByRefreshHash :one
-- Hot path for POST /auth/refresh.
SELECT * FROM sessions WHERE refresh_token_hash = $1;

-- name: GetSessionByID :one
SELECT * FROM sessions WHERE id = $1;

-- name: RotateSessionRefreshHash :one
-- Refresh-token rotation: swap in the new hash, bump usage, extend expiry.
UPDATE sessions
SET refresh_token_hash = sqlc.arg(new_hash),
    expires_at         = sqlc.arg(expires_at),
    last_used_at        = now()
WHERE id = sqlc.arg(id) AND revoked_at IS NULL
RETURNING *;

-- name: RevokeSession :exec
UPDATE sessions SET revoked_at = now() WHERE id = $1;

-- name: RevokeAllUserSessions :exec
UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL;

-- name: DeleteExpiredSessions :exec
DELETE FROM sessions WHERE expires_at < now();

-- name: RecordUsedRefreshHash :exec
-- Called on every rotation with the outgoing hash.
INSERT INTO refresh_token_history (token_hash, session_id)
VALUES ($1, $2)
ON CONFLICT (token_hash) DO NOTHING;

-- name: FindSessionByUsedRefreshHash :one
-- A hit here means a rotated-away token was replayed -> reuse detected.
SELECT session_id FROM refresh_token_history WHERE token_hash = $1;
