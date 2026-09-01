-- name: CreateOAuthState :exec
INSERT INTO oauth_states (state, project_id, provider, redirect_uri, expires_at)
VALUES ($1, $2, $3, $4, $5);

-- name: TakeOAuthState :one
-- Single-use: the row is deleted as it's read.
DELETE FROM oauth_states WHERE state = $1 RETURNING *;

-- name: DeleteExpiredOAuthStates :exec
DELETE FROM oauth_states WHERE expires_at < now();

-- name: GetOAuthAccount :one
SELECT * FROM oauth_accounts WHERE provider = $1 AND provider_user_id = $2;

-- name: CreateOAuthAccount :one
INSERT INTO oauth_accounts (user_id, provider, provider_user_id, access_token_enc, refresh_token_enc)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: CreateAuthExchangeCode :exec
INSERT INTO auth_exchange_codes (code_hash, user_id, project_id, expires_at)
VALUES ($1, $2, $3, $4);

-- name: TakeAuthExchangeCode :one
-- Atomically consume: only an unexpired, unconsumed code for this project returns.
UPDATE auth_exchange_codes SET consumed_at = now()
WHERE code_hash = $1 AND project_id = $2 AND consumed_at IS NULL AND expires_at > now()
RETURNING *;

-- name: DeleteExpiredAuthExchangeCodes :exec
DELETE FROM auth_exchange_codes WHERE expires_at < now();
