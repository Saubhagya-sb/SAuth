-- name: CreateUser :one
INSERT INTO users (project_id, email, username, phone, password_hash)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1 AND project_id = $2;

-- name: GetUserByIDOnly :one
-- id is globally unique; project_id comes back on the row.
SELECT * FROM users WHERE id = $1;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE project_id = $1 AND email = $2;

-- name: GetUserByLogin :one
-- Resolves the /auth/login "email_or_username" field within a project.
SELECT * FROM users
WHERE project_id = $1
  AND (email = sqlc.arg(identifier) OR username = sqlc.arg(identifier))
LIMIT 1;

-- name: SetUserEmailVerified :exec
UPDATE users SET email_verified = true WHERE id = $1;

-- name: SetUserPasswordHash :exec
UPDATE users SET password_hash = $2 WHERE id = $1;

-- name: SetUserBanned :exec
UPDATE users SET banned = $2 WHERE id = $1 AND project_id = $3;
