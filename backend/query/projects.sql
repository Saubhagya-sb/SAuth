-- name: GetProjectByAPIKey :one
-- Hottest lookup in the system: every end-user request resolves its project
-- from the X-API-Key header before anything else.
SELECT * FROM projects WHERE api_key = $1;

-- name: GetProjectByID :one
SELECT * FROM projects WHERE id = $1;
