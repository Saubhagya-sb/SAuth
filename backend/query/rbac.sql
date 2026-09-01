-- name: GetUserRoleNames :many
SELECT r.name
FROM user_roles ur
JOIN roles r ON r.id = ur.role_id
WHERE ur.user_id = $1
ORDER BY r.name;

-- name: GetUserPermissionNames :many
-- Flattened permission list for the access-token "permissions" claim.
SELECT DISTINCT p.name
FROM user_roles ur
JOIN role_permissions rp ON rp.role_id = ur.role_id
JOIN permissions p ON p.id = rp.permission_id
WHERE ur.user_id = $1
ORDER BY p.name;

-- name: GetDefaultRole :one
SELECT * FROM roles WHERE project_id = $1 AND is_default = true;

-- name: AssignRoleToUser :exec
-- project_id is carried explicitly so the composite FKs enforce that the user
-- and role belong to the same project.
INSERT INTO user_roles (user_id, role_id, project_id)
VALUES ($1, $2, $3)
ON CONFLICT (user_id, role_id) DO NOTHING;

-- name: RemoveRoleFromUser :exec
DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2;
