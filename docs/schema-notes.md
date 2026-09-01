# Schema decisions — migration 0001

Rationale for the choices in `backend/migrations/0001_init.up.sql`, and the
changes made to the original hand-written draft. Useful as interview prep.

## Kept from the original draft (good calls)

- **Per-project scoping** of `users`, `roles`, `permissions`, `otp_codes` — the
  same email can exist independently in two integrated apps. This is what makes
  the platform multi-tenant like Clerk/Auth0.
- **Token hashes only** — `sessions.refresh_token_hash`, `otp_codes.code_hash`,
  `console_sessions.refresh_token_hash`, `auth_exchange_codes.code_hash`. A DB
  leak alone doesn't hand over live sessions.
- **CITEXT** for `email` / `username` — case-insensitive compare without
  `LOWER()` wrappers or function indexes.
- **Composite UNIQUE doubles as index** — `(project_id, email)` serves both the
  uniqueness rule and the login lookup; no separate index needed.
- **`ON DELETE CASCADE`** throughout — deleting an org or project cleans up all
  dependents, no orphan rows, no cleanup job.
- **`metadata JSONB`** on `users` — integrator custom fields without migrations.

## Changed / added

| Change | Why |
|---|---|
| **`uq_users_project_phone UNIQUE (project_id, phone)`** | Phone OTP login has to resolve to exactly one account. NULLs stay distinct, so email-only users are unaffected. Normalize to E.164 in Go before insert. |
| **Composite FKs on `user_roles` / `role_permissions`** — carry `project_id`, FK to `users(id, project_id)` and `roles(id, project_id)` (targets: `uq_*_id_project`) | Enforces tenant isolation *in the database*: a role from project A physically cannot be attached to a user from project B. |
| **`updated_at` trigger** (`set_updated_at()` + `BEFORE UPDATE` triggers) | The draft had `updated_at` columns that nothing updated. Trigger keeps them honest regardless of which query path writes. |
| **Dropped `uuid-ossp` / `pgcrypto` extensions** | `gen_random_uuid()` is core in PostgreSQL 13+. Only `citext` needs an extension, and it's created in `bootstrap_db.sql` as superuser, not in the app migration. |
| **`CHECK` constraints** on `org_memberships.role`, `otp_codes.purpose`, `projects.environment` | Enum-like TEXT columns — cheap guard against typo'd values. |
| **`console_sessions` table** | Console admins log in/refresh too (`/console/auth/*`) but aren't in `users`; they need their own session store. |
| **`console_admins.disabled`, `.updated_at`** | Lock an admin out; consistency with other tables. |
| **`projects.environment` + `access/refresh_token_ttl_seconds`** | Separate test/live keys like Clerk; per-project token lifetimes configurable from the console (contract's PATCH project settings). |
| **`otp_codes.purpose` includes `reset_password`; table also holds link tokens** | `/auth/password/reset` and `/auth/verify-email` take a `token` — same storage, longer random value in `code_hash`. |
| **`oauth_states` + `auth_exchange_codes` tables** | The contract's OAuth flow signs/stores `state` (CSRF) and issues a short-lived `auth_code` swapped at `/auth/oauth/exchange` to keep tokens out of the URL. Kept in SQL for v1; swap to Redis later. |
| **`audit_log` table** | A console that bans users / edits permissions needs a trail. `ON DELETE SET NULL` so entries outlive what they reference. |
| **`roles.is_default` + `uq_roles_one_default` partial unique index** | New signups get the project's default role; at most one per project. |
| **Index on `org_memberships(admin_id)`** | `GET /console/orgs` lists orgs for an admin; PK leads with `org_id` so the reverse direction needs its own index. |
| **`users.phone_verified`** | Phone OTP verifies the phone, mirror of `email_verified`. |
| **Replaced `otp_codes(id, expires_at)` partial index with `(project_id, destination, purpose) WHERE consumed_at IS NULL` + `(expires_at)`** | `/auth/otp/verify` looks up by `id` (PK, already indexed). The real query needs are "invalidate earlier codes on re-request" and the expiry purge job. |

## Deferred / future

- **UUIDv7** for index locality at high write volume — generate in Go
  (`google/uuid` v7) rather than an extension. Not needed at this scale.
- **Redis** for `otp_codes`, `oauth_states`, `auth_exchange_codes`, and
  rate-limit counters — auto-TTL, no purge job. SQL is fine for v1 and keeps
  the stack to one datastore.
- **Partitioning `audit_log` by month** once it's large.
