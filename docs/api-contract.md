# SAuth — API Contract (v1)

Base URL: `https://api.yourauth.dev/v1`

## Conventions

- All requests/responses are JSON.
- Two credential types for calling the API:
  - **Project-scoped requests** (from an integrated third-party app, acting on behalf of an end user) → `X-API-Key` header (public key, safe client-side). Sensitive server-to-server calls also send `X-API-Secret` (private, server-only).
  - **Console requests** (managing the platform itself) → console admin session, `Authorization: Bearer <jwt>`, scoped to the admin's organizations.
- Error shape:
  ```json
  { "error": { "code": "invalid_credentials", "message": "Email or password is incorrect", "request_id": "req_9f8a..." } }
  ```
- List pagination: `?limit=20&cursor=<opaque>` → response includes `"next_cursor": "..." | null`.
- Timestamps: ISO 8601 UTC.

---

## 1. Console API — Bearer auth (admin session)

### Console auth
| Method | Path | Description |
|---|---|---|
| POST | `/console/auth/login` | Admin login (email + password) |
| POST | `/console/auth/logout` | Invalidate admin session |
| POST | `/console/auth/refresh` | Rotate admin refresh token |
| GET  | `/console/auth/me` | Current admin identity + org memberships |

### Organizations
| Method | Path | Description |
|---|---|---|
| POST | `/console/orgs` | Create organization |
| GET  | `/console/orgs` | List orgs the admin belongs to |
| GET  | `/console/orgs/{org_id}` | Org details |
| PATCH| `/console/orgs/{org_id}` | Update org name/settings |
| DELETE | `/console/orgs/{org_id}` | Delete org (cascades) |

### Projects
| Method | Path | Description |
|---|---|---|
| POST | `/console/orgs/{org_id}/projects` | Create project → returns `api_key` + `api_secret` (shown once) |
| GET  | `/console/orgs/{org_id}/projects` | List projects in org |
| GET  | `/console/projects/{project_id}` | Project details (config, allowed origins, OAuth settings) |
| PATCH| `/console/projects/{project_id}` | Update settings (enable OTP, Google OAuth client id/secret, redirect URLs) |
| POST | `/console/projects/{project_id}/rotate-secret` | Rotate `api_secret` |
| DELETE | `/console/projects/{project_id}` | Delete project |

### Users (console-managed view)
| Method | Path | Description |
|---|---|---|
| GET  | `/console/projects/{project_id}/users` | List/search (`?q=`, `?limit=`, `?cursor=`) |
| GET  | `/console/projects/{project_id}/users/{user_id}` | Details incl. roles, sessions, oauth accounts |
| PATCH| `/console/projects/{project_id}/users/{user_id}` | Ban/unban, force-verify, edit metadata |
| DELETE | `/console/projects/{project_id}/users/{user_id}` | Delete user |
| POST | `/console/projects/{project_id}/users/{user_id}/sessions/revoke-all` | Force logout everywhere |
| POST | `/console/projects/{project_id}/users/{user_id}/impersonate` | Issue debug session token (admin-only, logged) |

### Roles & Permissions (per project)
| Method | Path | Description |
|---|---|---|
| GET  | `/console/projects/{project_id}/permissions` | List permissions |
| POST | `/console/projects/{project_id}/permissions` | Create custom permission |
| GET  | `/console/projects/{project_id}/roles` | List roles |
| POST | `/console/projects/{project_id}/roles` | Create role |
| PATCH| `/console/projects/{project_id}/roles/{role_id}` | Rename / edit permission set |
| DELETE | `/console/projects/{project_id}/roles/{role_id}` | Delete role |
| POST | `/console/projects/{project_id}/users/{user_id}/roles` | Assign role (`{ "role_id": "..." }`) |
| DELETE | `/console/projects/{project_id}/users/{user_id}/roles/{role_id}` | Remove role |

### Analytics
| Method | Path | Description |
|---|---|---|
| GET | `/console/projects/{project_id}/analytics/signups?range=30d` | Signups over time |
| GET | `/console/projects/{project_id}/analytics/active-sessions` | Active session count |

---

## 2. End-User Auth API — `X-API-Key` auth

### Password auth
| Method | Path | Body | Description |
|---|---|---|---|
| POST | `/auth/signup` | `{ email, username?, password }` | Create user in this project |
| POST | `/auth/login` | `{ email_or_username, password }` | → `{ access_token, refresh_token, user }` |

### OTP auth
| Method | Path | Body | Description |
|---|---|---|---|
| POST | `/auth/otp/request` | `{ email_or_phone, purpose: "login"\|"signup" }` | Sends OTP → `{ otp_id, expires_at }` |
| POST | `/auth/otp/verify` | `{ otp_id, code }` | → `{ access_token, refresh_token, user }` |

### OAuth (Google, extensible)
| Method | Path | Description |
|---|---|---|
| GET | `/auth/oauth/google/start?redirect_uri=` | Redirect to Google consent (state signed & stored) |
| GET | `/auth/oauth/google/callback` | Code exchange, create/link user, redirect back with short-lived `auth_code` |
| POST | `/auth/oauth/exchange` | `{ auth_code }` → `{ access_token, refresh_token, user }` |

### Session management
| Method | Path | Body | Description |
|---|---|---|---|
| POST | `/auth/refresh` | `{ refresh_token }` | Rotate refresh token, return new pair |
| POST | `/auth/logout` | `{ refresh_token }` | Invalidate that session |
| GET  | `/auth/me` | *(Bearer access_token)* | Current user profile + roles/permissions |

### Password reset / email verification
| Method | Path | Body | Description |
|---|---|---|---|
| POST | `/auth/password/forgot` | `{ email }` | Send reset email/OTP |
| POST | `/auth/password/reset` | `{ token, new_password }` | Complete reset |
| POST | `/auth/verify-email` | `{ token }` | Mark email verified |

---

## 3. Token & response shapes

**Access token (JWT)** — short-lived (~15 min), `Authorization: Bearer <token>`:
```json
{
  "sub": "user_id",
  "project_id": "proj_id",
  "roles": ["admin"],
  "permissions": ["billing:read", "users:write"],
  "iat": 1234567890,
  "exp": 1234568790
}
```

**Refresh token** — opaque random string, long-lived (~30 days), stored hashed server-side, rotated on every use (old one invalidated → reuse detection for token theft).

**User object** (login / signup / me):
```json
{
  "id": "user_...",
  "email": "user@example.com",
  "username": "janedoe",
  "email_verified": true,
  "roles": ["member"],
  "created_at": "2026-08-30T12:00:00Z"
}
```

---

## 4. Flow sequences

**Password login** — `POST /auth/login` → validate bcrypt hash → issue JWT + refresh → client stores tokens.

**OTP login** — `POST /auth/otp/request` → generate code, hash + store (TTL 5 min), send via email/SMS → `POST /auth/otp/verify` → check hash + TTL → issue JWT + refresh.

**Google OAuth** — redirect to `/auth/oauth/google/start` → Google consent → `/auth/oauth/google/callback` exchanges code with Google, finds/creates user, generates short-lived `auth_code`, redirects to the app → `POST /auth/oauth/exchange` → real tokens.

**Refresh rotation** — `POST /auth/refresh` with `refresh_token` → validate hash, check not reused → issue new pair, invalidate old.
