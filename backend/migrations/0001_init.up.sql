-- ============================================================
-- SAuth — migration 0001 (initial schema)
--
-- Apply as the application role (sauth_app) via golang-migrate.
-- Prereq: scripts/bootstrap_db.sql has already created the database,
-- the sauth_app role, and the `citext` extension (all superuser-only).
-- gen_random_uuid() is core in PostgreSQL 13+, so no pgcrypto needed.
--
-- Design goals: fast auth-path lookups (login, token verify), correct
-- multi-tenant isolation via project_id enforced at the DB layer,
-- token hashes only (never raw), clean cascading deletes.
-- ============================================================

-- ------------------------------------------------------------
-- Shared: keep updated_at honest without app discipline
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ------------------------------------------------------------
-- Console side: platform operators
-- ------------------------------------------------------------

CREATE TABLE organizations (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TRIGGER trg_organizations_updated BEFORE UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE console_admins (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email         CITEXT UNIQUE NOT NULL,          -- case-insensitive
    password_hash TEXT NOT NULL,
    disabled      BOOLEAN NOT NULL DEFAULT false,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TRIGGER trg_console_admins_updated BEFORE UPDATE ON console_admins
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE org_memberships (
    org_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    admin_id   UUID NOT NULL REFERENCES console_admins(id) ON DELETE CASCADE,
    role       TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('owner','admin','member')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, admin_id)
);
-- PK leads with org_id ("who is in this org?"). The reverse lookup
-- ("which orgs is this admin in?") powers GET /console/orgs:
CREATE INDEX idx_org_memberships_admin_id ON org_memberships(admin_id);

CREATE TABLE console_sessions (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_id           UUID NOT NULL REFERENCES console_admins(id) ON DELETE CASCADE,
    refresh_token_hash TEXT NOT NULL UNIQUE,       -- hot path: POST /console/auth/refresh
    device_info        TEXT,
    ip_address         INET,
    expires_at         TIMESTAMPTZ NOT NULL,
    revoked_at         TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_console_sessions_admin_id ON console_sessions(admin_id);

-- ------------------------------------------------------------
-- Projects: one per integrated third-party app
-- ------------------------------------------------------------

CREATE TABLE projects (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    environment     TEXT NOT NULL DEFAULT 'live' CHECK (environment IN ('live','test')),
    api_key         TEXT UNIQUE NOT NULL,          -- public: pk_live_... / pk_test_...
    api_secret_hash TEXT NOT NULL,                 -- hash of sk_...; raw returned once
    allowed_origins TEXT[] NOT NULL DEFAULT '{}',
    otp_enabled     BOOLEAN NOT NULL DEFAULT true,
    google_oauth_client_id         TEXT,
    google_oauth_client_secret_enc TEXT,           -- AES-GCM at rest (SAUTH_ENCRYPTION_KEY)
    google_oauth_redirect_uri      TEXT,
    access_token_ttl_seconds       INTEGER NOT NULL DEFAULT 900
        CHECK (access_token_ttl_seconds BETWEEN 60 AND 86400),
    refresh_token_ttl_seconds      INTEGER NOT NULL DEFAULT 2592000
        CHECK (refresh_token_ttl_seconds BETWEEN 3600 AND 31536000),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_projects_org_id ON projects(org_id);
-- api_key is the single hottest lookup in the system (every end-user API
-- call resolves the project by api_key first); the UNIQUE constraint
-- above already provides that index.
CREATE TRIGGER trg_projects_updated BEFORE UPDATE ON projects
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ------------------------------------------------------------
-- End users: identity is scoped PER PROJECT
-- ------------------------------------------------------------

CREATE TABLE users (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id     UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    email          CITEXT,
    username       CITEXT,
    phone          TEXT,                           -- store normalized E.164
    password_hash  TEXT,                           -- NULL for OAuth-only / OTP-only users
    email_verified BOOLEAN NOT NULL DEFAULT false,
    phone_verified BOOLEAN NOT NULL DEFAULT false,
    banned         BOOLEAN NOT NULL DEFAULT false,
    metadata       JSONB NOT NULL DEFAULT '{}',    -- integrator custom fields (cf. Clerk public_metadata)
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- identity unique per project, not globally. NULLs are distinct in
    -- Postgres, so users lacking a given identifier never collide.
    CONSTRAINT uq_users_project_email    UNIQUE (project_id, email),
    CONSTRAINT uq_users_project_username UNIQUE (project_id, username),
    CONSTRAINT uq_users_project_phone    UNIQUE (project_id, phone),

    -- target for the composite (id, project_id) FKs the RBAC join tables
    -- use to enforce tenant isolation in the database itself.
    CONSTRAINT uq_users_id_project       UNIQUE (id, project_id)
);
-- No standalone index on project_id: every UNIQUE above leads with
-- project_id, so the b-tree left prefix already serves "all users in a
-- project" scans and the ON DELETE CASCADE from projects.
CREATE TRIGGER trg_users_updated BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ------------------------------------------------------------
-- OAuth linked accounts
-- ------------------------------------------------------------

CREATE TABLE oauth_accounts (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider          TEXT NOT NULL,               -- 'google' (extensible); validated in app
    provider_user_id  TEXT NOT NULL,
    access_token_enc  TEXT,                        -- encrypted, only if calling provider APIs later
    refresh_token_enc TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_oauth_provider_account UNIQUE (provider, provider_user_id)
);
CREATE INDEX idx_oauth_accounts_user_id ON oauth_accounts(user_id);

-- ------------------------------------------------------------
-- OTP codes — 6-digit codes and link tokens share this table
-- (production: move to Redis for auto-TTL; keep here for audit trail)
-- ------------------------------------------------------------

CREATE TABLE otp_codes (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID REFERENCES users(id) ON DELETE CASCADE,   -- NULL for signup OTP (no user yet)
    project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    destination TEXT NOT NULL,                     -- email or phone the code was sent to
    code_hash   TEXT NOT NULL,                     -- hash only
    purpose     TEXT NOT NULL
        CHECK (purpose IN ('login','signup','verify_email','reset_password')),
    attempts    SMALLINT NOT NULL DEFAULT 0,       -- brute-force guard, enforced in app
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- /auth/otp/verify looks up by id (PK). This partial index backs
-- "invalidate earlier un-consumed codes for this destination+purpose"
-- on re-request, plus resend throttling.
CREATE INDEX idx_otp_codes_active ON otp_codes(project_id, destination, purpose)
    WHERE consumed_at IS NULL;
-- supports the periodic purge: DELETE FROM otp_codes WHERE expires_at < now()
CREATE INDEX idx_otp_codes_expires_at ON otp_codes(expires_at);

-- ------------------------------------------------------------
-- End-user sessions / refresh tokens
-- ------------------------------------------------------------

CREATE TABLE sessions (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_hash TEXT NOT NULL UNIQUE,       -- hot path: POST /auth/refresh
    device_info        TEXT,
    ip_address         INET,
    expires_at         TIMESTAMPTZ NOT NULL,
    revoked_at         TIMESTAMPTZ,                -- set on rotation, logout, or reuse-detection
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at) WHERE revoked_at IS NULL;

-- ------------------------------------------------------------
-- RBAC: roles & permissions, scoped per project
-- ------------------------------------------------------------

CREATE TABLE permissions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,                     -- e.g. 'billing:read'
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_permissions_project_name UNIQUE (project_id, name),
    CONSTRAINT uq_permissions_id_project   UNIQUE (id, project_id)   -- composite-FK target
);

CREATE TABLE roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,                     -- e.g. 'admin', 'member'
    description TEXT,
    is_default  BOOLEAN NOT NULL DEFAULT false,    -- auto-assigned to new users in the project
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_roles_project_name UNIQUE (project_id, name),
    CONSTRAINT uq_roles_id_project   UNIQUE (id, project_id)         -- composite-FK target
);
-- at most one default role per project
CREATE UNIQUE INDEX uq_roles_one_default ON roles(project_id) WHERE is_default;

CREATE TABLE role_permissions (
    role_id       UUID NOT NULL,
    permission_id UUID NOT NULL,
    project_id    UUID NOT NULL,                   -- carried so both sides must share a tenant
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id, project_id)       REFERENCES roles(id, project_id)       ON DELETE CASCADE,
    FOREIGN KEY (permission_id, project_id) REFERENCES permissions(id, project_id) ON DELETE CASCADE
);
CREATE INDEX idx_role_permissions_permission_id ON role_permissions(permission_id);

CREATE TABLE user_roles (
    user_id    UUID NOT NULL,
    role_id    UUID NOT NULL,
    project_id UUID NOT NULL,                      -- forces user and role into the same tenant
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id, project_id) REFERENCES users(id, project_id) ON DELETE CASCADE,
    FOREIGN KEY (role_id, project_id) REFERENCES roles(id, project_id) ON DELETE CASCADE
);
-- login builds the JWT roles/permissions claims from this table
CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_user_roles_role_id ON user_roles(role_id);

-- ------------------------------------------------------------
-- OAuth transient state + short-lived code exchange
-- (keeps tokens out of the URL bar; SQL now, Redis-swappable later)
-- ------------------------------------------------------------

CREATE TABLE oauth_states (
    state        TEXT PRIMARY KEY,                 -- random opaque; CSRF guard for the redirect
    project_id   UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    provider     TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,                    -- app URL to return the user to
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_oauth_states_expires_at ON oauth_states(expires_at);

CREATE TABLE auth_exchange_codes (
    code_hash   TEXT PRIMARY KEY,                  -- hash of the short-lived auth_code
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,              -- ~60s
    consumed_at TIMESTAMPTZ
);
CREATE INDEX idx_auth_exchange_codes_expires_at ON auth_exchange_codes(expires_at);

-- ------------------------------------------------------------
-- Audit log — console actions
-- ------------------------------------------------------------

CREATE TABLE audit_log (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id         UUID REFERENCES organizations(id)  ON DELETE SET NULL,
    project_id     UUID REFERENCES projects(id)       ON DELETE SET NULL,
    actor_admin_id UUID REFERENCES console_admins(id) ON DELETE SET NULL,
    action         TEXT NOT NULL,                  -- 'user.banned', 'project.created', 'role.assigned', ...
    target_type    TEXT,                           -- 'user' | 'project' | 'role' | ...
    target_id      UUID,
    metadata       JSONB NOT NULL DEFAULT '{}',
    ip_address     INET,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- entries deliberately survive deletion of what they reference
-- (ON DELETE SET NULL) — that is the point of an audit trail.
CREATE INDEX idx_audit_log_org_created  ON audit_log(org_id, created_at DESC);
CREATE INDEX idx_audit_log_proj_created ON audit_log(project_id, created_at DESC);
