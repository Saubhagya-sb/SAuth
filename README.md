# SAuth

A self-hosted authentication platform — the parts you'd otherwise rent from
Clerk / Auth0, built to understand and own:

- **End-user auth** for integrated apps: username/password, email & phone OTP,
  Google OAuth, JWT access tokens + rotating refresh tokens.
- **Per-project multi-tenancy**: each integrated app is a "project" with its own
  API key pair and isolated users/roles/permissions.
- **RBAC** scoped per project, surfaced as claims in the access token.
- **Console**: a dark-themed Next.js dashboard to manage orgs, projects, users,
  roles, and view analytics + an audit log.
- **SDK**: a lightweight `@sauth/nextjs` package other apps drop in.

## Stack

| Part | Choice |
|---|---|
| Backend | Go — `chi` router, `sqlc` (type-safe queries), `pgx/v5` |
| Database | PostgreSQL 17, migrations via `golang-migrate` |
| Console | Next.js (App Router) + Tailwind + shadcn/ui |
| SDK | TypeScript npm package + demo app in `examples/` |

## Layout

```
backend/           Go auth service
  cmd/server/      entrypoint
  migrations/      golang-migrate SQL (0001_init.{up,down}.sql)
  query/           sqlc source queries
  internal/db/     sqlc-generated code (do not edit)
  internal/        config, http, auth, token, ...
  scripts/         bootstrap_db.sql
console/           Next.js admin dashboard
sdk/               @sauth/nextjs package
examples/demo-app/ sample integrator
docs/              api-contract.md, schema-notes.md
```

## Local setup (Windows)

**Prereqs:** PostgreSQL 17 (installed, service `postgresql-x64-17` running),
64-bit Go 1.26+, Node 20+.

```powershell
# one-off CLI tools
winget install ezwinports.make            # optional, for the Makefile
go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
# golang-migrate CLI:
curl.exe -L https://github.com/golang-migrate/migrate/releases/download/v4.18.1/migrate.windows-amd64.zip -o migrate.zip
Expand-Archive migrate.zip .; # then move migrate.exe onto PATH

# 1. bootstrap the database (prompts for the postgres superuser password)
psql -U postgres -f backend/scripts/bootstrap_db.sql

# 2. configure
cd backend; cp .env.example .env    # then edit .env

# 3. run migrations
migrate -path migrations -database "postgres://sauth_app:sauth_dev_pw@localhost:5432/sauth?sslmode=disable" up

# 4. generate query code + run
sqlc generate
go run ./cmd/server
```

With `make` installed the equivalent is `make bootstrap && make migrate-up && make sqlc && make run`.

## Build order

1. Go backend: username/password signup + login + JWT sessions ✅ schema
2. RBAC (roles/permissions) scoped per project
3. Multi-project support (API keys, project-scoped users)
4. OTP flow (email, then phone)
5. Google OAuth
6. Next.js console on the stable API
7. SDK + demo integrator app

See `docs/api-contract.md` for endpoints and `docs/schema-notes.md` for the
data-model rationale.
