-- ============================================================
-- One-time database bootstrap. Run as the postgres superuser:
--
--   psql -U postgres -f backend/scripts/bootstrap_db.sql
--
-- Creates the database, the least-privilege application role, and the
-- citext extension (all of which require superuser). After this, every
-- migration and the running service connect only as sauth_app.
-- ============================================================

-- CREATE DATABASE cannot run inside a transaction / DO block, so gate it
-- with \gexec instead.
SELECT 'CREATE DATABASE sauth'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'sauth')\gexec

\connect sauth

CREATE EXTENSION IF NOT EXISTS citext;

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sauth_app') THEN
        CREATE ROLE sauth_app LOGIN PASSWORD 'sauth_dev_pw';
    END IF;
END
$$;

GRANT ALL PRIVILEGES ON DATABASE sauth TO sauth_app;
GRANT ALL ON SCHEMA public TO sauth_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES    TO sauth_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO sauth_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON FUNCTIONS TO sauth_app;
