-- Reverse of 0001_init.up.sql. CASCADE mops up dependent objects
-- (indexes, triggers, FKs) so ordering only needs to be roughly
-- child-before-parent.

DROP TABLE IF EXISTS audit_log           CASCADE;
DROP TABLE IF EXISTS auth_exchange_codes CASCADE;
DROP TABLE IF EXISTS oauth_states        CASCADE;
DROP TABLE IF EXISTS user_roles          CASCADE;
DROP TABLE IF EXISTS role_permissions    CASCADE;
DROP TABLE IF EXISTS roles               CASCADE;
DROP TABLE IF EXISTS permissions         CASCADE;
DROP TABLE IF EXISTS sessions            CASCADE;
DROP TABLE IF EXISTS otp_codes           CASCADE;
DROP TABLE IF EXISTS oauth_accounts      CASCADE;
DROP TABLE IF EXISTS users               CASCADE;
DROP TABLE IF EXISTS projects            CASCADE;
DROP TABLE IF EXISTS console_sessions    CASCADE;
DROP TABLE IF EXISTS org_memberships     CASCADE;
DROP TABLE IF EXISTS console_admins      CASCADE;
DROP TABLE IF EXISTS organizations       CASCADE;

DROP FUNCTION IF EXISTS set_updated_at() CASCADE;
