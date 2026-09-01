-- Refresh-token reuse detection.
--
-- A `sessions` row is a token *family*: it always holds the current refresh
-- token hash. On every rotation the outgoing hash is copied here. If a hash
-- that already lives in this table is presented again, the token has been
-- replayed after rotation (classic stolen-refresh-token signal) and the whole
-- family is revoked.

CREATE TABLE refresh_token_history (
    token_hash TEXT PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    used_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_refresh_token_history_session ON refresh_token_history(session_id);
