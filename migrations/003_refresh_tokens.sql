-- Refresh tokens live on the session. Only SHA-256 hashes are stored, never the token itself.
-- Each refresh rotates the token. The previous hash is kept to detect reuse of a rotated token
-- (a theft signal) and to tolerate two tabs refreshing at the same moment (short grace window).
ALTER TABLE sessions
    ADD COLUMN refresh_hash TEXT,
    ADD COLUMN prev_refresh_hash TEXT,
    ADD COLUMN refresh_rotated_at TIMESTAMPTZ,
    ADD COLUMN refresh_expires_at TIMESTAMPTZ;

CREATE INDEX idx_sessions_refresh_hash ON sessions(refresh_hash) WHERE refresh_hash IS NOT NULL;
CREATE INDEX idx_sessions_prev_refresh_hash ON sessions(prev_refresh_hash) WHERE prev_refresh_hash IS NOT NULL;
