CREATE TABLE owner_bootstrap (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    token_sha256 TEXT NOT NULL CHECK (
        length(token_sha256) = 64 AND token_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT
) STRICT;

CREATE TABLE owner_sessions (
    session_sha256 TEXT PRIMARY KEY CHECK (
        length(session_sha256) = 64 AND session_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    csrf_sha256 TEXT NOT NULL CHECK (
        length(csrf_sha256) = 64 AND csrf_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT
) STRICT;

CREATE INDEX owner_sessions_expiry ON owner_sessions(expires_at, revoked_at);

CREATE TRIGGER owner_sessions_credentials_immutable
BEFORE UPDATE OF session_sha256, csrf_sha256, created_at, expires_at ON owner_sessions
BEGIN
    SELECT RAISE(ABORT, 'owner_session_credentials_are_immutable');
END;

CREATE TRIGGER owner_sessions_revocation_monotonic
BEFORE UPDATE OF revoked_at ON owner_sessions
WHEN OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL
BEGIN
    SELECT RAISE(ABORT, 'owner_session_revocation_is_monotonic');
END;
