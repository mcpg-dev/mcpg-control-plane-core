-- Service tokens — non-interactive machine credentials (GA C9). sqlite mirror
-- of the Postgres migration. RLS is Postgres-only; sqlite / Tier-0 isolates at
-- the application layer (the repo + handler filter by org_id, and the auth-time
-- lookup is gated by the globally-unique `token_hash`).
--
-- Only the SHA-256 of the presented token is stored (`token_hash`, BLOB) — the
-- plaintext is shown once at creation and is otherwise unrecoverable.
-- `org_roles` is a JSON array string here (matching org_memberships on sqlite),
-- a TEXT[] on Postgres.

CREATE TABLE service_tokens (
    id                  TEXT PRIMARY KEY,
    org_id              TEXT NOT NULL,
    name                TEXT NOT NULL,
    token_hash          BLOB NOT NULL UNIQUE,
    org_roles           TEXT NOT NULL DEFAULT '[]',
    created_by_user_id  TEXT,
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at          TEXT,
    last_used_at        TEXT,
    revoked_at          TEXT
);

CREATE INDEX service_tokens_org_idx ON service_tokens (org_id);
