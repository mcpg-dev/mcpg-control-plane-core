-- Initial schema for SQLite (Tier 0 + non-K8s self-host).
-- Postgres equivalent in `migrations/postgres/`. Schemas are
-- kept in sync; differences live in per-engine migration files.
--
-- Connection-level pragmas (foreign_keys, journal_mode=WAL) are
-- applied by `cp-server::db` via SqliteConnectOptions, not in
-- this migration — sqlx wraps each migration in a transaction
-- and PRAGMAs can't run there.

-- ─────────── Tenancy ───────────
CREATE TABLE orgs (
    id              TEXT PRIMARY KEY NOT NULL,
    slug            TEXT NOT NULL UNIQUE,
    name            TEXT NOT NULL,
    plan_tier       TEXT NOT NULL DEFAULT 'community',
    license_jwt     TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    deleted_at      TEXT
);

CREATE TABLE workspaces (
    id              TEXT PRIMARY KEY NOT NULL,
    org_id          TEXT NOT NULL REFERENCES orgs(id),
    slug            TEXT NOT NULL,
    name            TEXT NOT NULL,
    quota           TEXT NOT NULL DEFAULT '{}',
    sso_config      TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    deleted_at      TEXT,
    UNIQUE(org_id, slug)
);

CREATE TABLE environments (
    id              TEXT PRIMARY KEY NOT NULL,
    workspace_id    TEXT NOT NULL REFERENCES workspaces(id),
    slug            TEXT NOT NULL,
    name            TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    deleted_at      TEXT,
    UNIQUE(workspace_id, slug)
);

-- ─────────── Identity ───────────
CREATE TABLE users (
    id              TEXT PRIMARY KEY NOT NULL,
    federation_sub  TEXT UNIQUE,
    email           TEXT NOT NULL UNIQUE,
    name            TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE org_memberships (
    id              TEXT PRIMARY KEY NOT NULL,
    org_id          TEXT NOT NULL REFERENCES orgs(id),
    user_id         TEXT NOT NULL REFERENCES users(id),
    org_roles       TEXT NOT NULL DEFAULT '[]',
    workspace_roles TEXT NOT NULL DEFAULT '{}',
    UNIQUE(org_id, user_id)
);

CREATE TABLE sessions (
    sid               BLOB PRIMARY KEY NOT NULL,
    user_id           TEXT NOT NULL REFERENCES users(id),
    license_jwt       TEXT NOT NULL,
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at        TEXT NOT NULL,
    last_activity_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    revoked_at        TEXT,
    user_agent        TEXT,
    ip_address        TEXT
);
CREATE INDEX sessions_expires_idx ON sessions (expires_at);
CREATE INDEX sessions_user_idx ON sessions (user_id);

CREATE TABLE bootstrap_tokens (
    id              TEXT PRIMARY KEY NOT NULL,
    nonce           BLOB NOT NULL UNIQUE,
    org_id          TEXT NOT NULL REFERENCES orgs(id),
    workspace_id    TEXT NOT NULL REFERENCES workspaces(id),
    environment_id  TEXT NOT NULL REFERENCES environments(id),
    issued_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at      TEXT NOT NULL,
    consumed_at     TEXT,
    consumed_by_uid TEXT,
    issuer_user_id  TEXT NOT NULL REFERENCES users(id),
    one_shot        INTEGER NOT NULL DEFAULT 1,
    max_uses        INTEGER,
    use_count       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX bootstrap_tokens_expires_idx ON bootstrap_tokens (expires_at);

-- ─────────── Inventory ───────────
CREATE TABLE instances (
    id              TEXT PRIMARY KEY NOT NULL,
    org_id          TEXT NOT NULL REFERENCES orgs(id),
    workspace_id    TEXT NOT NULL REFERENCES workspaces(id),
    environment_id  TEXT NOT NULL REFERENCES environments(id),
    instance_uid    TEXT NOT NULL,
    version         TEXT NOT NULL,
    labels          TEXT NOT NULL DEFAULT '{}',
    state           TEXT NOT NULL DEFAULT 'enrolling',
    last_seen_at    TEXT,
    discovered_via  TEXT NOT NULL,
    addressable     TEXT NOT NULL DEFAULT '[]',
    cert_serial     BLOB,
    cert_expires_at TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE(workspace_id, instance_uid)
);
CREATE INDEX instances_workspace_state_idx ON instances (workspace_id, state);
CREATE INDEX instances_last_seen_idx ON instances (last_seen_at);

-- ─────────── Configuration ───────────
CREATE TABLE plugin_sets (
    id              TEXT PRIMARY KEY NOT NULL,
    org_id          TEXT NOT NULL REFERENCES orgs(id),
    workspace_id    TEXT NOT NULL REFERENCES workspaces(id),
    name            TEXT NOT NULL,
    spec            TEXT NOT NULL,
    content_hash    TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE(workspace_id, name)
);

CREATE TABLE bindings (
    instance_id     TEXT PRIMARY KEY NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    plugin_set_id   TEXT NOT NULL REFERENCES plugin_sets(id),
    bound_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_acked_at   TEXT,
    last_ack_hash   TEXT
);

-- ─────────── Audit ledger ───────────
CREATE TABLE audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id          TEXT NOT NULL,
    workspace_id    TEXT,
    user_id         TEXT,
    session_id      BLOB,
    actor_kind      TEXT NOT NULL,
    actor_subject   TEXT NOT NULL,
    action          TEXT NOT NULL,
    target_kind     TEXT,
    target_id       TEXT,
    target_slug     TEXT,
    payload         TEXT,
    request_id      TEXT,
    source_ip       TEXT,
    user_agent      TEXT,
    occurred_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    prev_hash       BLOB,
    entry_hash      BLOB NOT NULL,
    signature       BLOB
);
CREATE INDEX audit_log_org_time_idx ON audit_log (org_id, occurred_at DESC);
CREATE INDEX audit_log_actor_idx ON audit_log (org_id, actor_kind, actor_subject);
CREATE INDEX audit_log_target_idx ON audit_log (target_kind, target_id);
