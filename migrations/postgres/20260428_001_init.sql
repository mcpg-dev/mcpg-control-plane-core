-- Initial schema for PostgreSQL (Tier 1 self-host + Cloud + sovereign).
-- SQLite equivalent in `migrations/sqlite/`. Schemas are kept in sync.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "citext";

-- ─────────── Tenancy ───────────
CREATE TABLE orgs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug            TEXT NOT NULL UNIQUE,
    name            TEXT NOT NULL,
    plan_tier       TEXT NOT NULL DEFAULT 'community',
    license_jwt     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ
);

CREATE TABLE workspaces (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES orgs(id),
    slug            TEXT NOT NULL,
    name            TEXT NOT NULL,
    quota           JSONB NOT NULL DEFAULT '{}',
    sso_config      JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ,
    UNIQUE(org_id, slug)
);

CREATE TABLE environments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    UUID NOT NULL REFERENCES workspaces(id),
    slug            TEXT NOT NULL,
    name            TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ,
    UNIQUE(workspace_id, slug)
);

-- ─────────── Identity ───────────
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    federation_sub  TEXT UNIQUE,
    email           CITEXT NOT NULL UNIQUE,
    name            TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE org_memberships (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES orgs(id),
    user_id         UUID NOT NULL REFERENCES users(id),
    org_roles       TEXT[] NOT NULL DEFAULT '{}',
    workspace_roles JSONB NOT NULL DEFAULT '{}',
    UNIQUE(org_id, user_id)
);

CREATE TABLE sessions (
    sid               BYTEA PRIMARY KEY,
    user_id           UUID NOT NULL REFERENCES users(id),
    license_jwt       TEXT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at        TIMESTAMPTZ NOT NULL,
    last_activity_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at        TIMESTAMPTZ,
    user_agent        TEXT,
    ip_address        INET
);
CREATE INDEX sessions_expires_idx ON sessions (expires_at);
CREATE INDEX sessions_user_idx ON sessions (user_id);

CREATE TABLE bootstrap_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    nonce           BYTEA NOT NULL UNIQUE,
    org_id          UUID NOT NULL REFERENCES orgs(id),
    workspace_id    UUID NOT NULL REFERENCES workspaces(id),
    environment_id  UUID NOT NULL REFERENCES environments(id),
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    consumed_at     TIMESTAMPTZ,
    consumed_by_uid TEXT,
    issuer_user_id  UUID NOT NULL REFERENCES users(id),
    one_shot        BOOLEAN NOT NULL DEFAULT TRUE,
    max_uses        INTEGER,
    use_count       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX bootstrap_tokens_expires_idx ON bootstrap_tokens (expires_at);

-- ─────────── Inventory ───────────
CREATE TABLE instances (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES orgs(id),
    workspace_id    UUID NOT NULL REFERENCES workspaces(id),
    environment_id  UUID NOT NULL REFERENCES environments(id),
    instance_uid    TEXT NOT NULL,
    version         TEXT NOT NULL,
    labels          JSONB NOT NULL DEFAULT '{}',
    state           TEXT NOT NULL DEFAULT 'enrolling',
    last_seen_at    TIMESTAMPTZ,
    discovered_via  TEXT NOT NULL,
    addressable     JSONB NOT NULL DEFAULT '[]',
    cert_serial     BYTEA,
    cert_expires_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(workspace_id, instance_uid)
);
CREATE INDEX instances_workspace_state_idx ON instances (workspace_id, state);
CREATE INDEX instances_last_seen_idx ON instances (last_seen_at);

-- ─────────── Configuration ───────────
CREATE TABLE plugin_sets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES orgs(id),
    workspace_id    UUID NOT NULL REFERENCES workspaces(id),
    name            TEXT NOT NULL,
    spec            JSONB NOT NULL,
    content_hash    TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(workspace_id, name)
);

CREATE TABLE bindings (
    instance_id     UUID PRIMARY KEY REFERENCES instances(id) ON DELETE CASCADE,
    plugin_set_id   UUID NOT NULL REFERENCES plugin_sets(id),
    bound_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_acked_at   TIMESTAMPTZ,
    last_ack_hash   TEXT
);

-- ─────────── Audit ledger ───────────
CREATE TABLE audit_log (
    id              BIGSERIAL PRIMARY KEY,
    org_id          UUID NOT NULL,
    workspace_id    UUID,
    user_id         UUID,
    session_id      BYTEA,
    actor_kind      TEXT NOT NULL,
    actor_subject   TEXT NOT NULL,
    action          TEXT NOT NULL,
    target_kind     TEXT,
    target_id       UUID,
    target_slug     TEXT,
    payload         JSONB,
    request_id      UUID,
    source_ip       INET,
    user_agent      TEXT,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    prev_hash       BYTEA,
    entry_hash      BYTEA NOT NULL,
    signature       BYTEA
);
CREATE INDEX audit_log_org_time_idx ON audit_log (org_id, occurred_at DESC);
CREATE INDEX audit_log_actor_idx ON audit_log (org_id, actor_kind, actor_subject);
CREATE INDEX audit_log_target_idx ON audit_log (target_kind, target_id);

-- ─────────── RLS (Cloud only; enabled via runtime SET) ───────────
-- Policies created here but disabled by default. Cloud build
-- enables RLS at runtime; self-host single-tenant leaves it off.

ALTER TABLE workspaces       ENABLE ROW LEVEL SECURITY;
ALTER TABLE environments     ENABLE ROW LEVEL SECURITY;
ALTER TABLE instances        ENABLE ROW LEVEL SECURITY;
ALTER TABLE plugin_sets      ENABLE ROW LEVEL SECURITY;
ALTER TABLE bindings         ENABLE ROW LEVEL SECURITY;
ALTER TABLE bootstrap_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_memberships  ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log        ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_iso_workspaces       ON workspaces
    USING (org_id = current_setting('mcpg.org_id', true)::UUID);
CREATE POLICY tenant_iso_environments     ON environments
    USING (workspace_id IN (SELECT id FROM workspaces));
CREATE POLICY tenant_iso_instances        ON instances
    USING (org_id = current_setting('mcpg.org_id', true)::UUID);
CREATE POLICY tenant_iso_plugin_sets      ON plugin_sets
    USING (org_id = current_setting('mcpg.org_id', true)::UUID);
CREATE POLICY tenant_iso_bindings         ON bindings
    USING (instance_id IN (SELECT id FROM instances));
CREATE POLICY tenant_iso_bootstrap_tokens ON bootstrap_tokens
    USING (org_id = current_setting('mcpg.org_id', true)::UUID);
CREATE POLICY tenant_iso_org_memberships  ON org_memberships
    USING (org_id = current_setting('mcpg.org_id', true)::UUID);
CREATE POLICY tenant_iso_audit_log        ON audit_log
    USING (org_id = current_setting('mcpg.org_id', true)::UUID);
