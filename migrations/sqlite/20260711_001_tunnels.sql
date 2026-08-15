-- Reverse-tunnel registry (RFC 0026). See the postgres mirror for the full
-- rationale. Sqlite has no RLS; tenant isolation stays at the application
-- layer (org-scoped repo queries), matching instance_billing_events.

CREATE TABLE tunnels (
    org_id            TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name              TEXT NOT NULL,
    exposure          TEXT NOT NULL DEFAULT 'public' CHECK (exposure IN ('public', 'private')),
    mode              TEXT NOT NULL DEFAULT 'relay_terminated' CHECK (mode IN ('relay_terminated', 'e2ee')),
    hostname          TEXT,
    status            TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    instance_uid      TEXT,
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_connected_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (org_id, name)
);

CREATE UNIQUE INDEX tunnels_hostname_uq ON tunnels (hostname) WHERE hostname IS NOT NULL;
CREATE INDEX tunnels_org_active_idx ON tunnels (org_id) WHERE status = 'active';
