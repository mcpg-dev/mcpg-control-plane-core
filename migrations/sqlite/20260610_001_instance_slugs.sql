-- Instance slug registry. The slug is the globally-unique DNS label that
-- addresses a deployed gateway at {slug}.mcpg.cloud/mcp (host-per-instance
-- routing), so uniqueness is GLOBAL, not per-tenant. A partial unique index
-- on live rows lets a slug be re-used after its prior holder fails/deletes.
CREATE TABLE instance_slugs (
    id             TEXT PRIMARY KEY NOT NULL,
    org_id         TEXT NOT NULL REFERENCES orgs(id),
    workspace_id   TEXT NOT NULL REFERENCES workspaces(id),
    environment_id TEXT NOT NULL REFERENCES environments(id),
    slug           TEXT NOT NULL,
    instance_uid   TEXT,
    status         TEXT NOT NULL DEFAULT 'provisioning', -- provisioning|active|failed
    namespace      TEXT,
    created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    deleted_at     TEXT
);
CREATE UNIQUE INDEX instance_slugs_live_slug_idx ON instance_slugs (slug) WHERE deleted_at IS NULL;
CREATE INDEX instance_slugs_uid_idx ON instance_slugs (instance_uid);
CREATE INDEX instance_slugs_org_idx ON instance_slugs (org_id);
