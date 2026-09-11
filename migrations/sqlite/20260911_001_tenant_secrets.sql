-- Tenant secret channel: values a tenant registers for one of its gateways
-- by name, delivered into the gateway pod as environment through a
-- provisioner-rendered Secret, and referenced from the published config as
-- `${env.TENANT_…}`. Keys live in the reserved `TENANT_` namespace the
-- platform never uses; values are envelope-encrypted (AAD binds org +
-- gateway name) and are never returned by the API once written.
CREATE TABLE tenant_secrets (
    org_id         TEXT NOT NULL,
    workspace_slug TEXT NOT NULL,
    env_slug       TEXT NOT NULL,
    gateway_name   TEXT NOT NULL,
    key            TEXT NOT NULL,
    value_enc      BLOB NOT NULL,
    created_by     TEXT NOT NULL,
    created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (org_id, workspace_slug, env_slug, gateway_name, key)
);
