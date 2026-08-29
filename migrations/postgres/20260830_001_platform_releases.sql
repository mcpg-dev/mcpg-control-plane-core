-- The admin-blessed platform release: the gateway version every managed
-- instance is provisioned at, and the capability manifest publish validation
-- runs against. Platform-scoped: no org column and NO RLS by design — reads
-- happen on the BYPASSRLS pool, writes only through the platform-admin API.
-- Append-only; the newest row is current and history is the audit trail.
-- Capabilities is the raw `mcpg capabilities` JSON, stored as TEXT so both
-- backends share one shape.
CREATE TABLE platform_releases (
    id              BIGSERIAL PRIMARY KEY,
    gateway_version TEXT NOT NULL,
    image_digest    TEXT NOT NULL DEFAULT '',
    capabilities    TEXT NOT NULL,
    set_by          TEXT NOT NULL,
    set_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
