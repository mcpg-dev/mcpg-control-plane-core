-- Reverse-tunnel registry (RFC 0026).
--
-- The control plane is the authority for which reverse tunnels an org has
-- open. The relay calls the CP register/heartbeat/deregister API (§3.6); that
-- handler enforces the concurrent-tunnel quota + org suspension inside a
-- scoped transaction and writes here. Metering (tunnel-hours) integrates the
-- connect/disconnect transitions from the sibling `tunnel_billing_events`
-- ledger, so this table only needs the current registration, not history.
--
-- The PER-ORG key is (org_id, name): a tunnel name is unique within an org,
-- but two orgs may each run a private tunnel named "internal" — cross-org
-- isolation keeps them apart, exactly as the relay's `get_for_org` does.
-- `hostname` is the public URL host for `public` exposure and NULL for
-- `private`; the GLOBAL partial unique index on it is the cross-tenant arbiter
-- for `<slug>.tunnels.mcpg.cloud`, spanning rows RLS hides (same idiom as
-- custom_domains).
--
-- `org_id` FK to ORGS (only ever soft-deleted/scrubbed, never removed) with
-- ON DELETE CASCADE so a hard org purge clears its registrations.

CREATE TABLE tunnels (
    org_id            UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name              TEXT NOT NULL,
    -- public | private
    exposure          TEXT NOT NULL DEFAULT 'public' CHECK (exposure IN ('public', 'private')),
    -- relay_terminated | e2ee
    mode              TEXT NOT NULL DEFAULT 'relay_terminated' CHECK (mode IN ('relay_terminated', 'e2ee')),
    -- public URL host; NULL for private exposure
    hostname          TEXT,
    -- active | revoked
    status            TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    -- the dialing gateway instance uid (informational / audit)
    instance_uid      TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_connected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, name)
);

-- One org per public hostname, platform-wide. Partial: private tunnels have
-- no hostname, so they never contend. The index spans RLS-hidden rows so the
-- arbiter holds even though tenants can't see each other's tunnels.
CREATE UNIQUE INDEX tunnels_hostname_uq ON tunnels (hostname) WHERE hostname IS NOT NULL;

-- The concurrent-tunnel quota counts active rows per org.
CREATE INDEX tunnels_org_active_idx ON tunnels (org_id) WHERE status = 'active';

-- RLS: per-tenant, ENABLE + FORCE (born in the post-rollout era). The ::UUID
-- cast fails closed loudly on a reverted-to-'' scope; the WITH CHECK pins
-- INSERT/UPDATE to the scoped org, not just row visibility.
ALTER TABLE tunnels ENABLE ROW LEVEL SECURITY;
ALTER TABLE tunnels FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_iso_tunnels ON tunnels
    USING (org_id = current_setting('mcpg.org_id', true)::UUID)
    WITH CHECK (org_id = current_setting('mcpg.org_id', true)::UUID);
