-- Custom-domain ownership verification.
--
-- Before this table, `custom_hostname` on a publish was accepted verbatim and
-- rendered straight into an HTTPRoute on the SHARED edge — any tenant could
-- claim `api.someone-elses.com` and the edge would route that host's traffic
-- (including ACME HTTP-01 challenges for it) to their gateway. Ownership must
-- be proven before a hostname is routable: the tenant creates a DNS TXT record
--   _mcpg-challenge.<hostname>  →  "mcpg-domain-verify=<token>"
-- and the CP resolves + matches it before flipping `status` to `verified`.
-- The publish path then requires a verified row for (org, hostname).
--
-- `hostname` is normalised (lowercase FQDN, no trailing dot) by
-- `CustomHostname::parse` before it ever reaches this table.
--
-- The PER-ORG key is (org_id, hostname); the GLOBAL unique index on hostname
-- is the cross-tenant arbiter — one org per hostname, platform-wide. A second
-- org claiming an already-claimed hostname gets a unique violation (mapped to
-- 409); transferring a domain between orgs requires the holder (or an
-- operator) to delete its row first. The unique index spans rows RLS hides,
-- so the arbiter works even though tenants can't see each other's claims.

CREATE TABLE custom_domains (
    org_id       UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    hostname     TEXT NOT NULL,
    -- Random challenge token; the expected TXT value is
    -- "mcpg-domain-verify=<token>". Regenerated only if the row is recreated.
    token        TEXT NOT NULL,
    -- pending | verified
    status       TEXT NOT NULL DEFAULT 'pending',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    verified_at  TIMESTAMPTZ,
    PRIMARY KEY (org_id, hostname)
);

CREATE UNIQUE INDEX custom_domains_hostname_uq ON custom_domains (hostname);

-- Org-keyed + FORCEd from creation (same posture as federation_licenses; see
-- docs/control-plane/POSTGRES.md): the ::UUID cast fails closed loudly on a
-- reverted-to-'' scope; the WITH CHECK pins writes to the scoped org.
ALTER TABLE custom_domains ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_iso_custom_domains ON custom_domains
    USING (org_id = current_setting('mcpg.org_id', true)::UUID)
    WITH CHECK (org_id = current_setting('mcpg.org_id', true)::UUID);
ALTER TABLE custom_domains FORCE ROW LEVEL SECURITY;
