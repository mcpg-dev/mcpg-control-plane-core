-- Per-org federation license store.
--
-- Replaces the single in-process `AppState.federation_license` slot, which was
-- overwritten on EVERY federated login — so the last tenant to log in had its
-- plan/quotas/features applied process-wide to ALL orgs' entitlement checks
-- (quota gate, free-plan publish gate, retention pruning, feature flags). That
-- is a cross-tenant entitlement leak + non-deterministic enforcement. Keying the
-- license by org fixes it; persisting it (vs the in-memory slot) means a CP
-- restart no longer silently downgrades every paying tenant to the community
-- plan until they re-authenticate.
--
-- One row per org (the org's currently-installed federation license). The
-- community/Tier-0 license is NOT stored here — orgs with no row fall back to
-- the in-process default community claims.
--
-- `claims_json` is the parsed LicenseClaims (read path: entitlement checks);
-- `license_jwt` is the signed token (read path: handed to gateways in the
-- ConfigBundle). Both are derived from the same federation-issued JWT, already
-- verified at install time. `expires_at` mirrors claims.exp so the read path can
-- ignore an expired license (→ fall back to community) without re-decoding.

CREATE TABLE federation_licenses (
    org_id        UUID PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    license_jwt   TEXT NOT NULL,
    claims_json   JSONB NOT NULL,
    plan          TEXT NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    installed_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Org-keyed + FORCEd from creation (the repo is org-scoped from day one, so no
-- phased rollout is needed — unlike the init tables). Cast/WITH-CHECK posture
-- matches the rest of the RLS rollout (see docs/control-plane/POSTGRES.md): the
-- ::UUID cast fails closed loudly on a reverted-to-'' scope; the WITH CHECK pins
-- writes to the scoped org.
ALTER TABLE federation_licenses ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_iso_fed_lic ON federation_licenses
    USING (org_id = current_setting('mcpg.org_id', true)::UUID)
    WITH CHECK (org_id = current_setting('mcpg.org_id', true)::UUID);
ALTER TABLE federation_licenses FORCE ROW LEVEL SECURITY;
