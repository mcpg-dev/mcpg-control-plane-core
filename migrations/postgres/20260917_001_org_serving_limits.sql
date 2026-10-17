-- The serving ceiling the billing federation last computed for an org: its
-- included allowance, the prepaid pack credits still live, and the
-- pay-as-you-go calls its spend cap allows. The quota gate reads it on every
-- heartbeat, and keeps serving on the last one it has while the federation
-- cannot be reached. `limits_json` is the shared
-- `mcpg_control_plane_core::serving_limits::OrgServingLimits`.

CREATE TABLE org_serving_limits (
    org_id       UUID PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    period       TEXT NOT NULL,
    limits_json  JSONB NOT NULL,
    fetched_at   TIMESTAMPTZ NOT NULL
);

-- Org-keyed + FORCEd from creation, like federation_licenses: the repo is
-- org-scoped, the ::UUID cast fails closed on an empty scope, and WITH CHECK
-- pins writes to the scoped org.
ALTER TABLE org_serving_limits ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_iso_serving_limits ON org_serving_limits
    USING (org_id = current_setting('mcpg.org_id', true)::UUID)
    WITH CHECK (org_id = current_setting('mcpg.org_id', true)::UUID);
ALTER TABLE org_serving_limits FORCE ROW LEVEL SECURITY;
