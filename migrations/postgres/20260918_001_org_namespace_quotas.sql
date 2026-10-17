-- The tenant namespace ResourceQuota an enterprise contract sets for an org.
--
-- A publish sends the provisioner the ceilings the control plane derives from
-- the org's plan (gateways, replicas and the largest compute type the plan
-- allows). A contract that buys more than a plan row — or an unlimited plan,
-- which yields no number — gets its ceilings here, set by a platform admin;
-- a row replaces the plan's derivation for that org. `quota_json` is the
-- control plane's `NamespaceQuota`.

CREATE TABLE org_namespace_quotas (
    org_id      UUID PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    quota_json  JSONB NOT NULL,
    updated_by  TEXT NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Org-keyed + FORCEd from creation, like license_retention_floors: the repo
-- is org-scoped, the ::UUID cast fails closed on an empty scope, and WITH
-- CHECK pins writes to the scoped org.
ALTER TABLE org_namespace_quotas ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_iso_namespace_quota ON org_namespace_quotas
    USING (org_id = current_setting('mcpg.org_id', true)::UUID)
    WITH CHECK (org_id = current_setting('mcpg.org_id', true)::UUID);
ALTER TABLE org_namespace_quotas FORCE ROW LEVEL SECURITY;
