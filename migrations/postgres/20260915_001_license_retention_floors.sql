-- The retention a destructive job (obs pruner, audit retention, idle reaper)
-- may shrink an org's data to.
--
-- A licence that expires, is revoked, or cannot be read says nothing about
-- the plan the customer pays for, and a lower plan can be undone within days
-- (a failed renewal that is retried, a downgrade that is reversed). Data
-- deleted on either account cannot be restored. So a job acts on the most
-- generous plan recorded here until a lower plan has been in force, on a
-- valid licence, for 30 days.
--
-- `claims_json` holds the licence claims whose windows are kept; `lowered_at`
-- is when a valid lower plan was first seen, and is cleared while the licence
-- is expired or revoked. Orgs that never held a paid plan have no row.

CREATE TABLE license_retention_floors (
    org_id       UUID PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    plan         TEXT NOT NULL,
    claims_json  JSONB NOT NULL,
    lowered_at   TIMESTAMPTZ,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Org-keyed + FORCEd from creation, like federation_licenses: the repo is
-- org-scoped, the ::UUID cast fails closed on an empty scope, and WITH CHECK
-- pins writes to the scoped org.
ALTER TABLE license_retention_floors ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_iso_retention_floor ON license_retention_floors
    USING (org_id = current_setting('mcpg.org_id', true)::UUID)
    WITH CHECK (org_id = current_setting('mcpg.org_id', true)::UUID);
ALTER TABLE license_retention_floors FORCE ROW LEVEL SECURITY;
