-- An org that lost a paid plan, and what it keeps running until the grace
-- ends.
--
-- A plan drop (a downgrade, a cancellation, an unpaid renewal past its grace,
-- a revocation by the issuer, an operator's suspension) judges new work by the
-- plan left at once, but what the org already runs keeps the lost plan's terms
-- until `grace_until`. Then the plan-loss reconciler stops what the plan left
-- does not cover and sets `enforced_at`. An upgrade, a payment or a lifted
-- suspension during the grace deletes the row.
--
-- `held_claims` / `held_jwt` are the lost plan's licence: its claims judge
-- what keeps running, and the token is what the org's gateways are delivered
-- through the grace. `reason` is downgraded | plan_ended | unpaid | revoked |
-- suspended; `immediate` marks an operator's suspension with no grace.
-- `notified_at` is when the owners' notice was sent.

CREATE TABLE org_plan_grace (
    org_id       UUID PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    held_plan    TEXT NOT NULL,
    held_claims  JSONB NOT NULL,
    held_jwt     TEXT,
    reason       TEXT NOT NULL,
    lost_at      TIMESTAMPTZ NOT NULL,
    grace_until  TIMESTAMPTZ NOT NULL,
    immediate    BOOLEAN NOT NULL DEFAULT FALSE,
    notified_at  TIMESTAMPTZ,
    enforced_at  TIMESTAMPTZ,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Org-keyed + FORCEd from creation, like license_retention_floors: the repo
-- is org-scoped, the ::UUID cast fails closed on an empty scope, and WITH
-- CHECK pins writes to the scoped org. The reconciler's cross-org listing
-- runs on the BYPASSRLS background pool.
ALTER TABLE org_plan_grace ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_iso_plan_grace ON org_plan_grace
    USING (org_id = current_setting('mcpg.org_id', true)::UUID)
    WITH CHECK (org_id = current_setting('mcpg.org_id', true)::UUID);
ALTER TABLE org_plan_grace FORCE ROW LEVEL SECURITY;
