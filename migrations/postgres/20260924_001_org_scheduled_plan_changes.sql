-- A plan change an org's owner scheduled in advance: a downgrade or a cancel
-- that takes effect when the paid period ends.
--
-- The licence refresh and the plan-loss reconciler each hold back a pass
-- that would bring down more paid orgs than their brake allows — the mark of
-- an issuer that answers wrongly, not of customers leaving. A change the
-- control plane saw scheduled before it took effect is customers leaving, so
-- it never counts toward either brake. `to_plan` is the plan it lands on
-- (`community` for a cancel), `effective_at` when it takes effect.

CREATE TABLE org_scheduled_plan_changes (
    org_id        UUID PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    to_plan       TEXT NOT NULL,
    effective_at  TIMESTAMPTZ NOT NULL,
    recorded_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Org-keyed + FORCEd from creation, like org_plan_grace: every read and write
-- names the org it is for.
ALTER TABLE org_scheduled_plan_changes ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_iso_scheduled_plan_change ON org_scheduled_plan_changes
    USING (org_id = current_setting('mcpg.org_id', true)::UUID)
    WITH CHECK (org_id = current_setting('mcpg.org_id', true)::UUID);
ALTER TABLE org_scheduled_plan_changes FORCE ROW LEVEL SECURITY;
