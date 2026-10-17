-- What a plan-loss enforcement stopped, and whether the owners were told.
--
-- The enforcement notice names the gateways stopped and the tunnels closed.
-- They are kept with the loss so that a notice the billing federation could
-- not send is sent again on a later pass with the same content.
-- `enforced_summary` is {"stopped_gateways": [...], "closed_tunnels": n}.
-- A loss enforced before this column existed counts as told.
ALTER TABLE org_plan_grace ADD COLUMN enforced_summary JSONB;
ALTER TABLE org_plan_grace ADD COLUMN enforced_notified_at TIMESTAMPTZ;

-- FORCEd RLS hides every row from the owner role outside an org scope, so the
-- backfill lifts FORCE for its one statement and restores it.
ALTER TABLE org_plan_grace NO FORCE ROW LEVEL SECURITY;
UPDATE org_plan_grace SET enforced_notified_at = enforced_at WHERE enforced_at IS NOT NULL;
ALTER TABLE org_plan_grace FORCE ROW LEVEL SECURITY;
