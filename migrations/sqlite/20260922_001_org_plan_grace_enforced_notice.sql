-- What a plan-loss enforcement stopped, and whether the owners were told.
--
-- The enforcement notice names the gateways stopped and the tunnels closed.
-- They are kept with the loss so that a notice the billing federation could
-- not send is sent again on a later pass with the same content.
-- `enforced_summary` is JSON: {"stopped_gateways": [...], "closed_tunnels": n}.
-- A loss enforced before this column existed counts as told.
ALTER TABLE org_plan_grace ADD COLUMN enforced_summary TEXT;
ALTER TABLE org_plan_grace ADD COLUMN enforced_notified_at TEXT;
UPDATE org_plan_grace SET enforced_notified_at = enforced_at WHERE enforced_at IS NOT NULL;
