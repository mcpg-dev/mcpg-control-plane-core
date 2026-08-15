-- Per-instance-hour metering ledger.
--
-- One row per billing-relevant lifecycle transition of a managed gateway
-- instance: `started` (publish reached READY), `resized` (a re-publish reached
-- READY with a different size/replicas), `stopped` (teardown confirmed). The
-- usage endpoint integrates consecutive events into per-size instance-hours
-- for a calendar month; the federation export pushes them to Stripe.
--
-- `org_id` references ORGS, deliberately NOT instances: billing history is
-- evidence and must survive instance deletion AND the GDPR erase — exactly
-- like the opaque `tool_usage_rollups_*` aggregates, which the erase handler
-- also keeps. `instance_id` therefore carries no FK (the instance row is
-- freely deletable), and `workspace_id` carries none either (erase deletes
-- workspaces). The org row itself is only ever soft-deleted/scrubbed, never
-- removed, so the FK holds.

CREATE TABLE instance_billing_events (
    id           BIGSERIAL PRIMARY KEY,
    org_id       UUID NOT NULL REFERENCES orgs(id),
    workspace_id UUID NOT NULL,
    instance_id  UUID NOT NULL,
    event        TEXT NOT NULL CHECK (event IN ('started', 'resized', 'stopped')),
    size         TEXT NOT NULL DEFAULT 's',
    replicas     INTEGER NOT NULL DEFAULT 1,
    at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Period aggregation per org; open-interval lookups per instance.
CREATE INDEX idx_ibe_org_at ON instance_billing_events(org_id, at);
CREATE INDEX idx_ibe_instance_at ON instance_billing_events(instance_id, at);

-- RLS: per-tenant, ENABLE + FORCE in one shot (born in the post-rollout era).
-- Same fail-closed idiom as `instance_logs`: the `::UUID` cast plus a matching
-- WITH CHECK pin INSERT/UPDATE to the scoped org, not just row visibility.
ALTER TABLE instance_billing_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE instance_billing_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_iso_ibe ON instance_billing_events
    USING (org_id = current_setting('mcpg.org_id', true)::UUID)
    WITH CHECK (org_id = current_setting('mcpg.org_id', true)::UUID);
