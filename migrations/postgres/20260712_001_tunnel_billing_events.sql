-- Reverse-tunnel byte-usage ledger (RFC 0026 Phase C metering).
--
-- The relay flushes each tunnel's transferred-byte delta to the CP on its
-- periodic heartbeat; this append-only ledger accumulates them. The usage
-- endpoint SUMs a calendar month per org into a billable tunnel-byte total,
-- and the federation export reports the month-over-month delta to a Stripe
-- meter as the fair-use overage above the plan's included allowance.
--
-- Bytes are the relay's real marginal cost (egress bandwidth); the concurrent-
-- tunnel QUOTA stays the primary value metric, so most orgs never accrue a
-- billable overage here. The flush is at-most-once — the relay drops an
-- unconfirmed delta rather than risk double counting — so this ledger
-- UNDER-counts on a CP blip, the same safe direction the tool-call and
-- instance-hour exporters take.
--
-- `org_id` FK to ORGS (only ever soft-deleted/scrubbed), NOT to `tunnels`:
-- billing evidence must survive tunnel deregistration AND the GDPR erase,
-- exactly like `instance_billing_events` and the `tool_usage_rollups_*`
-- aggregates. No cascade — a tunnel row is freely deletable, the ledger is not.

CREATE TABLE tunnel_billing_events (
    id      BIGSERIAL PRIMARY KEY,
    org_id  UUID NOT NULL REFERENCES orgs(id),
    bytes   BIGINT NOT NULL CHECK (bytes >= 0),
    at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Period aggregation per org.
CREATE INDEX idx_tbe_org_at ON tunnel_billing_events(org_id, at);

-- RLS: per-tenant, ENABLE + FORCE (born in the post-rollout era). Same
-- fail-closed idiom as `instance_billing_events`: the `::UUID` cast plus a
-- matching WITH CHECK pin INSERT to the scoped org, not just row visibility.
ALTER TABLE tunnel_billing_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE tunnel_billing_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_iso_tbe ON tunnel_billing_events
    USING (org_id = current_setting('mcpg.org_id', true)::UUID)
    WITH CHECK (org_id = current_setting('mcpg.org_id', true)::UUID);
