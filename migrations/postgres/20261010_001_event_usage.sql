-- MCP Events delivery ledger.
--
-- A gateway reports, with each metrics report, the deliveries it made since
-- the last one, rolled up per event type and delivery mode. This append-only
-- ledger keeps the rows. The usage endpoint SUMs a calendar month per org into
-- `events_delivered`, and the quota status compares it with the plan's
-- `events_delivered_per_month`.
--
-- No principal, URL or host is ever stored: the gateway rolls them away.
-- `org_id` FK to ORGS, so the evidence survives the GDPR erase like the other
-- usage ledgers.

CREATE TABLE event_usage (
    id            BIGSERIAL PRIMARY KEY,
    org_id        UUID NOT NULL REFERENCES orgs(id),
    event_name    TEXT NOT NULL,
    mode          TEXT NOT NULL,
    delivered     BIGINT NOT NULL CHECK (delivered >= 0),
    abandoned     BIGINT NOT NULL CHECK (abandoned >= 0),
    bytes         BIGINT NOT NULL CHECK (bytes >= 0),
    window_start  TIMESTAMPTZ NOT NULL,
    at            TIMESTAMPTZ NOT NULL
);

-- Period aggregation per org.
CREATE INDEX idx_eu_org_at ON event_usage(org_id, at);

-- RLS: per-tenant, ENABLE + FORCE, with a WITH CHECK that pins INSERT to the
-- scoped org.
ALTER TABLE event_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE event_usage FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_iso_eu ON event_usage
    USING (org_id = current_setting('mcpg.org_id', true)::UUID)
    WITH CHECK (org_id = current_setting('mcpg.org_id', true)::UUID);
