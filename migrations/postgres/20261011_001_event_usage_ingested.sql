-- MCP Events ingest meter.
--
-- The delivery ledger also keeps what a gateway took into its event logs:
-- `ingested` counts the occurrences appended since the previous report, on
-- rows whose `mode` names the source kind. Delivery rows keep 0, so one SUM
-- per column gives each meter. The quota status compares the month's sum
-- with the plan's `events_ingested_per_month`.

ALTER TABLE event_usage
    ADD COLUMN ingested BIGINT NOT NULL DEFAULT 0 CHECK (ingested >= 0);
