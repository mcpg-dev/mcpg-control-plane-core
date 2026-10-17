-- Replicas a publish asked an instance to run. A replica is a running
-- gateway, so the org's gateway ceiling sums them; recorded in the same
-- transaction as the ceiling check, so a publish still in flight already
-- counts. Instances outside the publish path (self-registration) run one.
-- Rows that predate the column count what their open billing interval
-- records, so no backfill is needed.
ALTER TABLE instances ADD COLUMN replicas INTEGER NOT NULL DEFAULT 1;
