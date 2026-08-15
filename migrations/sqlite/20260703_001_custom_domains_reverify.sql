-- Periodic re-verification bookkeeping for custom domains (sqlite mirror of
-- the Postgres migration — see it for the full rationale). `failing_since` is
-- the durable first-definitive-miss stamp the grace window is measured from;
-- `last_checked_at` is observability.

ALTER TABLE custom_domains ADD COLUMN last_checked_at TEXT;
ALTER TABLE custom_domains ADD COLUMN failing_since   TEXT;
