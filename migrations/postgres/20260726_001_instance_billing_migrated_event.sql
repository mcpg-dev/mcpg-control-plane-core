-- Admit `migrated` into the instance-hour ledger.
--
-- A move between cells closes one segment and opens the next at the same size
-- rather than emitting `stopped` + `started`, which would both gap the billable
-- interval and read as a restart on the invoice. The writer emits the event
-- already; the original CHECK admitted only three values, so every migration's
-- meter write failed — and because the ledger write is best-effort, the failure
-- surfaced as a log line rather than an error, leaving the pre-migration
-- interval open at the old size.

ALTER TABLE instance_billing_events
    DROP CONSTRAINT IF EXISTS instance_billing_events_event_check;

ALTER TABLE instance_billing_events
    ADD CONSTRAINT instance_billing_events_event_check
    CHECK (event IN ('started', 'resized', 'stopped', 'migrated'));
