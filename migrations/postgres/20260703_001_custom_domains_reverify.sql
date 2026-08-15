-- Periodic re-verification bookkeeping for custom domains.
--
-- Domain ownership can lapse (domain sold, DNS provider changed, TXT record
-- removed). The CP re-checks the `_mcpg-challenge.<hostname>` TXT record on an
-- interval; a VERIFIED domain whose record has been definitively missing for
-- longer than the grace window reverts to `pending` (which blocks NEW
-- publishes with that hostname — existing routes are not torn down; the
-- cert-manager renewal failing + DNS moving away starve them naturally).
--
-- `last_checked_at` is observability ("when did the loop last look");
-- `failing_since` is the durable first-definitive-miss stamp the grace window
-- is measured from (cleared on a successful check). Durable rather than
-- in-memory so a CP restart doesn't reset the clock.

ALTER TABLE custom_domains ADD COLUMN last_checked_at TIMESTAMPTZ;
ALTER TABLE custom_domains ADD COLUMN failing_since   TIMESTAMPTZ;
