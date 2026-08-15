-- Last time an instance actually served traffic, and when it was warned about
-- going idle.
--
-- `last_seen_at` is a heartbeat: an instance nobody uses still reports it, so
-- it cannot distinguish "in use" from "running and abandoned". The free tier's
-- included instance is reclaimed after a period of no use, which needs a mark
-- that only real work moves.
--
-- Raw `tool_invocations` carry `instance_id` but are pruned after ~48h, far
-- short of the idle window — so activity is stamped here at ingest instead of
-- derived by query.
ALTER TABLE instances ADD COLUMN last_activity_at TEXT;
-- Set when the idle warning is issued; cleared by any subsequent activity, so
-- a tenant who comes back gets the full window again.
ALTER TABLE instances ADD COLUMN idle_warned_at TEXT;

CREATE INDEX instances_last_activity_idx ON instances (last_activity_at);
