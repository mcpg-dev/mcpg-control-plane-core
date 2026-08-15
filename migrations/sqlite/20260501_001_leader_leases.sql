-- Leader-lease table for periodic-task gating (M5 #5).
--
-- Periodic background tasks (state_janitor, cred_rotator, …)
-- run on every CP replica. Without coordination, three replicas
-- → three janitor passes → 3× DB load + occasional update races.
--
-- Each named task acquires a TTL lease here on every tick; only
-- the holder runs that tick's work. Lease length: 30s; tasks
-- renew on every successful pass. If the holder crashes, the
-- lease expires and another replica picks it up on its next
-- tick (max ~30s outage).

CREATE TABLE leader_leases (
    lease_name        TEXT PRIMARY KEY NOT NULL,
    holder_replica_id TEXT NOT NULL,
    acquired_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at        TEXT NOT NULL
);
