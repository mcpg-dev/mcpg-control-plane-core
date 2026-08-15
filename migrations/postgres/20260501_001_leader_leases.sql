-- Leader-lease table for periodic-task gating (M5 #5).
-- See sqlite mirror for full doc.

CREATE TABLE leader_leases (
    lease_name        TEXT PRIMARY KEY,
    holder_replica_id UUID NOT NULL,
    acquired_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at        TIMESTAMPTZ NOT NULL
);
