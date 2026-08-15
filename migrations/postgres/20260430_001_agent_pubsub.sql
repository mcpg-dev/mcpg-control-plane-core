-- Cross-replica fan-out for agent ConfigUpdate pushes (M5 #3).
-- See sqlite mirror for full doc.

CREATE TABLE agent_replica_claims (
    instance_id        UUID PRIMARY KEY,
    replica_id         UUID NOT NULL,
    last_heartbeat_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX agent_replica_claims_replica_idx
    ON agent_replica_claims (replica_id);

CREATE TABLE agent_pending_pushes (
    id                 BIGSERIAL PRIMARY KEY,
    instance_id        UUID NOT NULL,
    target_replica_id  UUID NOT NULL,
    message_proto      BYTEA NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    attempts           INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX agent_pending_pushes_target_idx
    ON agent_pending_pushes (target_replica_id, created_at);
