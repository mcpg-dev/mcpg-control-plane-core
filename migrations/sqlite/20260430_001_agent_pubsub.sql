-- Cross-replica fan-out for agent ConfigUpdate pushes (M5 #3).
--
-- Each gateway agent has at most one active gRPC Channel stream
-- to one CP replica. When a plugin set update fires on a
-- different replica, the originating handler can't push directly
-- to the in-memory ConnectedAgents map of the owning replica.
-- These two tables let it route through the DB:
--
-- * `agent_replica_claims` — which replica currently owns the
--   stream for which instance. Updated on every Channel connect /
--   disconnect with a heartbeat timestamp.
-- * `agent_pending_pushes` — durable FIFO of ServerMessages that
--   need delivering. Producer writes one row per (instance, msg);
--   the target replica's poller picks up matching rows and
--   pushes them to its local stream, deleting on success.

CREATE TABLE agent_replica_claims (
    instance_id        TEXT PRIMARY KEY NOT NULL,
    replica_id         TEXT NOT NULL,
    last_heartbeat_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX agent_replica_claims_replica_idx
    ON agent_replica_claims (replica_id);

CREATE TABLE agent_pending_pushes (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id        TEXT NOT NULL,
    target_replica_id  TEXT NOT NULL,
    message_proto      BLOB NOT NULL,
    created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    attempts           INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX agent_pending_pushes_target_idx
    ON agent_pending_pushes (target_replica_id, created_at);
