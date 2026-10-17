-- One claim per replica that holds a Channel of an instance.
--
-- The pods of a managed instance share its id and each holds a Channel of its
-- own, possibly on different CP replicas. Every replica among them holds a
-- claim, so a push reaches every process of the instance. SQLite cannot
-- change a primary key in place, so the table is rebuilt.

CREATE TABLE agent_replica_claims_new (
    instance_id        TEXT NOT NULL,
    replica_id         TEXT NOT NULL,
    last_heartbeat_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (instance_id, replica_id)
);

INSERT INTO agent_replica_claims_new (instance_id, replica_id, last_heartbeat_at)
    SELECT instance_id, replica_id, last_heartbeat_at FROM agent_replica_claims;

DROP TABLE agent_replica_claims;

ALTER TABLE agent_replica_claims_new RENAME TO agent_replica_claims;

CREATE INDEX agent_replica_claims_replica_idx
    ON agent_replica_claims (replica_id);
