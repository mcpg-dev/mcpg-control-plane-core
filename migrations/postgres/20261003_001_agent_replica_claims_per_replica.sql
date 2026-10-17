-- One claim per replica that holds a Channel of an instance.
--
-- The pods of a managed instance share its id and each holds a Channel of its
-- own, possibly on different CP replicas. Every replica among them holds a
-- claim, so a push reaches every process of the instance.

ALTER TABLE agent_replica_claims DROP CONSTRAINT agent_replica_claims_pkey;
ALTER TABLE agent_replica_claims ADD PRIMARY KEY (instance_id, replica_id);
