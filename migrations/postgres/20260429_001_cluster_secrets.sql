-- `cluster_secrets` — instance-shared secrets for multi-replica
-- CP deployments. See the sqlite mirror for full doc.

CREATE TABLE cluster_secrets (
    key         TEXT PRIMARY KEY,
    value       BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
