-- `cluster_secrets` — instance-shared secrets for multi-replica
-- CP deployments.
--
-- Each row is a named blob the CP reads at boot. First-replica
-- writes via `INSERT OR IGNORE` so concurrent first-boot races
-- still converge on a single value (whichever winner committed
-- first). Subsequent replicas read the same row.
--
-- Stored secrets so far:
-- * `cookie_signing_key` — 64 bytes for the axum-extra signed
--   cookie jar. Replaces the per-instance HKDF derivation that
--   broke sessions across LB-rescheduled requests.
-- * (next commit) `ca_cert_pem` / `ca_key_pem` — shared CA so
--   every replica's gRPC server cert validates against the same
--   root.

CREATE TABLE cluster_secrets (
    key         TEXT PRIMARY KEY NOT NULL,
    value       BLOB NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
