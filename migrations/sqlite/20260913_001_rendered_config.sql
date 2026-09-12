-- The config a managed instance actually runs, beside the RAW form the tenant
-- published: the provisioner hands it back on READY / MIGRATED — the published
-- config with every platform-injected block (`gateway.control_plane`,
-- `cloud.provenance`, the browser hand-off, `cluster:`, `gateway.secrets`) in
-- the YAML form the pod mounts. The agent channel ships these bytes, hashed
-- as `rendered_sha256`, so a hot-reload keeps the blocks the pod booted with;
-- `raw_config` stays what versions / diff / rollback show. NULL until the
-- publish reaches READY, and on rows recorded before the column existed.
ALTER TABLE config_artifacts ADD COLUMN rendered_config TEXT;
ALTER TABLE config_artifacts ADD COLUMN rendered_sha256 TEXT;
