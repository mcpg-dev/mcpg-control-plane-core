-- Versioned store of the RAW config a tenant published, per instance. Stored
-- verbatim (not a re-serialized AppConfig) so Phase-3 diff/rollback preserves
-- comments + key ordering. One row per publish; version is monotonic per
-- instance. This is the audit + rollback baseline for the publish loop.
CREATE TABLE config_artifacts (
    id              UUID PRIMARY KEY,
    org_id          UUID NOT NULL,
    instance_uid    TEXT NOT NULL,
    version         INTEGER NOT NULL,
    raw_config      TEXT NOT NULL,
    content_sha256  TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (instance_uid, version)
);
CREATE INDEX config_artifacts_instance ON config_artifacts (instance_uid, version);
