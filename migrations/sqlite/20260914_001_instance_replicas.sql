-- Replicas a publish asked an instance to run. See the postgres mirror for
-- the rationale.
ALTER TABLE instances ADD COLUMN replicas INTEGER NOT NULL DEFAULT 1;
