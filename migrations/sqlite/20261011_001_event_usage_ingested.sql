-- MCP Events ingest meter. See the postgres twin for the rationale.

ALTER TABLE event_usage
    ADD COLUMN ingested INTEGER NOT NULL DEFAULT 0 CHECK (ingested >= 0);
