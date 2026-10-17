-- MCP Events delivery ledger. See the postgres twin for the rationale.

CREATE TABLE event_usage (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id        TEXT NOT NULL,
    event_name    TEXT NOT NULL,
    mode          TEXT NOT NULL,
    delivered     INTEGER NOT NULL CHECK (delivered >= 0),
    abandoned     INTEGER NOT NULL CHECK (abandoned >= 0),
    bytes         INTEGER NOT NULL CHECK (bytes >= 0),
    window_start  TEXT NOT NULL,
    at            TEXT NOT NULL
);

CREATE INDEX idx_eu_org_at ON event_usage(org_id, at);
