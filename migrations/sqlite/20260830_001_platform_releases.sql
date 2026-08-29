-- The admin-blessed platform release. See the postgres mirror for the
-- rationale; sqlite stores the RFC3339 timestamp as TEXT.
CREATE TABLE platform_releases (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    gateway_version TEXT NOT NULL,
    image_digest    TEXT NOT NULL DEFAULT '',
    capabilities    TEXT NOT NULL,
    set_by          TEXT NOT NULL,
    set_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
