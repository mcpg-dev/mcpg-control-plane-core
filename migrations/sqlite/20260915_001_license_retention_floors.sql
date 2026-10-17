-- The retention a destructive job (obs pruner, audit retention, idle reaper)
-- may shrink an org's data to.
--
-- A licence that expires, is revoked, or cannot be read says nothing about
-- the plan the customer pays for, and a lower plan can be undone within days
-- (a failed renewal that is retried, a downgrade that is reversed). Data
-- deleted on either account cannot be restored. So a job acts on the most
-- generous plan recorded here until a lower plan has been in force, on a
-- valid licence, for 30 days.
--
-- `claims_json` holds the licence claims whose windows are kept; `lowered_at`
-- is when a valid lower plan was first seen, and is cleared while the licence
-- is expired or revoked. Orgs that never held a paid plan have no row.

CREATE TABLE license_retention_floors (
    org_id       TEXT PRIMARY KEY NOT NULL,
    plan         TEXT NOT NULL,
    claims_json  TEXT NOT NULL,
    lowered_at   TEXT,
    updated_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
