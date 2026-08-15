-- Org slug uniqueness must span LIVE rows only (postgres mirror has the
-- rationale). SQLite cannot drop an inline column UNIQUE (its auto-index is
-- undroppable), so this is the standard table rebuild: copy into a UNIQUE-less
-- clone, swap, and add the partial unique index on live rows.
--
-- The swap DROPs a table that child tables reference, which is legal here
-- because the migration runner applies sqlite migrations on a dedicated
-- connection with foreign-key ENFORCEMENT off (see cp-server `db.rs
-- run_migrations`); the child tables' `REFERENCES orgs(id)` clauses resolve
-- against the renamed replacement afterwards. The runtime pool keeps
-- foreign_keys=ON. The migrator wraps this file + its bookkeeping row in one
-- transaction, so a crash mid-swap rolls the whole rebuild back.
CREATE TABLE orgs_new (
    id              TEXT PRIMARY KEY NOT NULL,
    slug            TEXT NOT NULL,
    name            TEXT NOT NULL,
    plan_tier       TEXT NOT NULL DEFAULT 'community',
    license_jwt     TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    deleted_at      TEXT,
    status          TEXT NOT NULL DEFAULT 'active'
);
INSERT INTO orgs_new (id, slug, name, plan_tier, license_jwt, created_at, deleted_at, status)
    SELECT id, slug, name, plan_tier, license_jwt, created_at, deleted_at, status FROM orgs;
DROP TABLE orgs;
ALTER TABLE orgs_new RENAME TO orgs;
CREATE UNIQUE INDEX orgs_live_slug_idx ON orgs (slug) WHERE deleted_at IS NULL;
