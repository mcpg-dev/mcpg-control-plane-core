-- Org lifecycle status, for suspending a delinquent / non-paying tenant
-- WITHOUT deleting it. `active` (default) tenants behave as before;
-- `suspended` tenants are blocked from creating/modifying gateways
-- (publish) but remain fully readable (UI / audit / admin recovery).
-- Hard deletion stays separate (the `deleted_at` soft-delete column).
ALTER TABLE orgs
    ADD COLUMN status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended'));

-- Suspension is checked on the publish hot path; index the lookup.
CREATE INDEX IF NOT EXISTS orgs_status_idx ON orgs (status);
