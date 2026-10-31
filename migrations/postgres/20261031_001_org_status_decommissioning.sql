-- `decommissioning`: an org the delete handler has handed to the
-- decommission reconciler, until the reconciler finalises it with the
-- `deleted_at` soft-delete. The status check allows it next to `active` and
-- `suspended`.
ALTER TABLE orgs DROP CONSTRAINT IF EXISTS orgs_status_check;
ALTER TABLE orgs ADD CONSTRAINT orgs_status_check
    CHECK (status IN ('active', 'suspended', 'decommissioning'));
