-- Org slug uniqueness must span LIVE rows only. The inline UNIQUE from init
-- covered soft-deleted rows too, so decommissioning an org left its slug
-- permanently occupied and re-signup with the same name failed forever.
-- Same shape as `instance_slugs_live_slug_idx`: a partial unique index keeps
-- the fail-closed arbiter for live tenants (two live orgs can never share a
-- slug) while a soft-deleted row no longer blocks a new live one. Reads
-- already exclude deleted rows (`WHERE deleted_at IS NULL`).
ALTER TABLE orgs DROP CONSTRAINT orgs_slug_key;
CREATE UNIQUE INDEX orgs_live_slug_idx ON orgs (slug) WHERE deleted_at IS NULL;
