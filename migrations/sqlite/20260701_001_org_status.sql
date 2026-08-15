-- Org lifecycle status (sqlite mirror of the postgres migration). See the
-- postgres copy for rationale. `active` (default) | `suspended`. Hard deletion
-- stays separate (the `deleted_at` soft-delete column). The allowed-value
-- check is enforced in the repo (OrgsRepo::set_status) rather than a column
-- CHECK to keep the ADD COLUMN portable.
ALTER TABLE orgs ADD COLUMN status TEXT NOT NULL DEFAULT 'active';
