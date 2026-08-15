-- No-op on Sqlite — Row-Level Security is a Postgres-only feature.
--
-- Tier-0 / self-host single-tenant runs on Sqlite, where tenant isolation is
-- enforced at the application layer (`AuthContext::require_org` + the explicit
-- `WHERE org_id = ?` filters). The matching Postgres migration
-- (20260624_001_rls_force_tenant_payload_keys.sql) FORCEs RLS on
-- `tenant_payload_keys`. This file keeps the sqlite/postgres migration sets in
-- lockstep.
SELECT 1;
