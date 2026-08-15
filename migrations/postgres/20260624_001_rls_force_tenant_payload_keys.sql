-- Postgres RLS enforcement — observability vertical (4/4):
-- `tenant_payload_keys`.
--
-- ENABLE'd (USING-only, org-keyed) in 20260509_001_payload_source_encryption.sql
-- but never FORCEd and never scoped — the same fail-open gap as the other
-- observability tables. It stores per-org wrapped Data Encryption Keys (E.4
-- source-side payload encryption), so it is a tenant-isolation boundary just
-- like the rest.
--
-- The repo (apps/control-plane/server/src/repo/tenant_payload_keys.rs) now
-- self-scopes all three methods (each already carries `org_id`):
--   * `upsert` (DEK issuance on Register / rotation) — write, scoped + WITH CHECK;
--   * `get_latest` / `get_by_version` (DEK fetch for issue + decrypt) — read,
--     scoped (read-only tx, dropped).
--
-- Policy change vs 20260509: standardize the cast to `::UUID` and add a matching
-- WITH CHECK. Cast/fail-closed rationale identical to 20260621.

ALTER POLICY tenant_iso_payload_keys ON tenant_payload_keys
    USING (org_id = current_setting('mcpg.org_id', true)::UUID)
    WITH CHECK (org_id = current_setting('mcpg.org_id', true)::UUID);

ALTER TABLE tenant_payload_keys FORCE ROW LEVEL SECURITY;
