-- Postgres RLS enforcement — observability vertical (3/3):
-- `tool_invocation_payloads`.
--
-- ENABLE'd (USING-only, transitive via the parent `tool_invocations` row) in
-- 20260504_001_tool_invocation_payloads.sql but never FORCEd and never scoped.
-- Tenancy is enforced through the parent: a payload row is visible iff its
-- parent invocation is visible under the current scope.
--
-- The repo (apps/control-plane/server/src/repo/tool_invocation_payloads.rs)
-- now scopes:
--   * `upsert_self_scoped` (MetricsReport payload-capture hot path) — scopes to
--     the org of the just-inserted invocations. The parent rows are already
--     committed under the same org, so the transitive EXISTS resolves; the
--     WITH CHECK then guarantees a payload can only be written for an
--     invocation in the caller's scope.
--   * `get_self_scoped` (Enterprise payload-read handler) — scopes to the
--     caller's org; a cross-org invocation_id resolves to no parent → no row
--     (404), which the app-layer `belongs_to_org` guard already returns too.
--
-- Policy change vs 20260504: standardize the cast to `::UUID` and add a
-- matching WITH CHECK (same transitive EXISTS). The EXISTS subquery itself
-- reads the FORCEd `tool_invocations` under the same scope, so it sees only the
-- caller's parent rows.

ALTER POLICY tenant_iso_tip ON tool_invocation_payloads
    USING (
        EXISTS (
            SELECT 1 FROM tool_invocations ti
            WHERE ti.id = tool_invocation_payloads.invocation_id
              AND ti.org_id = current_setting('mcpg.org_id', true)::UUID
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM tool_invocations ti
            WHERE ti.id = tool_invocation_payloads.invocation_id
              AND ti.org_id = current_setting('mcpg.org_id', true)::UUID
        )
    );

ALTER TABLE tool_invocation_payloads FORCE ROW LEVEL SECURITY;
