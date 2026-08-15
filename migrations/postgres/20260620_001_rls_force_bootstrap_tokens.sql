-- Postgres RLS enforcement — end-state: bootstrap_tokens.
--
-- `bootstrap_tokens` is org-keyed (policy `org_id = current_setting('mcpg.org_id')`).
-- `issue`/`find_live_reusable_nonce`/`delete_for_instance_uid` carry the org and
-- self-scope on the main pool. But `consume(nonce, uid)` (gRPC Register / HTTP
-- enrollment) is INHERENTLY cross-org — the nonce is the secret lookup key and
-- the org is its RESULT (like a session token), so there is no org to scope to.
-- `consume` therefore runs on the BYPASSRLS background pool. That bypass pool is
-- why this table is FORCEd only at the end-state (not the per-table owner-role
-- rollout): under the owner role with a single pool, `consume` (and hence every
-- enrollment) would fail closed. See docs/control-plane/POSTGRES.md ("End-state").
--
-- Cross-tenant isolation for the consume path does NOT rest on RLS — it rests on
-- 128-bit nonce uniqueness + the `expected_instance_uid` anti-spoofing check
-- (both unchanged). RLS is the backstop for the org-scoped paths (issue/find/
-- delete), which the explicit `org_id` filters already constrain.
--
-- Policy change vs init.sql: add a WITH CHECK mirroring the USING clause so the
-- `issue` insert is constrained to the scoped org.
--
-- Same caveat: only ACTIVE under a non-superuser runtime role; default superuser
-- / sqlite is unaffected (inert), and `consume` works there because the (default)
-- bg pool is the same superuser/sqlite connection that bypasses RLS.

ALTER POLICY tenant_iso_bootstrap_tokens ON bootstrap_tokens
    USING (org_id = current_setting('mcpg.org_id', true)::UUID)
    WITH CHECK (org_id = current_setting('mcpg.org_id', true)::UUID);

ALTER TABLE bootstrap_tokens FORCE ROW LEVEL SECURITY;
