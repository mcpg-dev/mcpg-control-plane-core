-- See sqlite mirror for full doc.

CREATE TABLE tool_invocation_payloads (
    invocation_id     BIGINT PRIMARY KEY
        REFERENCES tool_invocations(id) ON DELETE CASCADE,
    request_ciphertext  BYTEA,
    response_ciphertext BYTEA,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- RLS via the parent table's `org_id` is the natural posture
-- — payload retrieval handlers join `tool_invocations` first
-- and rely on its RLS policy. We still enable RLS here as
-- belt-and-braces in case a future query path bypasses the
-- join.
ALTER TABLE tool_invocation_payloads ENABLE ROW LEVEL SECURITY;
-- Anyone who can SELECT the parent invocation can read its
-- payload; the join enforces tenancy.
CREATE POLICY tenant_iso_tip ON tool_invocation_payloads
    USING (
        EXISTS (
            SELECT 1 FROM tool_invocations ti
            WHERE ti.id = tool_invocation_payloads.invocation_id
              AND ti.org_id::text = current_setting('mcpg.org_id', true)
        )
    );
