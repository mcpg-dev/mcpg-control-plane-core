-- Per-call request/response payload capture (Q2 Phase D —
-- Enterprise opt-in).
--
-- One row per `tool_invocations` row that carries captured
-- payloads. Two-table split keeps the hot-path
-- `tool_invocations` table small + indexed, while the
-- ciphertext blobs (potentially large) live in this side
-- table that gets cascade-pruned when the parent row is
-- pruned.
--
-- Both columns are encrypted with the tenant's KMS-derived key
-- via `cipher::EnvelopeCipher::encrypt(tenant_slug, &bytes)`.
-- The CP never stores plaintext; retrieval handlers decrypt
-- on-demand and audit-log the retrieval. NULL means the
-- payload was never captured (e.g. the request had no body)
-- or capture failed at the boundary.

CREATE TABLE tool_invocation_payloads (
    invocation_id     INTEGER PRIMARY KEY NOT NULL
        REFERENCES tool_invocations(id) ON DELETE CASCADE,
    request_ciphertext  BLOB,
    response_ciphertext BLOB,
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- No additional indexes — the only access path is by
-- invocation_id (the primary key) for retrieval, and the
-- cascade delete from `tool_invocations` handles cleanup.
