-- E.4 — Source-side payload encryption. See sqlite mirror for
-- the full doc.

CREATE TABLE tenant_payload_keys (
    org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    key_version     INTEGER NOT NULL,
    dek_ciphertext  BYTEA NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at      TIMESTAMPTZ,
    PRIMARY KEY (org_id, key_version)
);

CREATE INDEX tenant_payload_keys_active_idx
    ON tenant_payload_keys (org_id, key_version DESC);

ALTER TABLE tenant_payload_keys ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_iso_payload_keys ON tenant_payload_keys
    USING (org_id::text = current_setting('mcpg.org_id', true));

ALTER TABLE tool_invocation_payloads
    ADD COLUMN payload_encrypted BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE tool_invocation_payloads
    ADD COLUMN dek_version INTEGER;
