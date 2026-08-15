-- E.4 — Source-side payload encryption.
--
-- Two changes:
--
-- 1. `tenant_payload_keys` — per-org Data Encryption Key (DEK)
--    issued by the CP and shipped to the gateway via Register /
--    CredentialRotation. The DEK material itself is sealed at
--    rest with the CP's `EnvelopeCipher`, AAD-bound to the org
--    slug — same envelope shape as `tool_invocation_payloads`,
--    so a leaked DB without the master key still can't decrypt
--    DEKs. One row per (org, version); rotation appends a new
--    version and the previous row remains for in-flight rows
--    encrypted under the older DEK (decrypt fall-through).
--
-- 2. `tool_invocation_payloads.payload_encrypted` + `dek_version`
--    — flag the storage path so retrieval handlers know which
--    key to use:
--      * `payload_encrypted = 0` (legacy) ⇒ CP-encrypted at
--        ingest, decrypt with `EnvelopeCipher::decrypt(slug, ct)`.
--        `dek_version` is NULL.
--      * `payload_encrypted = 1` ⇒ already-encrypted at the
--        gateway with the tenant DEK. Decrypt requires loading
--        the matching `tenant_payload_keys` row by `dek_version`,
--        unwrapping it with `EnvelopeCipher::decrypt(slug, ...)`,
--        then AES-256-GCM-decrypting the payload bytes.
--
-- Compatibility: existing rows have `payload_encrypted = 0` and
-- `dek_version = NULL`, which matches the legacy CP-encrypts-at-
-- ingest behaviour. Older gateways that never read
-- `RegisterResponse.payload_dek` keep shipping plaintext and
-- continue to work unchanged.

CREATE TABLE tenant_payload_keys (
    org_id          TEXT NOT NULL,
    key_version     INTEGER NOT NULL,
    -- AES-256 raw key bytes wrapped via `EnvelopeCipher::encrypt
    -- (org_slug, raw_dek)`. Format: nonce(12) || ciphertext+tag.
    dek_ciphertext  BLOB NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    rotated_at      TEXT,
    PRIMARY KEY (org_id, key_version)
);

CREATE INDEX tenant_payload_keys_active_idx
    ON tenant_payload_keys (org_id, key_version DESC);

ALTER TABLE tool_invocation_payloads
    ADD COLUMN payload_encrypted INTEGER NOT NULL DEFAULT 0;

ALTER TABLE tool_invocation_payloads
    ADD COLUMN dek_version INTEGER;
