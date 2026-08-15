-- Anchor for a per-org audit chain whose head has been archived and pruned.
--
-- `audit_log` is an append-only hash chain verified from a genesis of 32 zero
-- bytes, so deleting the oldest entries makes every remaining one unverifiable:
-- the first survivor's `prev_hash` no longer matches the walk's starting value.
--
-- A checkpoint records where the chain was cut, which hash the walk should
-- resume from, and where the removed entries now live. Verification starts from
-- `through_hash` instead of genesis, and the archive segment — signed, and
-- digest-matched before anything was deleted — is the verifiable record of what
-- came before.
--
-- One row per org: a later cut supersedes the earlier one, and its segment
-- chains back through `prev_segment_digest`.
CREATE TABLE audit_chain_checkpoints (
    org_id              UUID PRIMARY KEY NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    -- Highest `audit_log.id` that was archived and removed.
    through_id          BIGINT NOT NULL,
    -- `entry_hash` of that entry: the `prev_hash` the next survivor must carry.
    through_hash        BYTEA NOT NULL,
    -- Entries in this segment, and in every segment before it.
    archived_count      BIGINT NOT NULL,
    total_archived      BIGINT NOT NULL,
    -- blake3 of the segment bytes as written, and of the segment this one
    -- superseded (NULL for the first cut) — the archive is itself a chain.
    segment_digest      BYTEA NOT NULL,
    prev_segment_digest BYTEA,
    -- Where the segment was written, as the archive reported it.
    segment_locator     TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE audit_chain_checkpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_chain_checkpoints FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_iso_audit_chain_checkpoints ON audit_chain_checkpoints
    USING (org_id = current_setting('mcpg.org_id', true)::UUID)
    WITH CHECK (org_id = current_setting('mcpg.org_id', true)::UUID);
