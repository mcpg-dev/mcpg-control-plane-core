-- Durable, cross-replica per-instance gateway logs backing `mcpg cloud logs`.
--
-- Gateway agents ship rendered log lines over the Channel `LogBatch` message;
-- the CP persists them here so a `logs` tail/follow is durable and works no
-- matter which replica the HTTP request lands on. The former in-memory ring
-- lived only on the replica that owned the agent's Channel, so with
-- `replicaCount>1` (shared Postgres) a `logs` request landing on another replica
-- saw nothing. Same treatment as `instance_status_reports` / `tool_invocations`:
-- RLS-scoped per tenant, pruned by the leader-leased obs pruner.
--
-- `id` (BIGSERIAL) is the monotonic cursor: tail reads the top N by `id DESC`,
-- follow polls `id > :after_id` ascending. `at` is the agent's emit time
-- (nullable — a line may lack one); `ingested_at` is the CP clock used for
-- retention pruning.

CREATE TABLE instance_logs (
    id           BIGSERIAL PRIMARY KEY,
    org_id       UUID NOT NULL,
    workspace_id UUID NOT NULL,
    instance_id  UUID NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    at           TIMESTAMPTZ,
    ingested_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    level        INTEGER NOT NULL,
    target       TEXT NOT NULL,
    message      TEXT NOT NULL,
    plugin_id    TEXT NOT NULL DEFAULT ''
);

-- Tail + follow: newest-first / since-cursor scans for one instance.
CREATE INDEX idx_ilog_instance_id ON instance_logs(instance_id, id DESC);

-- Org-scoped pruning + known_orgs iteration.
CREATE INDEX idx_ilog_org_time ON instance_logs(org_id, ingested_at);

-- RLS: per-tenant, ENABLE + FORCE in one shot (this table is born in the
-- post-rollout era). Copy the status table's fail-closed idiom — the `::UUID`
-- cast plus a matching WITH CHECK, so an unset scope THROWS (a forgotten scope
-- is a loud error, never a silent leak) and INSERT/UPDATE are pinned to the
-- scoped org, not just row visibility.
ALTER TABLE instance_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE instance_logs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_iso_ilog ON instance_logs
    USING (org_id = current_setting('mcpg.org_id', true)::UUID)
    WITH CHECK (org_id = current_setting('mcpg.org_id', true)::UUID);
