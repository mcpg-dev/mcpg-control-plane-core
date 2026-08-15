-- Per-call tool invocation log (Q2 Phase C — observability).
--
-- Captures one row per tool call dispatched on a gateway, sent
-- in batches over the agent Channel via `MetricsReport`. The
-- raw rows are short-lived (~48h retention by default — see
-- `obs_pruner::TOOL_INVOCATIONS_RETENTION`); longer history
-- lives in the `tool_usage_rollups_*` tables.
--
-- Privacy invariant: tool *names* and aggregate stats are
-- captured. Tool *arguments* and *responses* are NEVER stored —
-- those may contain PII / secrets. `error_hash` is BLAKE3 of
-- the error message (operators correlate via local logs by
-- hash); the literal string is never shipped.
--
-- Cardinality discipline: gateway emits a top-K per-window cap
-- + an `__other__` overflow bucket so an attacker calling many
-- random tool names can't blow up this table.

CREATE TABLE tool_invocations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id          TEXT NOT NULL,
    workspace_id    TEXT NOT NULL,
    instance_id     TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    binding_id      TEXT,                              -- nullable: not every call routes via a binding
    plugin_id       TEXT NOT NULL,                     -- e.g. "github"
    tool_name       TEXT NOT NULL,                     -- e.g. "list_repos"
    started_at      TEXT NOT NULL,                     -- agent clock; informational
    ingested_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),  -- CP clock; query-authoritative
    duration_ms     INTEGER NOT NULL,
    outcome         TEXT NOT NULL,                     -- 'ok' | 'client_error' | 'server_error' | 'policy_denied'
    error_code      TEXT,                              -- e.g. "TIMEOUT", "INVALID_ARG"
    error_hash      TEXT,                              -- blake3 hex of error message (no plaintext)
    request_id      TEXT,                              -- correlation id
    caller_subject  TEXT                               -- "user:alice@acme" / "service:foo" — already in audit pattern
);

-- Time-window queries on workspace ("last hour of tool calls").
CREATE INDEX idx_ti_workspace_time
    ON tool_invocations(workspace_id, ingested_at DESC);

-- Tool drill-down ("p95 latency for github.list_repos last 24h").
CREATE INDEX idx_ti_tool_time
    ON tool_invocations(workspace_id, plugin_id, tool_name, ingested_at DESC);

-- Per-instance drill-down.
CREATE INDEX idx_ti_instance_time
    ON tool_invocations(instance_id, ingested_at DESC);

-- Outcome filtering ("show me errors from the last hour").
CREATE INDEX idx_ti_outcome_time
    ON tool_invocations(workspace_id, outcome, ingested_at DESC);

-- Org-scoped pruning (matches obs_pruner.known_orgs query).
CREATE INDEX idx_ti_org_time
    ON tool_invocations(org_id, ingested_at DESC);


-- Hourly rollups computed by the obs_rollup background task from
-- raw `tool_invocations` rows. Retained much longer (1 year);
-- rollups are tiny relative to raw events.
CREATE TABLE tool_usage_rollups_hourly (
    org_id          TEXT NOT NULL,
    workspace_id    TEXT NOT NULL,
    plugin_id       TEXT NOT NULL,
    tool_name       TEXT NOT NULL,
    window_start    TEXT NOT NULL,    -- truncated to hour boundary, CP clock
    calls           INTEGER NOT NULL,
    errors          INTEGER NOT NULL,
    p50_ms          INTEGER NOT NULL,
    p95_ms          INTEGER NOT NULL,
    p99_ms          INTEGER NOT NULL,
    max_ms          INTEGER NOT NULL,
    PRIMARY KEY (workspace_id, plugin_id, tool_name, window_start)
);
CREATE INDEX idx_turh_workspace_time
    ON tool_usage_rollups_hourly(workspace_id, window_start DESC);
CREATE INDEX idx_turh_org_time
    ON tool_usage_rollups_hourly(org_id, window_start DESC);


-- Daily rollups, retained even longer (5 years). Same shape as
-- hourly, just different `window_start` granularity.
CREATE TABLE tool_usage_rollups_daily (
    org_id          TEXT NOT NULL,
    workspace_id    TEXT NOT NULL,
    plugin_id       TEXT NOT NULL,
    tool_name       TEXT NOT NULL,
    window_start    TEXT NOT NULL,    -- truncated to day boundary, CP clock
    calls           INTEGER NOT NULL,
    errors          INTEGER NOT NULL,
    p50_ms          INTEGER NOT NULL,
    p95_ms          INTEGER NOT NULL,
    p99_ms          INTEGER NOT NULL,
    max_ms          INTEGER NOT NULL,
    PRIMARY KEY (workspace_id, plugin_id, tool_name, window_start)
);
CREATE INDEX idx_turd_workspace_time
    ON tool_usage_rollups_daily(workspace_id, window_start DESC);
CREATE INDEX idx_turd_org_time
    ON tool_usage_rollups_daily(org_id, window_start DESC);
