-- The serving ceiling the billing federation last computed for an org: its
-- included allowance, the prepaid pack credits still live, and the
-- pay-as-you-go calls its spend cap allows. The quota gate reads it on every
-- heartbeat, and keeps serving on the last one it has while the federation
-- cannot be reached. `limits_json` is the shared
-- `mcpg_control_plane_core::serving_limits::OrgServingLimits`.

CREATE TABLE org_serving_limits (
    org_id       TEXT PRIMARY KEY NOT NULL,
    period       TEXT NOT NULL,
    limits_json  TEXT NOT NULL,
    fetched_at   TEXT NOT NULL
);
