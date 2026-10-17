-- The tenant namespace ResourceQuota an enterprise contract sets for an org.
--
-- A publish sends the provisioner the ceilings the control plane derives from
-- the org's plan (gateways, replicas and the largest compute type the plan
-- allows). A contract that buys more than a plan row — or an unlimited plan,
-- which yields no number — gets its ceilings here, set by a platform admin;
-- a row replaces the plan's derivation for that org. `quota_json` is the
-- control plane's `NamespaceQuota`.

CREATE TABLE org_namespace_quotas (
    org_id      TEXT PRIMARY KEY NOT NULL,
    quota_json  TEXT NOT NULL,
    updated_by  TEXT NOT NULL,
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
