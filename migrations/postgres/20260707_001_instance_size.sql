-- Instance size class (`s` | `m` | `l` | `xl`, lowercase). Set by the publish
-- path from the tenant's `--size` choice (plan-gated); drives the provisioned
-- pod's resource requests/limits via the provisioner's size ladder. Instances
-- discovered outside the publish path (self-registration / kube provider)
-- keep the default.
ALTER TABLE instances ADD COLUMN size TEXT NOT NULL DEFAULT 's';
