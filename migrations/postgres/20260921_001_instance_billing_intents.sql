-- The billing each publish owes once it reaches READY, written before the
-- publish is sent to the provisioner. See the sqlite mirror for the rationale.
-- FORCEd like the ledger it feeds: a tenant's publish writes it in its own
-- scope, and the janitor resolves every tenant's on the BYPASSRLS pool.
CREATE TABLE instance_billing_intents (
    instance_id  UUID PRIMARY KEY,
    org_id       UUID NOT NULL REFERENCES orgs(id),
    workspace_id UUID NOT NULL,
    size         TEXT NOT NULL,
    replicas     INTEGER NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_ibi_requested_at ON instance_billing_intents(requested_at);

ALTER TABLE instance_billing_intents ENABLE ROW LEVEL SECURITY;
ALTER TABLE instance_billing_intents FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_iso_ibi ON instance_billing_intents
    USING (org_id = current_setting('mcpg.org_id', true)::UUID)
    WITH CHECK (org_id = current_setting('mcpg.org_id', true)::UUID);
