-- The billing each publish owes once it reaches READY, written before the
-- publish is sent to the provisioner.
--
-- A publish opens (or resizes) its instance's billable interval when the
-- provisioner reports READY, from the control-plane process that streams that
-- operation. When that process dies first, or the ledger write fails, the
-- instance runs unbilled until its next publish. The intent is the durable
-- record of what the READY would have written: the READY clears it once the
-- ledger holds the event, a FAILED clears it, and the state janitor opens the
-- interval itself for an intent whose instance has reported in since, and
-- drops one whose instance never came up. One per instance: a republish
-- replaces it.
CREATE TABLE instance_billing_intents (
    instance_id  TEXT PRIMARY KEY NOT NULL,
    org_id       TEXT NOT NULL REFERENCES orgs(id),
    workspace_id TEXT NOT NULL,
    size         TEXT NOT NULL,
    replicas     INTEGER NOT NULL,
    requested_at TEXT NOT NULL
);

CREATE INDEX idx_ibi_requested_at ON instance_billing_intents(requested_at);
