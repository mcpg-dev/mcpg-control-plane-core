-- An org that lost a paid plan, and what it keeps running until the grace
-- ends.
--
-- A plan drop (a downgrade, a cancellation, an unpaid renewal past its grace,
-- a revocation by the issuer, an operator's suspension) judges new work by the
-- plan left at once, but what the org already runs keeps the lost plan's terms
-- until `grace_until`. Then the plan-loss reconciler stops what the plan left
-- does not cover and sets `enforced_at`. An upgrade, a payment or a lifted
-- suspension during the grace deletes the row.
--
-- `held_claims` / `held_jwt` are the lost plan's licence: its claims judge
-- what keeps running, and the token is what the org's gateways are delivered
-- through the grace. `reason` is downgraded | plan_ended | unpaid | revoked |
-- suspended; `immediate` marks an operator's suspension with no grace.
-- `notified_at` is when the owners' notice was sent.

CREATE TABLE org_plan_grace (
    org_id       TEXT PRIMARY KEY NOT NULL,
    held_plan    TEXT NOT NULL,
    held_claims  TEXT NOT NULL,
    held_jwt     TEXT,
    reason       TEXT NOT NULL,
    lost_at      TEXT NOT NULL,
    grace_until  TEXT NOT NULL,
    immediate    INTEGER NOT NULL DEFAULT 0,
    notified_at  TEXT,
    enforced_at  TEXT,
    updated_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
