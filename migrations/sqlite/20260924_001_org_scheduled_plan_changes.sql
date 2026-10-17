-- A plan change an org's owner scheduled in advance: a downgrade or a cancel
-- that takes effect when the paid period ends.
--
-- The licence refresh and the plan-loss reconciler each hold back a pass
-- that would bring down more paid orgs than their brake allows — the mark of
-- an issuer that answers wrongly, not of customers leaving. A change the
-- control plane saw scheduled before it took effect is customers leaving, so
-- it never counts toward either brake. `to_plan` is the plan it lands on
-- (`community` for a cancel), `effective_at` when it takes effect.

CREATE TABLE org_scheduled_plan_changes (
    org_id        TEXT PRIMARY KEY NOT NULL,
    to_plan       TEXT NOT NULL,
    effective_at  TEXT NOT NULL,
    recorded_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
