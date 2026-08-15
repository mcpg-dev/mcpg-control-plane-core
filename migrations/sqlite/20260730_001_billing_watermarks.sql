-- Watermark: the last hour whose raw tool invocations have been rolled up.
--
-- The rollup pass recomputed only the hour before now, so each hour had a
-- single opportunity to be aggregated. Raw rows are pruned after 48h, and
-- closed billing periods read rollups only — so a control-plane outage longer
-- than an hour removed those hours from every future invoice permanently, and
-- a missing hour was indistinguishable from an idle one.
--
-- The pass now rolls forward from this mark, so a gap is closed on recovery as
-- long as the raw rows still exist.
CREATE TABLE billing_watermarks (
    name        TEXT PRIMARY KEY NOT NULL,
    watermark   TEXT NOT NULL,
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
