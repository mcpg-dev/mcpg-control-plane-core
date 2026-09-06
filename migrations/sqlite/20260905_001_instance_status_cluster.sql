-- Clustering health section of a StatusReport (`{kind, backend_up,
-- peers}` as reported by the replica). One JSON blob like
-- plugins_json — it is only ever read back whole for the gateway
-- pages, never filtered on inner fields. NULL for reports from
-- agents that predate the field.
ALTER TABLE instance_status_reports ADD COLUMN cluster_json TEXT;
