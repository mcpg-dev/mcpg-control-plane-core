-- The `secrets_digest` a StatusReport carries: sha256 (hex) over the
-- `${secret.*}` values the running config was resolved with. The control
-- plane computes the same digest over the registered set, so comparing the
-- two says whether a registered value is live on the gateway without either
-- side ever sending a value. NULL for reports persisted before the column
-- existed; empty for a gateway that resolves no secret.
ALTER TABLE instance_status_reports ADD COLUMN secrets_digest TEXT;
