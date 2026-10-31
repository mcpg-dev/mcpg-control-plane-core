-- No-op on Sqlite: `orgs.status` has no column CHECK here (see
-- 20260701_001_org_status.sql), so `decommissioning` needs no schema change.
-- This file exists to keep the sqlite/postgres migration sets in lockstep.
SELECT 1;
