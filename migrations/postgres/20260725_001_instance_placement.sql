-- Where a managed instance actually runs. Until now the answer lived only in
-- the provisioner's operations ledger, so the CP could not report an
-- instance's cell or region without a gRPC round-trip — and a fleet-wide
-- "which instances are in eu-west-1" query was impossible.
--
-- Empty for self-host instances and for anything discovered outside the
-- publish path; the columns are advisory, never a correctness gate (the
-- provisioner's `cell_assignments` remains the placement authority).
--
-- `instances` is RLS-FORCEd; adding columns does not change the policy, which
-- is defined on the table rather than per-column.
ALTER TABLE instances ADD COLUMN cell_id TEXT NOT NULL DEFAULT '';
ALTER TABLE instances ADD COLUMN cell_region TEXT NOT NULL DEFAULT '';
ALTER TABLE instances ADD COLUMN cell_namespace TEXT NOT NULL DEFAULT '';

CREATE INDEX instances_cell_idx ON instances (cell_id);
