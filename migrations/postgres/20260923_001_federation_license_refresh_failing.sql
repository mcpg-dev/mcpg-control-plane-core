-- When the licence refresh first failed to renew a brokered licence, with no
-- refresh answering since. While it is set, an mcpg.cloud licence keeps its
-- plan up to seven days past its `exp`; any answer from the issuer clears it
-- (a new licence replaces the row, a typed revoke removes it).
ALTER TABLE federation_licenses ADD COLUMN refresh_failing_since TIMESTAMPTZ;
