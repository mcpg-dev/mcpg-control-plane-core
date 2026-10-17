-- How long a revoked org keeps its paid retention.
--
-- A licence the issuer no longer issues kept the floor's windows with no end,
-- holding data and pausing the idle reaper for an org that pays for nothing.
-- `revoked_at` is when the revocation was first seen: the floor holds for 90
-- days from it, then the free plan's windows apply. `revoked_notified_at` is
-- when the owners were told the windows are about to shrink. Both are cleared
-- once a licence is installed again.
ALTER TABLE license_retention_floors ADD COLUMN revoked_at TEXT;
ALTER TABLE license_retention_floors ADD COLUMN revoked_notified_at TEXT;
