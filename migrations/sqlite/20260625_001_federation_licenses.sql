-- Per-org federation license store (sqlite mirror of the Postgres migration).
--
-- Replaces the single in-process federation-license slot that was overwritten
-- on every federated login (cross-tenant entitlement leak). One row per org;
-- orgs with no row fall back to the in-process default community claims. RLS is
-- Postgres-only (the matching postgres migration FORCEs it); sqlite / Tier-0
-- isolates at the application layer (the repo filters by org_id).
--
-- `claims_json` is the parsed LicenseClaims (entitlement checks); `license_jwt`
-- is the signed token (handed to gateways); `expires_at` mirrors claims.exp so
-- the read path can ignore an expired license.

CREATE TABLE federation_licenses (
    org_id        TEXT PRIMARY KEY NOT NULL,
    license_jwt   TEXT NOT NULL,
    claims_json   TEXT NOT NULL,
    plan          TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    installed_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
