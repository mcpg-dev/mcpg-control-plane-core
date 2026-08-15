-- Custom-domain ownership verification — sqlite mirror of the Postgres
-- migration. Ownership of a `custom_hostname` must be proven (DNS TXT
-- challenge at `_mcpg-challenge.<hostname>` = "mcpg-domain-verify=<token>")
-- before the publish path will render it onto the shared edge. RLS is
-- Postgres-only; sqlite / Tier-0 isolates at the application layer (the repo
-- filters by org_id).
--
-- (org_id, hostname) is the per-org key; the GLOBAL unique index on hostname
-- is the cross-tenant arbiter — one org per hostname, platform-wide.

CREATE TABLE custom_domains (
    org_id       TEXT NOT NULL,
    hostname     TEXT NOT NULL,
    token        TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    verified_at  TEXT,
    PRIMARY KEY (org_id, hostname)
);

CREATE UNIQUE INDEX custom_domains_hostname_uq ON custom_domains (hostname);
