-- Self-service enterprise SSO: one connection per org, applied to Keycloak
-- only after DNS TXT proof of email-domain ownership. The client secret is
-- stored envelope-encrypted; the alias is server-derived (org-<slug>).
CREATE TABLE org_sso_connections (
    org_id            TEXT NOT NULL,
    alias             TEXT NOT NULL,
    issuer            TEXT NOT NULL,
    client_id         TEXT NOT NULL,
    client_secret_enc BLOB NOT NULL,
    email_domain      TEXT NOT NULL,
    token             TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'pending',
    jit_enabled       INTEGER NOT NULL DEFAULT 0,
    last_error        TEXT,
    failing_since     TEXT,
    verified_at       TEXT,
    created_at        TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at        TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (org_id)
);

CREATE UNIQUE INDEX org_sso_connections_email_domain ON org_sso_connections (lower(email_domain));
CREATE UNIQUE INDEX org_sso_connections_alias ON org_sso_connections (alias);
