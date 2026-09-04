-- Self-service enterprise SSO: one connection per org, applied to Keycloak
-- only after DNS TXT proof of email-domain ownership. The client secret is
-- stored envelope-encrypted; the alias is server-derived (org-<slug>).
CREATE TABLE org_sso_connections (
    org_id            UUID NOT NULL,
    alias             TEXT NOT NULL,
    issuer            TEXT NOT NULL,
    client_id         TEXT NOT NULL,
    client_secret_enc BYTEA NOT NULL,
    email_domain      TEXT NOT NULL,
    token             TEXT NOT NULL,
    -- pending (awaiting DNS proof) | active (applied to Keycloak)
    -- | dns_lost (proof lapsed, IdP disabled) | error (apply failed)
    status            TEXT NOT NULL DEFAULT 'pending',
    jit_enabled       BOOLEAN NOT NULL DEFAULT FALSE,
    last_error        TEXT,
    failing_since     TIMESTAMPTZ,
    verified_at       TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id)
);

-- a login domain belongs to exactly one org, platform-wide; the alias is
-- what Keycloak keys the IdP on
CREATE UNIQUE INDEX org_sso_connections_email_domain ON org_sso_connections (lower(email_domain));
CREATE UNIQUE INDEX org_sso_connections_alias ON org_sso_connections (alias);

ALTER TABLE org_sso_connections ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_iso_org_sso_connections ON org_sso_connections
    USING (org_id = current_setting('mcpg.org_id', true)::UUID)
    WITH CHECK (org_id = current_setting('mcpg.org_id', true)::UUID);
ALTER TABLE org_sso_connections FORCE ROW LEVEL SECURITY;
