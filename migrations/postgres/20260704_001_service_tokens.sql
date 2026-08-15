-- Service tokens — non-interactive machine credentials (RFC 0007 §"Machine
-- auth" / GA C9).
--
-- Before this table the ONLY ways to authenticate to the CP API were a browser
-- session cookie or an OIDC `Authorization: Bearer <id_token>` — both tied to a
-- human's interactive login. CI / automation / a tenant's own backend had no
-- first-class credential: they either reused a human's id_token (short-lived,
-- not revocable independently) or relied on the loopback (no auth at all).
--
-- A service token is a long-lived (but expirable + independently revocable),
-- opaque bearer credential scoped to ONE org and a fixed set of `org_roles`.
-- It is presented in the same `Authorization: Bearer` header, disambiguated by
-- the `mcpgst_` prefix; the AuthContext extractor resolves it to a synthetic,
-- user-less principal (`user_id = NULL`, never platform-admin) bound to the
-- token's org + roles.
--
-- SECURITY: only the SHA-256 of the presented token is stored (`token_hash`) —
-- the plaintext is shown to the operator exactly ONCE at creation and is
-- otherwise unrecoverable, so a DB compromise yields no usable tokens
-- (256-bit-random preimage). The hash is globally UNIQUE, which doubles as the
-- O(1) auth-time lookup index (no per-row secret comparison — the lookup either
-- hits a row or not). Issuance/revocation are owner-gated AND user-only (a
-- service token cannot mint or manage other service tokens — no lateral
-- escalation). `org_roles` mirrors `org_memberships.org_roles` (TEXT[] on PG).

CREATE TABLE service_tokens (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    -- Human label (e.g. "ci-deploy"). Identifies the token in `list`; NOT a
    -- key (a revoked name can be reused) — tokens are identified by `id`.
    name                TEXT NOT NULL,
    -- SHA-256 of the full presented token string ("mcpgst_<b64url>"). UNIQUE so
    -- the auth path can resolve a presented token with one indexed lookup.
    token_hash          BYTEA NOT NULL UNIQUE,
    org_roles           TEXT[] NOT NULL DEFAULT '{}',
    created_by_user_id  UUID REFERENCES users(id),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- NULL = never expires (operator opt-out); the API defaults to a finite term.
    expires_at          TIMESTAMPTZ,
    last_used_at        TIMESTAMPTZ,
    revoked_at          TIMESTAMPTZ
);

CREATE INDEX service_tokens_org_idx ON service_tokens (org_id);

-- Org-keyed + FORCEd from creation (same posture as custom_domains /
-- federation_licenses; see docs/control-plane/POSTGRES.md). Management
-- (create/list/revoke) runs under the owner's org scope; the auth-time
-- resolve-by-hash is inherently cross-org (no org known yet) and runs on the
-- BYPASSRLS background pool, gated by the globally-unique hash.
ALTER TABLE service_tokens ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_iso_service_tokens ON service_tokens
    USING (org_id = current_setting('mcpg.org_id', true)::UUID)
    WITH CHECK (org_id = current_setting('mcpg.org_id', true)::UUID);
ALTER TABLE service_tokens FORCE ROW LEVEL SECURITY;
