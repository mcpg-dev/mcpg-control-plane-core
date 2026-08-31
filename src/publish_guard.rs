//! Pre-deploy guard for tenant-published gateway configs.
//!
//! In the managed service a tenant publishes a config that the platform runs
//! **in the tenant's own pod**. That makes the published config "config-origin"
//! — the position the gateway trusts for credential + environment resolution.
//! Two of those resolutions read host resources at config-load time and must
//! NOT be reachable from a tenant-authored config:
//!
//! - **CEL env interpolation** `${env.X}` / `${env.X}` — expanded against the
//!   POD's environment at load (see `libs/expr`). A tenant could read platform
//!   pod-env (downward-API values, future injected secrets) this way.
//! - **`env://` / `file://` secret-provider URIs** — resolve against pod env /
//!   filesystem. Same host-read exfil surface.
//!
//! The guard runs **before** the config is handed to the provisioner (CP
//! publish handler) — and is reusable by the `mcpg cloud` CLI pre-flight and a
//! belt-and-braces operator admission check. It parses the submitted YAML/TOML
//! and inspects only **leaf string VALUES** — never object keys, and never
//! comments (the parser drops them). So a `# ${env.X}` comment or an
//! `env`-named key does NOT 422 an otherwise-valid config; only a token that
//! would actually be interpolated/resolved (a value) is a violation.
//! `${env.X}` is gone once `AppConfig::load` expands it, so a post-load object
//! would never show it. Unparseable input fails closed (it wouldn't boot).
//!
//! It does NOT reject `${cred://plugin/target}` (a tenant's own credential
//! plugins) — it only validates such tokens are well-formed. External secret
//! schemes the tenant owns (`vault://`, `aws-sm://`) are likewise allowed; only
//! the host-reading `env://` / `file://` schemes are blocked.

use std::fmt;

/// A single rejected construct, with enough context for a useful CLI/API error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    /// Machine-stable kind (`host_env_interpolation`, `host_secret_uri`,
    /// `malformed_cred_token`).
    pub kind: &'static str,
    /// The offending token / fragment (truncated), for the operator's message.
    pub snippet: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishGuardError {
    pub violations: Vec<Violation>,
}

impl fmt::Display for PublishGuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "published config rejected by the publish guard ({} violation(s)): ",
            self.violations.len()
        )?;
        for (i, v) in self.violations.iter().enumerate() {
            if i > 0 {
                write!(f, "; ")?;
            }
            write!(f, "{} [{}]", v.snippet, v.kind)?;
        }
        Ok(())
    }
}

impl std::error::Error for PublishGuardError {}

/// CEL env-interpolation opener, matching `libs/expr`'s parser.
const ENV_OPENERS: [&str; 1] = ["${env."];
/// Credential-token opener (`${cred://plugin/target}`).
const CRED_OPENER: &str = "${cred://";
/// Secret-provider URI schemes that read POD-local host resources. Both carry
/// `//`, so they can't collide with a YAML/TOML key named `env`/`file`.
const HOST_SECRET_SCHEMES: [&str; 2] = ["env://", "file://"];
/// The one key that turns off the private-address pin, wherever it appears.
const PRIVATE_BACKENDS_KEY: &str = "allow_private_backends";

/// Validate a raw tenant-published config (YAML or TOML text). Returns the full
/// set of violations so the operator sees every problem at once, not one per
/// round-trip.
pub fn check_published_config(raw: &str) -> Result<(), PublishGuardError> {
    // Parse once, then inspect only leaf STRING VALUES. Object keys are never
    // visited and comments are dropped by the parser, so a forbidden token in a
    // comment or key can't false-positive an otherwise-valid config — only a
    // value that would actually be interpolated/resolved is a violation.
    let Some(cfg) = parse_structured(raw) else {
        // Fail closed: a config we can't parse as YAML or TOML can't be scanned
        // (and wouldn't boot the gateway anyway — mirrors `CloudAuthError::Unparseable`).
        return Err(PublishGuardError {
            violations: vec![Violation {
                kind: "unparseable_config",
                snippet: "config is not valid YAML or TOML".to_owned(),
            }],
        });
    };

    let mut violations = Vec::new();
    walk_leaf_strings(&cfg, &mut |leaf| check_leaf_value(leaf, &mut violations));
    check_ssrf(&cfg, &mut violations);

    if violations.is_empty() {
        Ok(())
    } else {
        Err(PublishGuardError { violations })
    }
}

/// Reject constructs that would let a tenant-published config reach the pod's
/// internal network (SSRF). The gateway's runtime pin already blocks backends
/// that *resolve* to private IPs — **unless** `allow_private_backends` is set,
/// which is exactly the bypass a published config must not carry, at whichever
/// level it is written. We also reject federation upstreams whose URL
/// host is a literal private IP or an obvious local name (the static guard can't
/// DNS-resolve, so the runtime pin remains the backstop for public names that
/// resolve privately). The sanctioned same-org private path is a
/// `tunnel://<name>` upstream, which is not gated here — it egresses through the
/// authenticated relay, not a raw private IP.
fn check_ssrf(cfg: &serde_json::Value, violations: &mut Vec<Violation>) {
    // `allow_private_backends` means the same thing wherever it sits:
    // `gateway.server`, a federation's `upstream_safety`, a registry's, and a
    // binding's own `backend` — which the gateway hands to a backend plugin
    // unparsed, so no schema on this side can enumerate where it may appear.
    // Searching for the key closes the surface that a list of paths reopens
    // every time a new one is added.
    let mut seen: Vec<String> = Vec::new();
    collect_private_backends(cfg, &mut String::new(), &mut seen);
    for path in seen {
        violations.push(Violation {
            kind: "private_backends_enabled",
            snippet: format!("{path}: true"),
        });
    }

    let Some(feds) = cfg.pointer("/mcp/federations").and_then(|v| v.as_array()) else {
        return;
    };
    for fed in feds {
        if let Some(url) = fed.pointer("/upstream/url").and_then(|v| v.as_str())
            && let Some(host) = gated_upstream_host(url)
            && is_private_or_local_host(&host)
        {
            violations.push(Violation {
                kind: "private_federation_upstream",
                snippet: truncate(url),
            });
        }
    }
}

/// Every `allow_private_backends: true` in the document, as a dotted path with
/// `[]` for a list. Two bindings that both set it collapse to one entry: the
/// path is what the operator has to go and edit, and repeating it says nothing
/// the first line did not.
fn collect_private_backends(value: &serde_json::Value, path: &mut String, out: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                let base = path.len();
                if !path.is_empty() {
                    path.push('.');
                }
                path.push_str(key);
                if key == PRIVATE_BACKENDS_KEY {
                    if child.as_bool() == Some(true) && !out.iter().any(|seen| seen == path) {
                        out.push(path.clone());
                    }
                } else {
                    collect_private_backends(child, path, out);
                }
                path.truncate(base);
            }
        }
        serde_json::Value::Array(items) => {
            let base = path.len();
            path.push_str("[]");
            for item in items {
                collect_private_backends(item, path, out);
            }
            path.truncate(base);
        }
        _ => {}
    }
}

/// The host of an `http(s)`/`ws(s)` upstream URL, or `None` for a scheme we do
/// not gate here: `tunnel://` (the sanctioned private path) and stdio (no URL).
fn gated_upstream_host(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    if !matches!(scheme, "http" | "https" | "ws" | "wss") {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host_port = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    // A bracketed IPv6 host (`[::1]:443`) keeps its brackets when stripping the
    // port; a `host:port` splits on the last colon.
    let host = match host_port.rfind(']') {
        Some(close) => &host_port[..=close],
        None => host_port
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(host_port),
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    (!host.is_empty()).then(|| host.to_owned())
}

/// Whether a host string is a literal private/loopback IP or an obvious
/// pod-local name. Best-effort static classification; the gateway's runtime DNS
/// pin remains the backstop for public names that resolve to private IPs.
fn is_private_or_local_host(host: &str) -> bool {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return ip_is_private(&ip);
    }
    let h = host.to_ascii_lowercase();
    h == "localhost"
        || h.ends_with(".localhost")
        || h.ends_with(".local")
        || h.ends_with(".internal")
        || h == "metadata.google.internal"
}

fn ip_is_private(ip: &std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local() // 169.254/16, incl. the 169.254.169.254 metadata IP
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.octets()[0] == 0 // 0.0.0.0/8
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|m| ip_is_private(&IpAddr::V4(m)))
        }
    }
}

/// Recursively visit every leaf `String` value (object values + array
/// elements). Object KEYS are deliberately never visited.
fn walk_leaf_strings(v: &serde_json::Value, f: &mut impl FnMut(&str)) {
    match v {
        serde_json::Value::String(s) => f(s),
        serde_json::Value::Array(items) => {
            for item in items {
                walk_leaf_strings(item, f);
            }
        }
        serde_json::Value::Object(map) => {
            for value in map.values() {
                walk_leaf_strings(value, f);
            }
        }
        _ => {}
    }
}

/// Run the three host-read checks against one leaf string value.
fn check_leaf_value(value: &str, violations: &mut Vec<Violation>) {
    // 1. Host-env interpolation `${env.X}`.
    for opener in ENV_OPENERS {
        for snippet in tokens_from(value, opener, '}') {
            violations.push(Violation {
                kind: "host_env_interpolation",
                snippet,
            });
        }
    }

    // 2. `${cred://...}` tokens — allowed, but must be well-formed
    //    (`cred://<plugin>/<target>[#part]`).
    for inner in cred_token_inners(value) {
        if !is_well_formed_cred(&inner) {
            violations.push(Violation {
                kind: "malformed_cred_token",
                snippet: format!("${{{inner}}}"),
            });
        }
    }

    // 3. Host-reading secret-provider URIs (`env://`, `file://`). Only count a
    //    scheme at a value boundary so an embedded substring (e.g. the `file:/`
    //    inside `profile://`) doesn't false-positive.
    for scheme in HOST_SECRET_SCHEMES {
        for idx in scheme_boundary_matches(value, scheme) {
            let end = value[idx..]
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '}')
                .map(|e| idx + e)
                .unwrap_or(value.len());
            violations.push(Violation {
                kind: "host_secret_uri",
                snippet: truncate(&value[idx..end]),
            });
        }
    }
}

/// Why a cloud publish was refused for lacking authentication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CloudAuthError {
    /// No token verifier (`governance.access.jwks` / `oidc_oauth`) is
    /// configured and the tenant did not explicitly opt into an anonymous
    /// gateway (`cloud.allow_anonymous: true`).
    NoVerifier,
    /// The config could not be parsed as YAML or TOML, so its auth posture
    /// can't be verified. Fail closed — an unparseable config wouldn't boot
    /// the gateway anyway.
    Unparseable,
}

impl fmt::Display for CloudAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoVerifier => write!(
                f,
                "cloud gateway requires a token verifier so its public endpoint isn't reachable \
                 with a self-asserted identity: set `governance.access.jwks` (or \
                 `governance.access.oidc_oauth`) to your IdP. To intentionally publish a public / \
                 anonymous MCP server, set `cloud.allow_anonymous: true`."
            ),
            Self::Unparseable => write!(
                f,
                "published config could not be parsed as YAML or TOML, so its authentication \
                 posture can't be verified — fix the config and re-publish."
            ),
        }
    }
}

impl std::error::Error for CloudAuthError {}

/// Guard a **managed-cloud** publish: a gateway exposed on the public edge at
/// `https://{subdomain}.<domain>/mcp` must not be reachable by a caller that
/// merely asserts an identity header. The gateway only enforces verified auth
/// when `governance.access.jwks` or `governance.access.oidc_oauth` is
/// configured (mirrors the gateway's `AccessConfig::is_enabled`); with neither,
/// the default trust floor admits self-asserted (`HeaderAsserted`) callers.
///
/// So at publish time we require EITHER a configured verifier OR an explicit
/// `cloud.allow_anonymous: true` opt-out (a deliberately public MCP server).
/// This is IdP-agnostic — the tenant brings their own issuer — and runs only
/// on the cloud publish path (self-host gateways never pass through here).
///
/// Call this AFTER [`check_published_config`]; it parses the structured config
/// (YAML first, then TOML — the two accepted publish encodings).
pub fn require_cloud_auth(raw: &str) -> Result<(), CloudAuthError> {
    let Some(cfg) = parse_structured(raw) else {
        return Err(CloudAuthError::Unparseable);
    };

    // Explicit opt-out: the tenant declares an intentionally public gateway.
    if cfg
        .pointer("/cloud/allow_anonymous")
        .and_then(|v| v.as_bool())
        == Some(true)
    {
        return Ok(());
    }

    // A configured verifier under `governance.access` — presence of either key
    // as an object is exactly what flips the gateway's `is_enabled()` to true.
    let access = cfg.pointer("/governance/access");
    let has_verifier = access.is_some_and(|a| {
        is_present_object(a.get("jwks")) || is_present_object(a.get("oidc_oauth"))
    });

    if has_verifier {
        Ok(())
    } else {
        Err(CloudAuthError::NoVerifier)
    }
}

/// Parse a published config into a JSON value, trying YAML first (the documented
/// publish format) then TOML (the provisioner's fallback). Returns `None` when
/// neither yields a top-level object.
fn parse_structured(raw: &str) -> Option<serde_json::Value> {
    if let Ok(v) = serde_yaml::from_str::<serde_json::Value>(raw)
        && v.is_object()
    {
        return Some(v);
    }
    if let Ok(v) = toml::from_str::<serde_json::Value>(raw)
        && v.is_object()
    {
        return Some(v);
    }
    None
}

/// True when `node` is present and a JSON object (matches the gateway treating
/// `jwks: {}` / `oidc_oauth: {...}` as "auth enabled" — a present, non-null
/// block). `null` / absent / scalar ⇒ not a verifier.
fn is_present_object(node: Option<&serde_json::Value>) -> bool {
    matches!(node, Some(serde_json::Value::Object(_)))
}

/// Collect every `<opener>...<close>` token's full text (opener through close).
fn tokens_from(raw: &str, opener: &str, close: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = raw;
    while let Some(start) = rest.find(opener) {
        let after = &rest[start + opener.len()..];
        match after.find(close) {
            Some(end) => {
                let token = &rest[start..start + opener.len() + end + close.len_utf8()];
                out.push(truncate(token));
                rest = &after[end + close.len_utf8()..];
            }
            None => break,
        }
    }
    out
}

/// Inner `cred://...` strings of every `${cred://...}` token.
fn cred_token_inners(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = raw;
    while let Some(open) = rest.find(CRED_OPENER) {
        let after = &rest[open + 2..]; // skip "${" → "cred://...}"
        match after.find('}') {
            Some(close) => {
                out.push(after[..close].to_owned());
                rest = &after[close + 1..];
            }
            None => break,
        }
    }
    out
}

/// Byte offsets where `scheme` starts at a value boundary — i.e. the preceding
/// char isn't part of a longer identifier (so `file:/` inside `profile://` is
/// not matched, but `"file://…"` / ` file://…` / a line-leading one is).
fn scheme_boundary_matches(raw: &str, scheme: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(rel) = raw[from..].find(scheme) {
        let idx = from + rel;
        let boundary = idx == 0
            || !matches!(
                raw[..idx].chars().next_back(),
                Some(c) if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'
            );
        if boundary {
            out.push(idx);
        }
        from = idx + scheme.len();
    }
    out
}

/// `cred://<plugin>/<target>[#part]` with non-empty plugin + target.
fn is_well_formed_cred(inner: &str) -> bool {
    let Some(path) = inner.strip_prefix("cred://") else {
        return false;
    };
    let (path, part_ok) = match path.split_once('#') {
        Some((p, frag)) => (p, !frag.is_empty()),
        None => (path, true),
    };
    if !part_ok {
        return false;
    }
    match path.split_once('/') {
        Some((plugin, target)) => !plugin.is_empty() && !target.is_empty(),
        None => false,
    }
}

fn truncate(s: &str) -> String {
    const MAX: usize = 80;
    if s.len() <= MAX {
        s.to_owned()
    } else {
        let mut end = MAX;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &s[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_a_clean_config() {
        let cfg = r#"
            gateway:
              server:
                bind_address: "0.0.0.0:8787"
            governance:
              access:
                resource_metadata:
                  resource: "https://edge-1.mcpg.cloud/mcp"
        "#;
        assert!(check_published_config(cfg).is_ok());
    }

    #[test]
    fn rejects_bare_and_legacy_env_interpolation() {
        let err = check_published_config(r#"url: "${env.DATABASE_URL}""#).unwrap_err();
        assert_eq!(err.violations.len(), 1);
        assert_eq!(err.violations[0].kind, "host_env_interpolation");

        let err = check_published_config(r#"token: "${env.MCPG_BOOTSTRAP}""#).unwrap_err();
        assert_eq!(err.violations[0].kind, "host_env_interpolation");
        assert!(err.to_string().contains("host_env_interpolation"));
    }

    #[test]
    fn reports_every_env_violation_at_once() {
        let cfg = r#"a: "${env.A}"
b: "${env.B}"
c: "${env.C}""#;
        let err = check_published_config(cfg).unwrap_err();
        assert_eq!(err.violations.len(), 3);
    }

    #[test]
    fn allows_well_formed_cred_token() {
        let cfg = r#"url: "postgres://app:${cred://vault/pw}@db/orders""#;
        assert!(check_published_config(cfg).is_ok());
    }

    #[test]
    fn rejects_malformed_cred_token() {
        // missing target after plugin
        let err = check_published_config(r#"x: "${cred://vault}""#).unwrap_err();
        assert_eq!(err.violations[0].kind, "malformed_cred_token");
    }

    #[test]
    fn rejects_host_secret_provider_uris() {
        for cfg in [
            r#"secret: "env://AWS_SECRET_ACCESS_KEY""#,
            r#"ca: "file:///var/run/secrets/token""#,
        ] {
            let err = check_published_config(cfg).unwrap_err();
            assert!(
                err.violations.iter().any(|v| v.kind == "host_secret_uri"),
                "expected host_secret_uri for {cfg}"
            );
        }
    }

    #[test]
    fn allows_external_secret_schemes() {
        // vault:// / aws-sm:// are the tenant's own external stores, not host reads.
        let cfg = r#"a: "vault://kv/data/db"
b: "aws-sm://prod/db-password""#;
        assert!(check_published_config(cfg).is_ok());
    }

    #[test]
    fn allows_forbidden_token_in_a_comment() {
        // A comment mentioning a forbidden token is dropped by the parser and
        // must NOT reject an otherwise-clean config (the reported false-positive).
        let cfg = r#"
            # example (don't do this): url: "${env.DATABASE_URL}"
            # or a secret via env://FOO / file:///run/secrets/x
            gateway:
              server:
                bind_address: "0.0.0.0:8787"
        "#;
        assert!(check_published_config(cfg).is_ok());
    }

    #[test]
    fn allows_forbidden_token_in_a_key() {
        // A key is never interpolated, so a forbidden substring in a key is fine.
        let cfg = r#"
            annotations:
              "note-about-${env.X}-and-file://y": "harmless value"
        "#;
        assert!(check_published_config(cfg).is_ok());
    }

    #[test]
    fn still_rejects_forbidden_token_in_a_value() {
        let err = check_published_config(r#"url: "${env.DATABASE_URL}""#).unwrap_err();
        assert_eq!(err.violations[0].kind, "host_env_interpolation");
    }

    #[test]
    fn check_published_config_fails_closed_on_unparseable() {
        let err = check_published_config("just a bare scalar, not an object").unwrap_err();
        assert_eq!(err.violations[0].kind, "unparseable_config");
    }

    #[test]
    fn cloud_auth_allows_jwks_verifier() {
        let cfg = r#"
            governance:
              access:
                jwks:
                  url: "https://idp.acme.com/.well-known/jwks.json"
                  audience: "mcpg-acme"
        "#;
        assert!(require_cloud_auth(cfg).is_ok());
    }

    #[test]
    fn cloud_auth_allows_oidc_verifier() {
        let cfg = r#"
            governance:
              access:
                oidc_oauth:
                  providers:
                    - issuer: "https://idp.acme.com/"
                      client_id: "gw"
        "#;
        assert!(require_cloud_auth(cfg).is_ok());
    }

    #[test]
    fn cloud_auth_rejects_unauthenticated_config() {
        // No verifier, no opt-out ⇒ a publicly-reachable gateway by omission.
        let cfg = r#"
            gateway:
              server:
                bind_address: "0.0.0.0:8787"
        "#;
        assert_eq!(require_cloud_auth(cfg), Err(CloudAuthError::NoVerifier));
        // resource_metadata alone is advertisement, not enforcement.
        let advertised = r#"
            governance:
              access:
                resource_metadata:
                  resource: "https://x.mcpg.cloud/mcp"
        "#;
        assert_eq!(
            require_cloud_auth(advertised),
            Err(CloudAuthError::NoVerifier)
        );
    }

    #[test]
    fn cloud_auth_honors_explicit_opt_out() {
        let cfg = r#"
            cloud:
              allow_anonymous: true
            gateway:
              server:
                bind_address: "0.0.0.0:8787"
        "#;
        assert!(require_cloud_auth(cfg).is_ok());
        // allow_anonymous: false is NOT an opt-out.
        let off = r#"
            cloud:
              allow_anonymous: false
        "#;
        assert_eq!(require_cloud_auth(off), Err(CloudAuthError::NoVerifier));
    }

    #[test]
    fn cloud_auth_parses_toml_publishes() {
        // The provisioner accepts TOML as well as YAML — the guard must too,
        // or a TOML publish would bypass the check.
        let toml_cfg = r#"
[governance.access.jwks]
url = "https://idp.acme.com/.well-known/jwks.json"
audience = "mcpg-acme"
"#;
        assert!(require_cloud_auth(toml_cfg).is_ok());
        let toml_bare = "[gateway.server]\nbind_address = \"0.0.0.0:8787\"\n";
        assert_eq!(
            require_cloud_auth(toml_bare),
            Err(CloudAuthError::NoVerifier)
        );
    }

    #[test]
    fn cloud_auth_fails_closed_on_unparseable() {
        // Not a YAML/TOML object (a bare scalar) ⇒ can't verify ⇒ reject.
        assert_eq!(
            require_cloud_auth("just a string"),
            Err(CloudAuthError::Unparseable)
        );
    }

    #[test]
    fn cloud_auth_treats_null_jwks_as_no_verifier() {
        // `jwks:` with no value parses to null, not an object — not a verifier.
        let cfg = r#"
            governance:
              access:
                jwks:
        "#;
        assert_eq!(require_cloud_auth(cfg), Err(CloudAuthError::NoVerifier));
    }

    #[test]
    fn rejects_server_level_private_backends() {
        let cfg = r#"
            gateway:
              server:
                allow_private_backends: true
        "#;
        let err = check_published_config(cfg).unwrap_err();
        assert_eq!(err.violations[0].kind, "private_backends_enabled");
    }

    #[test]
    fn allows_server_level_private_backends_false() {
        // The default posture is not a bypass — only an explicit `true` is.
        let cfg = r#"
            gateway:
              server:
                allow_private_backends: false
        "#;
        assert!(check_published_config(cfg).is_ok());
    }

    #[test]
    fn rejects_federation_private_backends_opt_in() {
        let cfg = r#"
            mcp:
              federations:
                - name: internal
                  upstream:
                    url: "https://api.example.com/mcp"
                    upstream_safety:
                      allow_private_backends: true
        "#;
        let err = check_published_config(cfg).unwrap_err();
        assert!(
            err.violations
                .iter()
                .any(|v| v.kind == "private_backends_enabled"),
            "expected private_backends_enabled, got {:?}",
            err.violations
        );
    }

    #[test]
    fn rejects_binding_level_private_backends() {
        // A binding's `backend:` block is a plugin spec the gateway forwards
        // unparsed, so this level is reachable without touching either of the
        // two the guard used to name.
        let cfg = r#"
            mcp:
              capabilities:
                tools:
                  - name: hass.states.list
                    backend:
                      kind: http
                      url: "https://hass.local/api/states"
                      allow_private_backends: true
        "#;
        let err = check_published_config(cfg).unwrap_err();
        assert!(
            err.violations.contains(&Violation {
                kind: "private_backends_enabled",
                snippet: "mcp.capabilities.tools[].backend.allow_private_backends: true".to_owned(),
            }),
            "expected the binding path to be named, got {:?}",
            err.violations
        );
    }

    #[test]
    fn reports_one_private_backends_violation_per_path() {
        // Four bindings, one path: the operator edits one place, and four
        // identical lines say nothing the first did not.
        let cfg = r#"
            mcp:
              capabilities:
                tools:
                  - name: a
                    backend: { kind: http, allow_private_backends: true }
                  - name: b
                    backend: { kind: http, allow_private_backends: true }
                resources:
                  - name: c
                    backend: { kind: http, allow_private_backends: true }
        "#;
        let err = check_published_config(cfg).unwrap_err();
        // Collection order follows map iteration and is not part of the
        // contract — compare as sets.
        let mut paths: Vec<&str> = err
            .violations
            .iter()
            .filter(|v| v.kind == "private_backends_enabled")
            .map(|v| v.snippet.as_str())
            .collect();
        paths.sort_unstable();
        assert_eq!(
            paths,
            vec![
                "mcp.capabilities.resources[].backend.allow_private_backends: true",
                "mcp.capabilities.tools[].backend.allow_private_backends: true",
            ]
        );
    }

    #[test]
    fn rejects_federation_upstream_with_private_ip_host() {
        for url in [
            "http://10.0.0.5:9000/mcp",
            "https://127.0.0.1/mcp",
            "http://169.254.169.254/latest/meta-data", // cloud metadata
            "http://192.168.1.1:8080/mcp",
            "http://[::1]:9000/mcp",
            "http://[fd00::1]/mcp", // ULA
            "https://localhost/mcp",
            "https://db.internal/mcp",
            "http://metadata.google.internal/computeMetadata/v1/",
        ] {
            let cfg = format!(
                r#"
                mcp:
                  federations:
                    - name: internal
                      upstream:
                        url: "{url}"
                "#
            );
            let err = match check_published_config(&cfg) {
                Ok(()) => panic!("expected rejection for {url}"),
                Err(e) => e,
            };
            assert!(
                err.violations
                    .iter()
                    .any(|v| v.kind == "private_federation_upstream"),
                "expected private_federation_upstream for {url}, got {:?}",
                err.violations
            );
        }
    }

    #[test]
    fn allows_federation_upstream_with_public_host() {
        let cfg = r#"
            mcp:
              federations:
                - name: partner
                  upstream:
                    url: "https://mcp.partner.com/mcp"
        "#;
        assert!(check_published_config(cfg).is_ok());
    }

    #[test]
    fn allows_tunnel_upstream_as_the_sanctioned_private_path() {
        // `tunnel://<name>` egresses through the authenticated relay, not a raw
        // private IP — it is the sanctioned same-org private path, not SSRF.
        let cfg = r#"
            mcp:
              federations:
                - name: private-gw
                  upstream:
                    url: "tunnel://acme-internal/mcp"
        "#;
        assert!(check_published_config(cfg).is_ok());
    }

    #[test]
    fn gated_upstream_host_extracts_host_across_forms() {
        assert_eq!(gated_upstream_host("https://h/mcp").as_deref(), Some("h"));
        assert_eq!(
            gated_upstream_host("http://user:pw@10.0.0.1:80/x").as_deref(),
            Some("10.0.0.1")
        );
        assert_eq!(
            gated_upstream_host("wss://[fe80::1]:443/mcp").as_deref(),
            Some("fe80::1")
        );
        assert_eq!(
            gated_upstream_host("https://host.example.com?q=1").as_deref(),
            Some("host.example.com")
        );
        // Non-network schemes are not gated here.
        assert_eq!(gated_upstream_host("tunnel://name/mcp"), None);
        assert_eq!(gated_upstream_host("stdio://"), None);
        assert_eq!(gated_upstream_host("not a url"), None);
    }

    #[test]
    fn is_private_or_local_host_classifies() {
        for host in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.0.1",
            "172.16.0.1",
            "169.254.169.254",
            "0.0.0.0",
            "::1",
            "fd12:3456::1",
            "fe80::1",
            "localhost",
            "svc.local",
            "db.internal",
            "metadata.google.internal",
            "LOCALHOST",
        ] {
            assert!(is_private_or_local_host(host), "{host} should be private");
        }
        for host in [
            "8.8.8.8",
            "1.1.1.1",
            "203.0.113.10",
            "2606:4700:4700::1111",
            "api.example.com",
            "mcp.partner.io",
        ] {
            assert!(!is_private_or_local_host(host), "{host} should be public");
        }
    }
}
