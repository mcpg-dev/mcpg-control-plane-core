//! Pre-deploy guard for tenant-published gateway configs.
//!
//! In the managed service a tenant publishes a config that the platform runs
//! **in the tenant's own pod**. That makes the published config "config-origin"
//! — the position the gateway trusts for credential + environment resolution.
//! Two of those resolutions read host resources at config-load time and must
//! NOT be reachable from a tenant-authored config:
//!
//! - **CEL env interpolation** `${env.X}` — expanded against the POD's
//!   environment at load (see `libs/expr`). A tenant could read platform
//!   pod-env (the enrollment URL, the cluster material, downward-API values)
//!   this way.
//! - **`env://` / `file://` secret-provider URIs** — resolve against pod env /
//!   filesystem. Same host-read exfil surface.
//!
//! The tenant's own values travel a separate channel: a key registered
//! through the control plane is mounted into the pod as a file and read as
//! `${secret.NAME}`. The guard admits exactly the registered names
//! ([`check_published_config_with_secret_keys`]); an unregistered one would
//! fail at load, so it is refused here where the publisher can act on it.
//! [`is_secret_key`] is the one grammar every side applies to a name.
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
//!
//! Licensing is the platform's on the managed service, so a `license:` block
//! in a published config is refused outright: the org's claims come from the
//! control plane, never from the config it admits.
//!
//! [`check_config_entitlements`] is the license half, read against the org's
//! claims: a config block whose surface a plan feature withholds (interactive
//! sign-in needs `sso.interactive_login`, DPoP `oauth.dpop`, rich
//! authorization requests `oauth.rich_authorization`), a `plugins[]` entry the
//! plan does not entitle, and — without `plugins.custom` — any plugin source
//! outside the first-party registry or any registry or trust setting that
//! could reach one. [`check_plugin_quota`] caps the entries at
//! `quotas.plugins`, and [`check_event_type_quota`] the declared MCP Events
//! types at `quotas.event_types`. Plugins the platform adds itself
//! ([`PLATFORM_INJECTED_PLUGINS`]) are outside the quota, and pass the
//! entitlement check where the licence admits them as the platform's, as the
//! gateway's own gate does. What the platform accepts but replaces in the
//! render is reported, not refused ([`managed_publish_warnings`]).

use std::collections::BTreeSet;
use std::fmt;

use mcpg_control_plane_license::license::LicenseClaims;

/// A single rejected construct, with enough context for a useful CLI/API error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    /// Machine-stable kind (`host_env_interpolation`, `unregistered_secret`,
    /// `host_secret_uri`, `malformed_cred_token`, `license_block`,
    /// `feature_not_licensed`, `plugin_not_entitled`, `plugin_quota_exceeded`, …).
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

/// Longest secret key a tenant may register.
pub const SECRET_KEY_MAX_LEN: usize = 64;

/// Whether `name` is a well-formed secret key: `[A-Za-z_][A-Za-z0-9_]{0,63}`
/// — a CEL identifier, which is also a file name under the mounted secret
/// directory. Case-sensitive, refused rather than normalised: a key that
/// needed lowercasing or trimming to fit is not the key the config names.
/// The control plane applies it at registration, the guard when a config
/// references a key, and the provisioner and gateway again on delivery.
pub fn is_secret_key(name: &str) -> bool {
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    name.len() <= SECRET_KEY_MAX_LEN
        && (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Digest of a secret set: hex sha256 over `NAME=VALUE\n` for every key in
/// sorted order. The control plane computes it over the registered set, the
/// provisioner over what it delivered, and the gateway over what it resolved,
/// so "live" versus "pending" is a comparison of digests — no side ever sends
/// a value. Empty when there are no keys, which is also what a gateway
/// reports when it resolves no `${secret.*}` reference.
pub fn secrets_digest<'a>(secrets: impl IntoIterator<Item = (&'a str, &'a str)>) -> String {
    use sha2::Digest as _;
    let mut entries: Vec<(&str, &str)> = secrets.into_iter().collect();
    if entries.is_empty() {
        return String::new();
    }
    entries.sort_unstable();
    let mut hasher = sha2::Sha256::new();
    for (name, value) in entries {
        hasher.update(name.as_bytes());
        hasher.update(b"=");
        hasher.update(value.as_bytes());
        hasher.update(b"\n");
    }
    hex::encode(hasher.finalize())
}

/// CEL env-interpolation opener, matching `libs/expr`'s parser.
const ENV_OPENERS: [&str; 1] = ["${env."];
/// Tenant-secret interpolation opener (`${secret.NAME}`), resolved by the
/// gateway from its mounted secret directory.
const SECRET_OPENER: &str = "${secret.";
/// Credential-token opener (`${cred://plugin/target}`).
const CRED_OPENER: &str = "${cred://";
/// Secret-provider URI schemes that read POD-local host resources. Both carry
/// `//`, so they can't collide with a YAML/TOML key named `env`/`file`.
const HOST_SECRET_SCHEMES: [&str; 2] = ["env://", "file://"];
/// The one key that turns off the private-address pin, wherever it appears.
const PRIVATE_BACKENDS_KEY: &str = "allow_private_backends";
/// The `governance.access` blocks the gateway verifies bearer tokens with —
/// the same set its `AccessConfig::is_enabled` reads.
const VERIFIER_KEYS: [&str; 3] = ["jwks", "oidc_oauth", "authorization_server"];

/// Validate a raw tenant-published config (YAML or TOML text). Returns the full
/// set of violations so the operator sees every problem at once, not one per
/// round-trip.
pub fn check_published_config(raw: &str) -> Result<(), PublishGuardError> {
    check_published_config_with_secret_keys(raw, &BTreeSet::new())
}

/// [`check_published_config`] with the tenant's registered secret keys: a
/// `${secret.X}` is admitted iff `X` is in `secret_keys` and refused as
/// `unregistered_secret` otherwise — the gateway would fail to load a config
/// naming a key its mount does not hold, and the publisher can act on it
/// here. `${env.…}` stays refused whatever the set holds: the pod's
/// environment is the platform's, and the tenant's values are files, not
/// variables.
pub fn check_published_config_with_secret_keys(
    raw: &str,
    secret_keys: &BTreeSet<String>,
) -> Result<(), PublishGuardError> {
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
    walk_leaf_strings(&cfg, &mut |leaf| {
        check_leaf_value(leaf, secret_keys, &mut violations)
    });
    check_ssrf(&cfg, &mut violations);
    check_license_block(&cfg, &mut violations);
    check_events(&cfg, &mut violations);

    if violations.is_empty() {
        Ok(())
    } else {
        Err(PublishGuardError { violations })
    }
}

/// Refuse the MCP Events settings a managed gateway must not run with: a
/// subscription that never expires, a subscriber trust floor below a
/// verified principal, a callback proof other than the signed challenge
/// (the allowlist and the receiver document trust what the tenant names),
/// a callback port other than 443 (the managed egress opens 443 only), and
/// an inbound source that accepts unsigned requests.
fn check_events(cfg: &serde_json::Value, violations: &mut Vec<Violation>) {
    const WEBHOOK: &str = "mcp.configurations.events.webhook";
    let mut refuse = |kind: &'static str, snippet: String| {
        violations.push(Violation { kind, snippet });
    };
    // Every delivery mode has its own floor, and each reaches subscribers.
    for mode in ["webhook", "poll", "push"] {
        if let Some(trust) = cfg
            .pointer(&format!("/mcp/configurations/events/{mode}/require_trust"))
            .and_then(|v| v.as_str())
            && trust != "verified"
        {
            refuse(
                "events_trust_floor",
                format!(
                    "mcp.configurations.events.{mode}.require_trust: {}",
                    truncate(trust)
                ),
            );
        }
    }
    if let Some(webhook) = cfg.pointer("/mcp/configurations/events/webhook") {
        if webhook.pointer("/ttl/allow_no_expiry") == Some(&serde_json::Value::Bool(true)) {
            refuse("events_no_expiry", format!("{WEBHOOK}.ttl.allow_no_expiry"));
        }
        if let Some(modes) = webhook
            .pointer("/verification/modes")
            .and_then(|v| v.as_array())
        {
            for mode in modes.iter().filter_map(|m| m.as_str()) {
                if mode != "challenge" {
                    refuse(
                        "events_verification_mode",
                        format!("{WEBHOOK}.verification.modes: {}", truncate(mode)),
                    );
                }
            }
        }
        if let Some(ports) = webhook
            .pointer("/egress/allowed_ports")
            .and_then(|v| v.as_array())
            && *ports != [serde_json::json!(443)]
        {
            refuse(
                "events_callback_ports",
                format!("{WEBHOOK}.egress.allowed_ports"),
            );
        }
    }
    if let Some(types) = cfg
        .pointer("/mcp/capabilities/events")
        .and_then(|v| v.as_array())
    {
        for (index, ty) in types.iter().enumerate() {
            if ty.pointer("/source/inbound/allow_unsigned") == Some(&serde_json::Value::Bool(true))
            {
                let name = ty
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(|n| format!("`{}`", truncate(n)))
                    .unwrap_or_else(|| index.to_string());
                refuse(
                    "events_unsigned_inbound",
                    format!("mcp.capabilities.events[{name}].source.inbound.allow_unsigned"),
                );
            }
        }
    }
}

/// Refuse a `license:` block. A token, a public key or `non_production_use`
/// would give the gateway a licence answer the tenant chose; on the managed
/// service the org's claims are the only one. A key with no value sets nothing.
fn check_license_block(cfg: &serde_json::Value, violations: &mut Vec<Violation>) {
    if cfg.get("license").is_some_and(|v| !v.is_null()) {
        violations.push(Violation {
            kind: "license_block",
            snippet: "license".to_owned(),
        });
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

/// Run the host-read and secret-reference checks against one leaf string value.
fn check_leaf_value(value: &str, secret_keys: &BTreeSet<String>, violations: &mut Vec<Violation>) {
    // 1. Host-env interpolation `${env.X}` — every name reads the pod's own
    //    environment.
    for opener in ENV_OPENERS {
        for snippet in tokens_from(value, opener, '}') {
            violations.push(Violation {
                kind: "host_env_interpolation",
                snippet,
            });
        }
    }

    // 1b. Tenant-secret interpolation `${secret.X}` — admitted only for a key
    //     registered for this gateway. The grammar sits in front of the set:
    //     a name outside it is not a file the gateway would read, whatever a
    //     caller lists.
    for snippet in tokens_from(value, SECRET_OPENER, '}') {
        let name = snippet
            .strip_prefix(SECRET_OPENER)
            .and_then(|s| s.strip_suffix('}'))
            .unwrap_or_default();
        if is_secret_key(name) && secret_keys.contains(name) {
            continue;
        }
        violations.push(Violation {
            kind: "unregistered_secret",
            snippet,
        });
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

/// The config surfaces a license feature withholds, as
/// `(feature, dotted path of the block that needs it)`. Only a present,
/// non-null block counts, as with the verifier blocks, and only when it turns
/// its surface on, as the gateway reads it: `dpop` with `enabled: true` (a
/// boolean), `authorization_details` with a non-empty `types` list.
pub fn licensed_config_surfaces(cfg: &serde_json::Value) -> Vec<(&'static str, String)> {
    use mcpg_control_plane_license::license::{
        FEATURE_DPOP, FEATURE_EVENTS_WEBHOOKS, FEATURE_INTERACTIVE_LOGIN,
        FEATURE_RICH_AUTHORIZATION,
    };
    const SERVER: &str = "governance.access.authorization_server";
    let mut surfaces = Vec::new();
    // Webhook delivery is on by default once events are enabled.
    if let Some(events) = cfg.pointer("/mcp/configurations/events")
        && events.get("enabled") == Some(&serde_json::Value::Bool(true))
        && events.pointer("/webhook/enabled") != Some(&serde_json::Value::Bool(false))
    {
        surfaces.push((
            FEATURE_EVENTS_WEBHOOKS,
            "mcp.configurations.events.webhook".to_owned(),
        ));
    }
    let Some(server) = cfg.pointer("/governance/access/authorization_server") else {
        return surfaces;
    };
    if let Some(idps) = server.get("trusted_idps").and_then(|v| v.as_array()) {
        for (index, idp) in idps.iter().enumerate() {
            if is_present_object(idp.get("login")) {
                let at = match idp.get("issuer").and_then(|v| v.as_str()) {
                    Some(issuer) => format!("{SERVER}.trusted_idps[`{}`].login", truncate(issuer)),
                    None => format!("{SERVER}.trusted_idps[{index}].login"),
                };
                surfaces.push((FEATURE_INTERACTIVE_LOGIN, at));
            }
        }
    }
    if is_present_object(server.get("interactive")) {
        surfaces.push((FEATURE_INTERACTIVE_LOGIN, format!("{SERVER}.interactive")));
    }
    if server.pointer("/dpop/enabled") == Some(&serde_json::Value::Bool(true)) {
        surfaces.push((FEATURE_DPOP, format!("{SERVER}.dpop")));
    }
    if server
        .pointer("/authorization_details/types")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|types| !types.is_empty())
    {
        surfaces.push((
            FEATURE_RICH_AUTHORIZATION,
            format!("{SERVER}.authorization_details"),
        ));
    }
    surfaces
}

/// Refuse a published config the org's license does not cover:
///
/// - a surface of the embedded authorization server a plan feature withholds
///   (interactive sign-in needs `sso.interactive_login`, DPoP `oauth.dpop`,
///   rich authorization requests `oauth.rich_authorization`);
/// - a `plugins[]` entry whose `id` or `ref`
///   [`plugin_load_violation`](mcpg_control_plane_license::license::plugin_load_violation)
///   refuses — `plugin_not_entitled` outside the plan's envelope,
///   `feature_not_licensed` for a plugin whose feature the plan lacks — other
///   than the platform's coordinator under a licence that admits it
///   ([`admits_platform_coordinator`](mcpg_control_plane_license::license::admits_platform_coordinator));
/// - without `plugins.custom`, every plugin source outside the first-party
///   registry and every registry or trust setting that could reach one
///   ([`custom_plugin_surfaces`]).
///
/// Runs on the managed-cloud publish path with the org's live claims; the
/// gateway applies the authorization-server rule at boot to every config the
/// platform did not render. Unparseable input fails closed.
pub fn check_config_entitlements(
    raw: &str,
    claims: &LicenseClaims,
) -> Result<(), PublishGuardError> {
    let Some(cfg) = parse_structured(raw) else {
        return Err(unparseable());
    };
    let mut violations: Vec<Violation> = licensed_config_surfaces(&cfg)
        .into_iter()
        .filter(|(feature, _)| !claims.has_feature(feature))
        .map(|(feature, path)| Violation {
            kind: "feature_not_licensed",
            snippet: not_granted(&path, feature, &claims.plan),
        })
        .collect();
    check_plugin_entitlements(&cfg, claims, &mut violations);
    if !allows_custom_plugins(claims) {
        use mcpg_control_plane_license::license::FEATURE_CUSTOM_PLUGINS;
        violations.extend(
            custom_plugin_surfaces(&cfg)
                .into_iter()
                .map(|path| Violation {
                    kind: "feature_not_licensed",
                    snippet: not_granted(&path, FEATURE_CUSTOM_PLUGINS, &claims.plan),
                }),
        );
    }
    if violations.is_empty() {
        Ok(())
    } else {
        Err(PublishGuardError { violations })
    }
}

/// Refuse a published config that lists more `plugins[]` entries than
/// `quotas.plugins` (`0` is unlimited). The quota also caps a workspace's
/// plugin sets; however it is summed, one config above it is over it. An
/// entry that loads one of the [`PLATFORM_INJECTED_PLUGINS`] is not counted;
/// one that only borrows its name as an alias is. Unparseable input fails
/// closed.
pub fn check_plugin_quota(raw: &str, claims: &LicenseClaims) -> Result<(), PublishGuardError> {
    let Some(cfg) = parse_structured(raw) else {
        return Err(unparseable());
    };
    let limit = claims.quotas.plugins;
    let listed = cfg
        .get("plugins")
        .and_then(serde_json::Value::as_array)
        .map_or(0, |entries| {
            entries
                .iter()
                .filter(|e| !loads_platform_injected_plugin(e))
                .count()
        }) as u64;
    if limit == 0 || listed <= limit {
        return Ok(());
    }
    Err(PublishGuardError {
        violations: vec![Violation {
            kind: "plugin_quota_exceeded",
            snippet: format!(
                "plugins lists {listed} entries and plan `{}` includes {limit}",
                claims.plan
            ),
        }],
    })
}

/// Refuse a published config that declares more MCP Events types under
/// `mcp.capabilities.events` than the plan serves (`event_types`, `0` is
/// unlimited). Imported types are not in the config; the gateway serves
/// those within what the declared ones leave. Unparseable input fails
/// closed.
pub fn check_event_type_quota(raw: &str, claims: &LicenseClaims) -> Result<(), PublishGuardError> {
    let Some(cfg) = parse_structured(raw) else {
        return Err(unparseable());
    };
    let limit = claims.quotas.event_types_for(&claims.plan);
    let declared = cfg
        .pointer("/mcp/capabilities/events")
        .and_then(serde_json::Value::as_array)
        .map_or(0, Vec::len) as u64;
    if limit == 0 || declared <= limit {
        return Ok(());
    }
    Err(PublishGuardError {
        violations: vec![Violation {
            kind: "event_type_quota_exceeded",
            snippet: format!(
                "mcp.capabilities.events declares {declared} event types and plan `{}` serves {limit}",
                claims.plan
            ),
        }],
    })
}

/// Whether `claims` admit plugins the customer publishes themselves, and the
/// registry and trust settings that reach them. The plan counts as well as
/// the flag, so a licence pinned before `plugins.custom` joined its plan keeps
/// what the plan sold.
pub fn allows_custom_plugins(claims: &LicenseClaims) -> bool {
    use mcpg_control_plane_license::license::FEATURE_CUSTOM_PLUGINS;
    claims.has_feature(FEATURE_CUSTOM_PLUGINS)
        || mcpg_control_plane_license::license::allows_custom_plugins(&claims.plan)
}

/// The signature policy every managed gateway runs by default: the managed
/// render sets it whatever the published config says, so an artefact loads
/// only when a trusted key signed it.
pub const MANAGED_SIGNATURE_POLICY: &str = "enforce";

/// `gateway.plugin_registry` keys that never change where an artefact comes
/// from or which key vouches for it, so every plan may set them. The default
/// signature policy is among them because the managed render replaces it
/// with [`MANAGED_SIGNATURE_POLICY`].
const REGISTRY_KEYS_ANY_PLAN: [&str; 4] = [
    "cache_dir",
    "revocation_list_path",
    "require_integrity_anchor",
    "default_signature_policy",
];

/// Every place a config reaches a plugin the platform did not publish, as a
/// dotted path: a `source.oci` outside the first-party registry, a per-entry
/// `signature.trusted_keys`, a per-entry `signature.policy` other than
/// [`MANAGED_SIGNATURE_POLICY`] (it would load an artefact no trusted key
/// signed), and any `gateway.plugin_registry` key beyond
/// [`REGISTRY_KEYS_ANY_PLAN`] (a mirror, a default registry, trusted keys,
/// credentials, TLS, a plain-HTTP registry). A key present with no value —
/// null, `[]` or `{}` — sets nothing and is not listed. A `source.path` names
/// a file in the image, which [`crate::target_validate`] checks against the
/// release.
pub fn custom_plugin_surfaces(cfg: &serde_json::Value) -> Vec<String> {
    use crate::target_validate::is_first_party_plugin_ref;
    let mut surfaces = Vec::new();
    if let Some(registry) = cfg
        .pointer("/gateway/plugin_registry")
        .and_then(serde_json::Value::as_object)
    {
        for (key, value) in registry {
            if !REGISTRY_KEYS_ANY_PLAN.contains(&key.as_str()) && sets_something(value) {
                surfaces.push(format!("gateway.plugin_registry.{key}"));
            }
        }
    }
    let Some(entries) = cfg.get("plugins").and_then(serde_json::Value::as_array) else {
        return surfaces;
    };
    for (index, entry) in entries.iter().enumerate() {
        if let Some(oci) = entry.pointer("/source/oci").and_then(|v| v.as_str())
            && !is_first_party_plugin_ref(oci)
        {
            surfaces.push(format!("plugins[{index}].source.oci `{}`", truncate(oci)));
        }
        if entry
            .pointer("/signature/trusted_keys")
            .is_some_and(sets_something)
        {
            surfaces.push(format!("plugins[{index}].signature.trusted_keys"));
        }
        if let Some(policy) = entry
            .pointer("/signature/policy")
            .filter(|v| sets_something(v))
            .filter(|v| v.as_str() != Some(MANAGED_SIGNATURE_POLICY))
        {
            let shown = policy
                .as_str()
                .map_or_else(|| policy.to_string(), str::to_owned);
            surfaces.push(format!(
                "plugins[{index}].signature.policy `{}`",
                truncate(&shown)
            ));
        }
    }
    surfaces
}

/// Plugins the managed platform adds to a render itself: the coordinator
/// behind the `cluster` block it renders for an instance with more than one
/// replica. The platform, not the tenant's plan, decides that they run, so
/// they are outside the tenant's plugin quota; without the platform's
/// `cluster` block nothing selects them. Whether a licence admits one is the
/// gateway's rule, [`admits_platform_coordinator`], which the entitlement
/// check applies too: a config the publish admits must load.
///
/// [`admits_platform_coordinator`]: mcpg_control_plane_license::license::admits_platform_coordinator
pub const PLATFORM_INJECTED_PLUGINS: [&str; 1] =
    [mcpg_control_plane_license::license::PLATFORM_COORDINATOR_PLUGIN];

/// Whether `plugin` is one of [`PLATFORM_INJECTED_PLUGINS`].
pub fn is_platform_injected_plugin(plugin: &str) -> bool {
    PLATFORM_INJECTED_PLUGINS.contains(&plugin)
}

/// Whether a `plugins[]` entry loads a platform-injected plugin: its manifest
/// id — the `ref`, else the `id` — is one of them. With a `ref`, the `id` is
/// only an alias, and the gateway loads the artefact the `ref` names.
fn loads_platform_injected_plugin(entry: &serde_json::Value) -> bool {
    entry
        .get("ref")
        .and_then(serde_json::Value::as_str)
        .or_else(|| entry.get("id").and_then(serde_json::Value::as_str))
        .is_some_and(is_platform_injected_plugin)
}

/// Run [`plugin_load_violation`] over every `plugins[]` entry's `id` and,
/// when it differs, its `ref`, except the platform's coordinator where the
/// licence admits it as such ([`admits_platform_coordinator`]).
/// Disabled entries are checked too, so the verdict never rests on the
/// gateway honouring the flag. A tenant `cluster` block names no plugin: the
/// managed render replaces it ([`managed_publish_warnings`]).
///
/// [`plugin_load_violation`]: mcpg_control_plane_license::license::plugin_load_violation
/// [`admits_platform_coordinator`]: mcpg_control_plane_license::license::admits_platform_coordinator
fn check_plugin_entitlements(
    cfg: &serde_json::Value,
    claims: &LicenseClaims,
    violations: &mut Vec<Violation>,
) {
    let Some(entries) = cfg.get("plugins").and_then(serde_json::Value::as_array) else {
        return;
    };
    for (index, entry) in entries.iter().enumerate() {
        let id = entry.get("id").and_then(serde_json::Value::as_str);
        let reference = entry
            .get("ref")
            .and_then(serde_json::Value::as_str)
            .filter(|r| Some(*r) != id);
        let named = [
            (format!("plugins[{index}]"), id),
            (format!("plugins[{index}].ref"), reference),
        ];
        for (at, plugin) in named {
            if let Some(plugin) = plugin.filter(|p| {
                !mcpg_control_plane_license::license::admits_platform_coordinator(claims, p)
            }) {
                check_plugin(claims, &at, plugin, violations);
            }
        }
    }
}

/// What a managed publish accepts but does not run as written, one sentence
/// each, for the publish answer. The platform owns the `cluster` block — it
/// renders its own coordinator for an instance with more than one replica
/// and none for one — and renders `gateway.plugin_registry.
/// default_signature_policy` as [`MANAGED_SIGNATURE_POLICY`]. Empty for a
/// config that sets nothing the platform replaces, and for one that does not
/// parse (the guards refuse that).
pub fn managed_publish_warnings(raw: &str) -> Vec<String> {
    let Some(cfg) = parse_structured(raw) else {
        return Vec::new();
    };
    let mut warnings = Vec::new();
    if cfg.get("cluster").is_some_and(sets_something) {
        warnings.push(
            "`cluster` is ignored: on the managed service the platform owns clustering and \
             supplies the coordinator of an instance with more than one replica"
                .to_owned(),
        );
    }
    if let Some(policy) = cfg
        .pointer("/gateway/plugin_registry/default_signature_policy")
        .filter(|v| sets_something(v))
        .filter(|v| v.as_str() != Some(MANAGED_SIGNATURE_POLICY))
    {
        let shown = policy
            .as_str()
            .map_or_else(|| policy.to_string(), str::to_owned);
        warnings.push(format!(
            "`gateway.plugin_registry.default_signature_policy: {}` is ignored: managed \
             gateways verify plugin signatures (`{MANAGED_SIGNATURE_POLICY}`)",
            truncate(&shown)
        ));
    }
    warnings
}

/// Record why `claims` may not load `plugin`, named at config path `at`.
fn check_plugin(claims: &LicenseClaims, at: &str, plugin: &str, violations: &mut Vec<Violation>) {
    use mcpg_control_plane_license::license::{LicenseError, plugin_load_violation};
    let at = format!("{at} `{}`", truncate(plugin));
    match plugin_load_violation(claims, plugin) {
        None => {}
        Some(LicenseError::FeatureNotLicensed { feature, .. }) => {
            violations.push(Violation {
                kind: "feature_not_licensed",
                snippet: not_granted(&at, &feature, &claims.plan),
            });
        }
        Some(_) => violations.push(Violation {
            kind: "plugin_not_entitled",
            snippet: format!(
                "{at} is not among the plugins plan `{}` entitles",
                claims.plan
            ),
        }),
    }
}

/// Whether a config value turns something on: anything but null, `[]` or `{}`.
fn sets_something(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => false,
        serde_json::Value::Array(items) => !items.is_empty(),
        serde_json::Value::Object(map) => !map.is_empty(),
        _ => true,
    }
}

fn not_granted(path: &str, feature: &str, plan: &str) -> String {
    format!("{path} needs the `{feature}` license feature, which plan `{plan}` does not grant")
}

fn unparseable() -> PublishGuardError {
    PublishGuardError {
        violations: vec![Violation {
            kind: "unparseable_config",
            snippet: "config is not valid YAML or TOML".to_owned(),
        }],
    }
}

/// Why a cloud publish was refused for lacking authentication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CloudAuthError {
    /// No token verifier (`governance.access.jwks` / `oidc_oauth` /
    /// `authorization_server`) is configured and the tenant did not
    /// explicitly opt into an anonymous gateway (`cloud.allow_anonymous: true`).
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
                 `governance.access.oidc_oauth`) to your IdP, or configure the embedded \
                 enterprise-managed authorization server (`governance.access.authorization_server`). \
                 To intentionally publish a public / anonymous MCP server, set \
                 `cloud.allow_anonymous: true`."
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
/// when `governance.access.jwks`, `governance.access.oidc_oauth` or the
/// embedded `governance.access.authorization_server` is configured (mirrors
/// the gateway's `AccessConfig::is_enabled`); with none, the default trust
/// floor admits self-asserted (`HeaderAsserted`) callers.
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

    // A configured verifier under `governance.access` — presence of any of
    // these keys as an object is exactly what flips the gateway's
    // `is_enabled()` to true.
    let access = cfg.pointer("/governance/access");
    let has_verifier = access.is_some_and(|a| {
        VERIFIER_KEYS
            .iter()
            .any(|key| is_present_object(a.get(*key)))
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
/// `jwks: {}` / `oidc_oauth: {...}` / `authorization_server: {...}` as "auth
/// enabled" — a present, non-null block). `null` / absent / scalar ⇒ not a
/// verifier.
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

    fn keys(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|k| (*k).to_owned()).collect()
    }

    /// A `${secret.X}` config reference, inline in a larger string.
    fn secret_ref_config(name: &str) -> String {
        format!(
            "mcp:\n  capabilities:\n    tools:\n      - name: t\n        backend:\n          kind: http\n          headers:\n            authorization: \"Bearer ${{secret.{name}}}\"\n"
        )
    }

    /// A registered key is admitted as `${secret.X}`; an unregistered one is
    /// refused with its own kind and the token as the snippet.
    #[test]
    fn a_registered_secret_key_is_admitted_and_an_unregistered_one_is_refused() {
        let registered = keys(&["API_TOKEN"]);
        assert!(
            check_published_config_with_secret_keys(&secret_ref_config("API_TOKEN"), &registered)
                .is_ok()
        );
        let err = check_published_config_with_secret_keys(&secret_ref_config("OTHER"), &registered)
            .expect_err("an unregistered key is refused");
        assert_eq!(
            err.violations,
            vec![Violation {
                kind: "unregistered_secret",
                snippet: "${secret.OTHER}".to_owned(),
            }]
        );
        // Case-sensitive: the file the gateway would open is `API_TOKEN`.
        let err =
            check_published_config_with_secret_keys(&secret_ref_config("api_token"), &registered)
                .unwrap_err();
        assert_eq!(err.violations[0].kind, "unregistered_secret");
        // A name outside the grammar can never be registered, so it is
        // unregistered even when a caller lists it.
        let err = check_published_config_with_secret_keys(
            &secret_ref_config(" API_TOKEN"),
            &keys(&[" API_TOKEN"]),
        )
        .unwrap_err();
        assert_eq!(err.violations[0].kind, "unregistered_secret");
        // The plain entry point admits no secret reference at all.
        let err = check_published_config(&secret_ref_config("API_TOKEN")).unwrap_err();
        assert_eq!(err.violations[0].kind, "unregistered_secret");
        // Every reference in a value is reported, and the other guards keep
        // running alongside.
        let mixed = format!(
            "{}          token: \"${{secret.A}}:${{secret.B}}\"\n          ca: file:///etc/x\n",
            secret_ref_config("API_TOKEN")
        );
        let err = check_published_config_with_secret_keys(&mixed, &keys(&["API_TOKEN", "B"]))
            .unwrap_err();
        // Leaf order follows map iteration and is not part of the contract.
        let mut found: Vec<(&str, &str)> = err
            .violations
            .iter()
            .map(|v| (v.kind, v.snippet.as_str()))
            .collect();
        found.sort_unstable();
        assert_eq!(
            found,
            vec![
                ("host_secret_uri", "file:///etc/x"),
                ("unregistered_secret", "${secret.A}"),
            ],
            "{err}"
        );
    }

    /// `${env.…}` is the pod's environment, never the tenant's channel: it is
    /// refused whatever is registered, including a name that IS registered.
    #[test]
    fn env_interpolation_is_refused_even_for_a_registered_key() {
        let cfg = |name: &str| {
            format!(
                "mcp:\n  capabilities:\n    tools:\n      - name: t\n        backend:\n          kind: http\n          headers:\n            authorization: \"Bearer ${{env.{name}}}\"\n"
            )
        };
        for name in ["TENANT_X", "API_TOKEN", "MCPG_CP_ENROLLMENT_URL", "PATH"] {
            let err = check_published_config_with_secret_keys(&cfg(name), &keys(&[name]))
                .expect_err(name);
            assert_eq!(err.violations[0].kind, "host_env_interpolation", "{name}");
            assert_eq!(err.violations[0].snippet, format!("${{env.{name}}}"));
        }
    }

    #[test]
    fn secret_key_grammar() {
        for ok in [
            "A",
            "_",
            "API_TOKEN",
            "api_token",
            "TENANT_S3_SECRET_KEY",
            "camelCase9",
            "_leading",
            "a1",
            &"A".repeat(SECRET_KEY_MAX_LEN),
        ] {
            assert!(is_secret_key(ok), "{ok}");
        }
        for bad in [
            "",
            "1A",
            "9",
            "A-B",
            "A B",
            " A",
            "A ",
            "A.B",
            "A/B",
            "../A",
            "Ä",
            "A\n",
            &"A".repeat(SECRET_KEY_MAX_LEN + 1),
        ] {
            assert!(!is_secret_key(bad), "{bad:?} must be refused");
        }
    }

    /// The digest is order-independent, value-sensitive, and empty for an
    /// empty set — the same three properties every side relies on.
    #[test]
    fn secrets_digest_recipe() {
        use sha2::Digest as _;
        assert_eq!(secrets_digest(std::iter::empty()), "");
        let expected = hex::encode(sha2::Sha256::digest(b"API_TOKEN=t0k\nSIGNING_KEY=k3y\n"));
        assert_eq!(
            secrets_digest([("SIGNING_KEY", "k3y"), ("API_TOKEN", "t0k")]),
            expected
        );
        assert_eq!(
            secrets_digest([("API_TOKEN", "t0k"), ("SIGNING_KEY", "k3y")]),
            expected
        );
        assert_ne!(
            secrets_digest([("API_TOKEN", "t0k"), ("SIGNING_KEY", "k3y!")]),
            expected
        );
        assert_ne!(secrets_digest([("API_TOKEN", "t0k")]), expected);
    }

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

    /// The embedded enterprise-managed authorization server verifies the
    /// tokens it mints, so it is a verifier on its own — no JWKS or OIDC
    /// block and no anonymous opt-out needed.
    #[test]
    fn cloud_auth_allows_embedded_authorization_server() {
        let cfg = r#"
            governance:
              access:
                resource_metadata:
                  resource: "https://edge-1.mcpg.cloud/mcp"
                authorization_server:
                  issuer: "https://edge-1.mcpg.cloud"
                  signing_secret: "${secret.EMA_SIGNING_SECRET}"
                  trusted_idps:
                    - issuer: "https://acme.okta.com"
                  clients:
                    - client_id: "mcp-client"
                      client_secret: "${secret.MCP_CLIENT_SECRET}"
        "#;
        assert!(require_cloud_auth(cfg).is_ok());
        let toml_cfg = r#"
[governance.access.authorization_server]
issuer = "https://edge-1.mcpg.cloud"
signing_secret = "${secret.EMA_SIGNING_SECRET}"
"#;
        assert!(require_cloud_auth(toml_cfg).is_ok());
    }

    /// Only a present block counts: an empty `access` map, a bare
    /// `authorization_server:` (null) or a scalar is no verifier.
    #[test]
    fn cloud_auth_treats_an_absent_or_null_authorization_server_as_no_verifier() {
        for cfg in [
            "governance:\n  access: {}\n",
            "governance:\n  access:\n    authorization_server:\n",
            "governance:\n  access:\n    authorization_server: \"https://edge-1.mcpg.cloud\"\n",
        ] {
            assert_eq!(
                require_cloud_auth(cfg),
                Err(CloudAuthError::NoVerifier),
                "{cfg}"
            );
        }
    }

    fn claims_for(plan: &str) -> LicenseClaims {
        let mut claims = LicenseClaims::community("mcpg-cp");
        let (entitlements, quotas) = mcpg_control_plane_license::license::plan_envelope(plan);
        claims.plan = plan.to_owned();
        claims.plugin_entitlements = entitlements;
        claims.quotas = quotas;
        claims.features = mcpg_control_plane_license::license::features_for(plan);
        claims
    }

    /// A managed gateway runs MCP Events only with expiring subscriptions,
    /// verified subscribers, the signed challenge, callbacks on 443 and
    /// signed inbound sources.
    #[test]
    fn refuses_the_events_settings_a_managed_gateway_must_not_run() {
        let cfg = r#"
mcp:
  configurations:
    events:
      enabled: true
      webhook:
        require_trust: header_asserted
        ttl: { allow_no_expiry: true }
        verification: { modes: [challenge, allowlist, well_known], allowlist: [hooks.example.com] }
        egress: { allowed_ports: [443, 8443] }
      poll: { require_trust: header_asserted }
      push: { require_trust: header_asserted }
  capabilities:
    events:
      - name: orders.created
        source: { inbound: { source_id: orders, allow_unsigned: true } }
"#;
        let err = check_published_config(cfg).unwrap_err();
        let kinds: Vec<&str> = found(&err).iter().map(|(k, _)| *k).collect();
        assert_eq!(
            kinds,
            [
                "events_callback_ports",
                "events_no_expiry",
                "events_trust_floor",
                "events_trust_floor",
                "events_trust_floor",
                "events_unsigned_inbound",
                "events_verification_mode",
                "events_verification_mode",
            ]
        );
        assert!(
            found(&err)
                .iter()
                .any(|(_, s)| s.contains("events[`orders.created`]"))
        );
        for mode in ["webhook", "poll", "push"] {
            assert!(
                found(&err)
                    .iter()
                    .any(|(_, s)| s.contains(&format!("events.{mode}.require_trust"))),
                "{mode}"
            );
        }

        let fine = r#"
mcp:
  configurations:
    events:
      enabled: true
      webhook:
        require_trust: verified
        verification: { modes: [challenge] }
        egress: { allowed_ports: [443] }
  capabilities:
    events:
      - name: orders.created
        source: { inbound: { source_id: orders, verify: { profile: standard_webhooks, secrets: ["${secret.SHOP}"] } } }
"#;
        check_published_config_with_secret_keys(fine, &BTreeSet::from(["SHOP".to_owned()]))
            .expect("the managed shape");
    }

    /// MCP Events webhook delivery needs `events.webhooks`, which every plan
    /// carries; a licence without it is refused, and events with webhook
    /// delivery off need nothing.
    #[test]
    fn webhook_delivery_needs_its_feature() {
        use mcpg_control_plane_license::license::FEATURE_EVENTS_WEBHOOKS;
        let on = "mcp:\n  configurations:\n    events:\n      enabled: true\n";
        let off = "mcp:\n  configurations:\n    events:\n      enabled: true\n      webhook: { enabled: false }\n";
        for plan in ["community", "pro", "team", "enterprise"] {
            check_config_entitlements(on, &claims_for(plan)).expect(plan);
        }
        let mut without = claims_for("pro");
        without.features.retain(|f| f != FEATURE_EVENTS_WEBHOOKS);
        let err = check_config_entitlements(on, &without).unwrap_err();
        assert_eq!(err.violations.len(), 1);
        assert_eq!(err.violations[0].kind, "feature_not_licensed");
        assert!(
            err.violations[0]
                .snippet
                .contains("mcp.configurations.events.webhook")
        );
        check_config_entitlements(off, &without).expect("webhook delivery off");
    }

    /// `(kind, snippet)` of every violation, sorted: collection order follows
    /// map iteration and is not part of the contract.
    fn found(err: &PublishGuardError) -> Vec<(&'static str, String)> {
        let mut out: Vec<(&'static str, String)> = err
            .violations
            .iter()
            .map(|v| (v.kind, v.snippet.clone()))
            .collect();
        out.sort();
        out
    }

    /// A tenant `license:` block is refused whatever it holds; a key with no
    /// value sets nothing and passes. TOML reads the same way.
    #[test]
    fn refuses_a_tenant_license_block() {
        for cfg in [
            "license:\n  non_production_use: true\n",
            "license:\n  token: \"eyJhbGciOiJFZERTQSJ9.e30.sig\"\n  pubkey_pem: \"-----BEGIN PUBLIC KEY-----\"\n",
            "license: {}\n",
            "[license]\nnon_production_use = true\n",
        ] {
            let err = check_published_config(cfg).expect_err(cfg);
            assert_eq!(
                err.violations,
                vec![Violation {
                    kind: "license_block",
                    snippet: "license".to_owned(),
                }],
                "{cfg}"
            );
        }
        check_published_config(
            "license:\ngateway:\n  server:\n    bind_address: \"0.0.0.0:8787\"\n",
        )
        .expect("a license key with no value");
    }

    /// One first-party OCI entry per plugin id: `(id, short name)`.
    fn plugins_config(entries: &[(&str, &str)]) -> String {
        let mut cfg = String::from("plugins:\n");
        for (id, short) in entries {
            cfg.push_str(&format!(
                "  - id: {id}\n    source:\n      oci: ghcr.io/mcpg-dev/plugins/{short}:1.0.0\n"
            ));
        }
        cfg
    }

    /// A paid-namespace plugin is outside a lower plan's envelope, and a
    /// feature-gated one needs its feature; a free plugin passes everywhere,
    /// and a disabled entry is checked like any other.
    #[test]
    fn plugin_entitlements_follow_the_plan() {
        let cfg = format!(
            "{}    disabled: true\n",
            plugins_config(&[
                ("dev.mcpg.backend.http", "backend-http"),
                ("dev.mcpg.policy.casbin", "policy-casbin"),
                ("dev.mcpg.identity.saml", "identity-saml"),
                ("dev.mcpg.payment.acp", "payment-acp"),
                ("dev.mcpg.cluster.redis", "cluster-redis"),
            ])
        );
        let casbin = (
            "plugin_not_entitled",
            "plugins[1] `dev.mcpg.policy.casbin` is not among the plugins plan `{plan}` entitles",
        );
        let saml = (
            "feature_not_licensed",
            "plugins[2] `dev.mcpg.identity.saml` needs the `sso.saml` license feature, which \
             plan `{plan}` does not grant",
        );
        let payment = (
            "plugin_not_entitled",
            "plugins[3] `dev.mcpg.payment.acp` is not among the plugins plan `{plan}` entitles",
        );
        let redis = (
            "plugin_not_entitled",
            "plugins[4] `dev.mcpg.cluster.redis` is not among the plugins plan `{plan}` entitles",
        );
        for (plan, expected) in [
            ("community", vec![casbin, saml, payment, redis]),
            ("pro", vec![casbin, saml, redis]),
            ("team", vec![redis]),
        ] {
            let err = check_config_entitlements(&cfg, &claims_for(plan)).expect_err(plan);
            let mut want: Vec<(&'static str, String)> = expected
                .into_iter()
                .map(|(kind, snippet)| (kind, snippet.replace("{plan}", plan)))
                .collect();
            want.sort();
            assert_eq!(found(&err), want, "{plan}");
        }
        check_config_entitlements(&cfg, &claims_for("enterprise")).expect("enterprise");
        let toml_cfg = "[[plugins]]\nid = \"dev.mcpg.policy.casbin\"\n\
                        [plugins.source]\noci = \"ghcr.io/mcpg-dev/plugins/policy-casbin:1.0.0\"\n";
        let err = check_config_entitlements(toml_cfg, &claims_for("community")).unwrap_err();
        assert_eq!(err.violations[0].kind, "plugin_not_entitled", "{err}");
    }

    /// The `ref` names the artefact the gateway loads, so it is checked as
    /// well as the alias — once when the two agree.
    #[test]
    fn plugin_entitlements_read_the_ref() {
        let community = claims_for("community");
        let aliased = "plugins:\n  - id: pay\n    ref: dev.mcpg.payment.acp\n    source:\n      \
                       oci: ghcr.io/mcpg-dev/plugins/payment-acp:1.0.0\n";
        let err = check_config_entitlements(aliased, &community).unwrap_err();
        assert_eq!(
            found(&err),
            vec![(
                "plugin_not_entitled",
                "plugins[0].ref `dev.mcpg.payment.acp` is not among the plugins plan \
                 `community` entitles"
                    .to_owned()
            )]
        );
        let same = aliased.replace("id: pay", "id: dev.mcpg.payment.acp");
        let err = check_config_entitlements(&same, &community).unwrap_err();
        assert_eq!(err.violations.len(), 1, "{err}");
        assert!(
            err.violations[0].snippet.starts_with("plugins[0] "),
            "{err}"
        );
    }

    /// The platform owns the `cluster` block on the managed service: a tenant
    /// one names no plugin and is not refused on any plan, and the publish
    /// answer says it is ignored. A config without one, or with an empty one,
    /// draws no warning.
    #[test]
    fn a_tenant_cluster_block_is_ignored_with_a_warning() {
        let redis = "cluster:\n  kind: redis\n  url: \"${secret.REDIS_URL}\"\n  \
                     allow_plaintext_state: true\n";
        for plan in ["community", "pro", "team", "enterprise"] {
            check_config_entitlements(redis, &claims_for(plan)).expect(plan);
            check_config_entitlements("cluster:\n  kind: nats\n", &claims_for(plan)).expect(plan);
        }
        let warnings = managed_publish_warnings(redis);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0].starts_with("`cluster` is ignored"),
            "{warnings:?}"
        );
        for quiet in [
            "gateway: {}\n",
            "cluster: {}\n",
            "cluster:\n",
            "not: [valid",
        ] {
            assert!(managed_publish_warnings(quiet).is_empty(), "{quiet}");
        }
    }

    /// The coordinator the platform injects for an instance with more than
    /// one replica passes where the licence admits it as the platform's — the
    /// rule the gateway's own gate applies, so what the publish admits loads —
    /// under its `id` or its `ref`; another cluster coordinator does not, and
    /// neither does it under a licence without that admission.
    #[test]
    fn a_platform_injected_plugin_is_exempt_from_the_plan() {
        use mcpg_control_plane_license::license::FEATURE_PLATFORM_COORDINATION;
        let nats = plugins_config(&[("dev.mcpg.cluster.nats", "cluster-nats")]);
        let aliased = "plugins:\n  - id: coordinator\n    ref: dev.mcpg.cluster.nats\n    \
                       source:\n      oci: ghcr.io/mcpg-dev/plugins/cluster-nats:1.0.0\n";
        let redis = plugins_config(&[("dev.mcpg.cluster.redis", "cluster-redis")]);
        for plan in ["community", "pro"] {
            let mut managed = claims_for(plan);
            managed.features.push(FEATURE_PLATFORM_COORDINATION.into());
            check_config_entitlements(&nats, &managed).expect(plan);
            check_config_entitlements(aliased, &managed).expect(plan);
            let err = check_config_entitlements(&redis, &managed).expect_err(plan);
            assert_eq!(err.violations[0].kind, "plugin_not_entitled", "{err}");

            for cfg in [nats.as_str(), aliased] {
                let err = check_config_entitlements(cfg, &claims_for(plan)).expect_err(plan);
                assert_eq!(
                    err.violations[0].kind, "plugin_not_entitled",
                    "{plan}: {err}"
                );
            }
        }
        let mut one = claims_for("community");
        one.quotas.plugins = 1;
        let two = plugins_config(&[
            ("dev.mcpg.backend.http", "backend-http"),
            ("dev.mcpg.cluster.nats", "cluster-nats"),
        ]);
        check_plugin_quota(&two, &one).expect("the injected coordinator is not counted");
        let over = plugins_config(&[
            ("dev.mcpg.backend.http", "backend-http"),
            ("dev.mcpg.backend.mock", "backend-mock"),
        ]);
        check_plugin_quota(&over, &one).expect_err("two tenant plugins over a quota of one");
    }

    /// The quota exemption follows the artefact an entry loads, not its
    /// alias: the coordinator's id over another plugin's `ref` loads that
    /// plugin and counts, and an alias over the coordinator's `ref` does not.
    #[test]
    fn the_coordinators_name_as_an_alias_does_not_exempt_another_plugin() {
        let mut one = claims_for("community");
        one.quotas.plugins = 1;
        let masked = format!(
            "{}  - id: dev.mcpg.cluster.nats\n    ref: dev.mcpg.backend.mock\n    \
             source:\n      oci: ghcr.io/mcpg-dev/plugins/backend-mock:1.0.0\n",
            plugins_config(&[("dev.mcpg.backend.http", "backend-http")])
        );
        let err = check_plugin_quota(&masked, &one).expect_err("backend.mock loads and counts");
        assert_eq!(err.violations[0].kind, "plugin_quota_exceeded", "{err}");

        let aliased = format!(
            "{}  - id: coordinator\n    ref: dev.mcpg.cluster.nats\n    \
             source:\n      oci: ghcr.io/mcpg-dev/plugins/cluster-nats:1.0.0\n",
            plugins_config(&[("dev.mcpg.backend.http", "backend-http")])
        );
        check_plugin_quota(&aliased, &one).expect("the coordinator under an alias is not counted");
    }

    const CUSTOM_PLUGIN_CONFIG: &str = r#"
gateway:
  plugin_registry:
    cache_dir: /var/lib/mcpg/plugin-cache
    default_registry: registry.example.com/plugins
    mirrors:
      - url: registry.example.com/mirror
    trusted_keys:
      - id: acme
        pem: "-----BEGIN PUBLIC KEY-----"
    insecure_registries: ["registry.example.com"]
    auth:
      username: acme
    tls:
      insecure: true
plugins:
  - id: acme.tool
    class: tool_gate
    source:
      oci: registry.example.com/plugins/acme-tool:1.0.0
  - id: dev.mcpg.backend.http
    source:
      oci: ghcr.io/mcpg-dev/plugins/backend-http:1.0.0
    signature:
      trusted_keys:
        - id: acme
          pem: "-----BEGIN PUBLIC KEY-----"
"#;

    /// Without `plugins.custom`, every source outside the first-party
    /// registry and every registry or trust setting that could reach one is
    /// refused and named; enterprise may set them all.
    #[test]
    fn registry_and_trust_overrides_need_custom_plugins() {
        for plan in ["community", "pro", "team"] {
            let err =
                check_config_entitlements(CUSTOM_PLUGIN_CONFIG, &claims_for(plan)).expect_err(plan);
            let mut want: Vec<(&'static str, String)> = [
                "gateway.plugin_registry.auth",
                "gateway.plugin_registry.default_registry",
                "gateway.plugin_registry.insecure_registries",
                "gateway.plugin_registry.mirrors",
                "gateway.plugin_registry.tls",
                "gateway.plugin_registry.trusted_keys",
                "plugins[0].source.oci `registry.example.com/plugins/acme-tool:1.0.0`",
                "plugins[1].signature.trusted_keys",
            ]
            .into_iter()
            .map(|path| {
                (
                    "feature_not_licensed",
                    format!(
                        "{path} needs the `plugins.custom` license feature, which plan `{plan}` \
                         does not grant"
                    ),
                )
            })
            .collect();
            want.sort();
            assert_eq!(found(&err), want, "{plan}");
        }
        check_config_entitlements(CUSTOM_PLUGIN_CONFIG, &claims_for("enterprise"))
            .expect("enterprise references its own plugins");
    }

    /// Settings that cannot reach a plugin the platform did not publish pass
    /// on every plan: the cache and revocation paths, a stricter integrity
    /// rule, a default signature policy (the managed render replaces it), a
    /// per-entry policy of `enforce`, a hash pin, and keys with no value.
    #[test]
    fn registry_settings_that_reach_no_custom_plugin_pass_on_every_plan() {
        let cfg = r#"
gateway:
  plugin_registry:
    cache_dir: /var/lib/mcpg/plugin-cache
    revocation_list_path: /etc/mcpg/revoked.json
    require_integrity_anchor: true
    default_signature_policy: disabled
    mirrors: []
    trusted_keys: []
    auth: {}
    tls:
plugins:
  - id: dev.mcpg.backend.http
    source:
      oci: oci://ghcr.io/mcpg-dev/plugins/backend-http:1.0.0
    signature:
      policy: enforce
      sha256: "0000000000000000000000000000000000000000000000000000000000000000"
      trusted_keys: []
  - id: dev.mcpg.backend.mock
    source:
      path: /usr/local/lib/mcpg/plugins/dev.mcpg.backend.mock/plugin.so
"#;
        for plan in ["community", "pro", "team", "enterprise"] {
            check_config_entitlements(cfg, &claims_for(plan)).expect(plan);
        }
    }

    /// A per-entry signature policy weaker than the managed default would
    /// load an artefact no trusted key signed, so without `plugins.custom` it
    /// is refused and named; `enforce` passes everywhere and enterprise may
    /// relax it. The default policy is never refused: the publish answer
    /// says the managed render replaces it.
    #[test]
    fn a_per_plugin_signature_policy_below_enforce_needs_custom_plugins() {
        let with_policy = |policy: &str| {
            format!(
                "{}    signature:\n      policy: {policy}\n",
                plugins_config(&[("dev.mcpg.backend.http", "backend-http")])
            )
        };
        for plan in ["community", "pro", "team"] {
            for policy in ["disabled", "warn"] {
                let err = check_config_entitlements(&with_policy(policy), &claims_for(plan))
                    .expect_err(plan);
                assert_eq!(
                    found(&err),
                    vec![(
                        "feature_not_licensed",
                        format!(
                            "plugins[0].signature.policy `{policy}` needs the `plugins.custom` \
                             license feature, which plan `{plan}` does not grant"
                        )
                    )],
                    "{plan} {policy}"
                );
            }
            check_config_entitlements(&with_policy("enforce"), &claims_for(plan)).expect(plan);
        }
        check_config_entitlements(&with_policy("disabled"), &claims_for("enterprise"))
            .expect("enterprise relaxes a plugin it vouches for itself");

        let relaxed = "gateway:\n  plugin_registry:\n    default_signature_policy: disabled\n";
        check_config_entitlements(relaxed, &claims_for("community")).expect("never refused");
        let warnings = managed_publish_warnings(relaxed);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0].starts_with(
                "`gateway.plugin_registry.default_signature_policy: disabled` is ignored"
            ),
            "{warnings:?}"
        );
        let strict = "gateway:\n  plugin_registry:\n    default_signature_policy: enforce\n";
        assert!(managed_publish_warnings(strict).is_empty());
    }

    /// `plugins.custom` in the claims admits custom plugins on any plan, and
    /// an enterprise licence issued before the flag joined its plan keeps them.
    #[test]
    fn custom_plugins_follow_the_flag_or_the_plan() {
        use mcpg_control_plane_license::license::FEATURE_CUSTOM_PLUGINS;
        let mut contracted = claims_for("team");
        contracted.features.push(FEATURE_CUSTOM_PLUGINS.to_owned());
        assert!(allows_custom_plugins(&contracted));
        check_config_entitlements(CUSTOM_PLUGIN_CONFIG, &contracted)
            .expect("a contracted plugins.custom grant");
        let mut pinned = claims_for("enterprise");
        pinned.features.retain(|f| f != FEATURE_CUSTOM_PLUGINS);
        assert!(allows_custom_plugins(&pinned));
        assert!(!allows_custom_plugins(&claims_for("team")));
    }

    /// `quotas.plugins` caps the entries one config lists, disabled ones
    /// included; `0` is unlimited and unparseable input fails closed.
    #[test]
    fn plugin_count_is_capped_by_the_plan() {
        let entries = |n: usize| {
            let mut cfg = String::from("plugins:\n");
            for i in 0..n {
                cfg.push_str(&format!(
                    "  - id: dev.mcpg.transform.t{i}\n    disabled: true\n    source:\n      \
                     oci: ghcr.io/mcpg-dev/plugins/transform-t{i}:1.0.0\n"
                ));
            }
            cfg
        };
        let community = claims_for("community");
        assert_eq!(community.quotas.plugins, 25);
        check_plugin_quota(&entries(25), &community).expect("at the quota");
        check_plugin_quota("gateway: {}\n", &community).expect("no plugins");
        let err = check_plugin_quota(&entries(26), &community).unwrap_err();
        assert_eq!(
            err.violations,
            vec![Violation {
                kind: "plugin_quota_exceeded",
                snippet: "plugins lists 26 entries and plan `community` includes 25".to_owned(),
            }]
        );
        check_plugin_quota(&entries(400), &claims_for("enterprise")).expect("unlimited");
        assert_eq!(
            check_plugin_quota("just a string", &community)
                .unwrap_err()
                .violations[0]
                .kind,
            "unparseable_config"
        );
    }

    /// `event_types` caps the MCP Events types one config declares; `0` is
    /// unlimited and unparseable input fails closed.
    #[test]
    fn declared_event_types_are_capped_by_the_plan() {
        let types = |n: usize| {
            let mut cfg = String::from("mcp:\n  capabilities:\n    events:\n");
            for i in 0..n {
                cfg.push_str(&format!(
                    "      - name: orders.e{i}\n        source:\n          inbound:\n            \
                     source_id: e{i}\n"
                ));
            }
            cfg
        };
        let community = claims_for("community");
        let limit = community.quotas.event_types_for("community");
        assert_eq!(limit, 10);
        check_event_type_quota(&types(10), &community).expect("at the cap");
        check_event_type_quota("gateway: {}\n", &community).expect("no events");
        let err = check_event_type_quota(&types(11), &community).unwrap_err();
        assert_eq!(
            err.violations,
            vec![Violation {
                kind: "event_type_quota_exceeded",
                snippet: "mcp.capabilities.events declares 11 event types and plan `community` \
                          serves 10"
                    .to_owned(),
            }]
        );
        check_event_type_quota(&types(400), &claims_for("enterprise")).expect("unlimited");
        assert_eq!(
            check_event_type_quota("just a string", &community)
                .unwrap_err()
                .violations[0]
                .kind,
            "unparseable_config"
        );
    }

    const LOGIN_CONFIG: &str = r#"
governance:
  access:
    authorization_server:
      issuer: "https://edge-1.mcpg.cloud"
      trusted_idps:
        - issuer: "https://acme.okta.com"
          login:
            client_id: "0oa1agent"
            client_secret: "${secret.OKTA_CLIENT_SECRET}"
        - issuer: "https://other.example.com"
      interactive:
        access_token_ttl_secs: 600
"#;

    /// Interactive sign-in is an enterprise feature: the login block and the
    /// interactive block are each refused under a plan without it, and named.
    #[test]
    fn interactive_login_needs_the_enterprise_feature() {
        for plan in ["community", "pro", "team"] {
            let err = check_config_entitlements(LOGIN_CONFIG, &claims_for(plan)).expect_err(plan);
            let snippets: Vec<&str> = err.violations.iter().map(|v| v.snippet.as_str()).collect();
            assert_eq!(err.violations.len(), 2, "{plan}: {snippets:?}");
            assert!(
                err.violations
                    .iter()
                    .all(|v| v.kind == "feature_not_licensed"
                        && v.snippet.contains("`sso.interactive_login`")
                        && v.snippet.contains(&format!("plan `{plan}`"))),
                "{snippets:?}"
            );
            assert!(snippets[0].starts_with(
                "governance.access.authorization_server.trusted_idps[`https://acme.okta.com`].login"
            ));
            assert!(snippets[1].starts_with("governance.access.authorization_server.interactive"));
        }
        check_config_entitlements(LOGIN_CONFIG, &claims_for("enterprise"))
            .expect("enterprise grants interactive login");
    }

    /// An EMA-only server, an absent or null block, and TOML all read the
    /// same way; unparseable input fails closed.
    #[test]
    fn config_entitlements_see_only_present_blocks() {
        let community = claims_for("community");
        for clean in [
            "gateway:\n  server:\n    bind_address: \"0.0.0.0:8787\"\n",
            "governance:\n  access:\n    authorization_server:\n      issuer: https://x\n      trusted_idps:\n        - issuer: https://acme.okta.com\n",
            "governance:\n  access:\n    authorization_server:\n      interactive:\n      trusted_idps:\n        - issuer: https://acme.okta.com\n          login:\n",
        ] {
            check_config_entitlements(clean, &community).expect(clean);
        }
        let toml_cfg = r#"
[[governance.access.authorization_server.trusted_idps]]
issuer = "https://acme.okta.com"
[governance.access.authorization_server.trusted_idps.login]
client_id = "agent"
"#;
        let err = check_config_entitlements(toml_cfg, &community).unwrap_err();
        assert_eq!(err.violations.len(), 1, "{err}");
        assert_eq!(
            check_config_entitlements("just a string", &community)
                .unwrap_err()
                .violations[0]
                .kind,
            "unparseable_config"
        );
    }

    const CONSTRAINED_TOKENS_CONFIG: &str = r#"
governance:
  access:
    authorization_server:
      issuer: "https://edge-1.mcpg.cloud"
      trusted_idps:
        - issuer: "https://acme.okta.com"
      dpop:
        enabled: true
        nonce: token_endpoint
      authorization_details:
        types:
          - type: mcp_tool
            actions: ["tools/call"]
"#;

    /// DPoP and rich authorization requests are enterprise features: each
    /// turned-on block is refused under a plan without its feature, and
    /// named with the feature and the plan.
    #[test]
    fn dpop_and_rich_authorization_need_the_enterprise_features() {
        for plan in ["community", "pro", "team"] {
            let err = check_config_entitlements(CONSTRAINED_TOKENS_CONFIG, &claims_for(plan))
                .expect_err(plan);
            let snippets: Vec<&str> = err.violations.iter().map(|v| v.snippet.as_str()).collect();
            assert_eq!(err.violations.len(), 2, "{plan}: {snippets:?}");
            assert!(
                err.violations
                    .iter()
                    .all(|v| v.kind == "feature_not_licensed"
                        && v.snippet.contains(&format!("plan `{plan}`"))),
                "{snippets:?}"
            );
            assert_eq!(
                snippets[0],
                format!(
                    "governance.access.authorization_server.dpop needs the `oauth.dpop` license \
                     feature, which plan `{plan}` does not grant"
                )
            );
            assert_eq!(
                snippets[1],
                format!(
                    "governance.access.authorization_server.authorization_details needs the \
                     `oauth.rich_authorization` license feature, which plan `{plan}` does not \
                     grant"
                )
            );
        }
        check_config_entitlements(CONSTRAINED_TOKENS_CONFIG, &claims_for("enterprise"))
            .expect("enterprise grants DPoP and rich authorization requests");
    }

    /// A block that leaves its surface off needs no feature: `dpop` without
    /// `enabled: true`, `authorization_details` without a type. TOML reads
    /// the same way.
    #[test]
    fn disabled_dpop_and_authorization_details_blocks_need_no_feature() {
        let community = claims_for("community");
        for clean in [
            "governance:\n  access:\n    authorization_server:\n      dpop:\n        enabled: false\n        nonce: always\n        required: false\n",
            "governance:\n  access:\n    authorization_server:\n      dpop: {}\n",
            "governance:\n  access:\n    authorization_server:\n      dpop:\n",
            "governance:\n  access:\n    authorization_server:\n      authorization_details:\n        max_entries: 8\n",
            "governance:\n  access:\n    authorization_server:\n      authorization_details:\n        types: []\n",
            "governance:\n  access:\n    authorization_server:\n      authorization_details:\n",
        ] {
            check_config_entitlements(clean, &community).expect(clean);
        }
        let toml_cfg = r#"
[governance.access.authorization_server.dpop]
enabled = true
[[governance.access.authorization_server.authorization_details.types]]
type = "mcp_tool"
"#;
        let err = check_config_entitlements(toml_cfg, &community).unwrap_err();
        assert_eq!(err.violations.len(), 2, "{err}");
        check_config_entitlements(
            "[governance.access.authorization_server.dpop]\nenabled = false\n",
            &community,
        )
        .expect("a TOML block that leaves DPoP off");
    }

    /// Interactive sign-in, DPoP and rich authorization requests on one
    /// server are refused together, each by its own feature.
    #[test]
    fn one_refusal_names_every_authorization_server_feature() {
        let every = format!(
            "{LOGIN_CONFIG}      dpop:\n        enabled: true\n      authorization_details:\n        \
             types:\n          - type: mcp_tool\n"
        );
        let err = check_config_entitlements(&every, &claims_for("team")).unwrap_err();
        let features: Vec<&str> = err
            .violations
            .iter()
            .map(|v| {
                [
                    "sso.interactive_login",
                    "oauth.dpop",
                    "oauth.rich_authorization",
                ]
                .into_iter()
                .find(|f| v.snippet.contains(&format!("`{f}`")))
                .unwrap_or("?")
            })
            .collect();
        assert_eq!(
            features,
            [
                "sso.interactive_login",
                "sso.interactive_login",
                "oauth.dpop",
                "oauth.rich_authorization"
            ],
            "{err}"
        );
        check_config_entitlements(&every, &claims_for("enterprise"))
            .expect("enterprise grants all three");
    }

    #[test]
    fn cloud_auth_error_names_every_verifier() {
        let msg = CloudAuthError::NoVerifier.to_string();
        for key in VERIFIER_KEYS {
            assert!(msg.contains(&format!("governance.access.{key}")), "{msg}");
        }
        assert!(msg.contains("cloud.allow_anonymous: true"), "{msg}");
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
