//! Target-version validation for tenant configs.
//!
//! The platform runs one admin-blessed gateway release, and a tenant's config
//! is only accepted when it validates against THAT build's capability
//! manifest (`mcpg capabilities`): the config must satisfy the target's own
//! JSON schema, and every plugin reference must be one the tenant's plan
//! permits. Runs on publish AND on redeploy, and fails closed: a manifest
//! this module cannot understand rejects the config rather than waving it
//! through.
//!
//! [`publish_guard`](crate::publish_guard) stays the security gate (host-read
//! exfil constructs); this module is the compatibility gate. Both must pass.

use serde::Deserialize;
use std::fmt;

/// Registry path first-party plugins publish under. NB the path segment is the
/// plugin's hyphenated SHORT name (`identity-oidc`), not its dotted id
/// (`dev.mcpg.identity.oidc`) — reusing the id as the path is the natural
/// mistake and 404s at boot, where OCI resolution is fail-closed.
pub const FIRST_PARTY_PLUGIN_PREFIX: &str = "ghcr.io/mcpg-dev/plugins/";

/// Which plugins a tenant may reference from its config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginPolicy {
    /// First-party plugins only. The default for every plan.
    FirstPartyOnly,
    /// Any registry, including the tenant's own published plugins.
    /// Enterprise.
    AllowCustom,
}

/// True when `reference` names a plugin published by the platform. Tolerates a
/// leading `oci://` and an explicit `docker.io`-style host already being
/// present; anything else is treated as third-party.
pub fn is_first_party_plugin_ref(reference: &str) -> bool {
    reference
        .trim_start_matches("oci://")
        .starts_with(FIRST_PARTY_PLUGIN_PREFIX)
}

/// The slice of `mcpg capabilities` output this validator consumes. Additive
/// manifest fields are ignored by construction; a `manifest_version` above
/// [`MAX_UNDERSTOOD_MANIFEST`] is refused (fail closed, not best-effort).
#[derive(Debug, Clone, Deserialize)]
pub struct GatewayCapabilities {
    pub manifest_version: u32,
    #[serde(default)]
    pub gateway_version: String,
    pub plugin_protocol_version: String,
    pub config_schema: serde_json::Value,
    #[serde(default)]
    pub baked_plugins: Vec<BakedPlugin>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BakedPlugin {
    pub id: String,
}

const MAX_UNDERSTOOD_MANIFEST: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetViolation {
    /// Machine-stable kind (`schema_mismatch`, `plugin_not_first_party`,
    /// `plugin_not_in_release`, `manifest_not_understood`,
    /// `config_unparseable`).
    pub kind: &'static str,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetValidationError {
    pub violations: Vec<TargetViolation>,
}

impl fmt::Display for TargetValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "config rejected against the platform release ({} violation(s)): ",
            self.violations.len()
        )?;
        for (i, v) in self.violations.iter().enumerate() {
            if i > 0 {
                write!(f, "; ")?;
            }
            write!(f, "{} [{}]", v.detail, v.kind)?;
        }
        Ok(())
    }
}

impl std::error::Error for TargetValidationError {}

/// Validate a submitted YAML/TOML config against the target gateway's
/// capability manifest. Empty configs are the caller's concern (a publish
/// without a config is legal today — the CR runs the image defaults).
pub fn validate_against_gateway(
    raw: &str,
    caps: &GatewayCapabilities,
    policy: PluginPolicy,
) -> Result<(), TargetValidationError> {
    let mut violations = Vec::new();

    if caps.manifest_version > MAX_UNDERSTOOD_MANIFEST {
        return Err(TargetValidationError {
            violations: vec![TargetViolation {
                kind: "manifest_not_understood",
                detail: format!(
                    "the release's capability manifest is version {} and this control \
                     plane understands up to {MAX_UNDERSTOOD_MANIFEST} — refusing to \
                     validate rather than guess",
                    caps.manifest_version
                ),
            }],
        });
    }

    let Some(value) = parse_structured(raw) else {
        return Err(TargetValidationError {
            violations: vec![TargetViolation {
                kind: "config_unparseable",
                detail: "the config parses as neither YAML nor TOML".into(),
            }],
        });
    };

    // 1. The target build's own schema. This is the versioned contract: keys
    //    the target does not know, wrong shapes, missing requireds — all
    //    surface here with schema-quality paths.
    match jsonschema::validator_for(&caps.config_schema) {
        Ok(schema) => {
            for err in schema.iter_errors(&value) {
                violations.push(TargetViolation {
                    kind: "schema_mismatch",
                    detail: format!("{}: {}", err.instance_path, err),
                });
            }
        }
        Err(e) => {
            // A schema the release itself shipped but that does not compile
            // is a platform defect — refuse the publish, not the blame.
            violations.push(TargetViolation {
                kind: "manifest_not_understood",
                detail: format!("the release's config schema does not compile: {e}"),
            });
        }
    }

    // 2. Plugin references. Plugins are never bundled with the gateway: a
    //    deployment names them in config and the runtime fetches them from
    //    OCI. A tenant therefore pins whatever version it wants, including a
    //    digest — the honest supply-chain form. Integrity is carried by
    //    signature verification and the revocation list, not by withholding
    //    the pin; the cost of a tenant pinning a stale plugin is theirs, and
    //    revocation still refuses a withdrawn artefact.
    //
    //    WHOSE plugins is the plan question: first-party only by default,
    //    any registry under `PluginPolicy::AllowCustom`. `path:` sources
    //    still have to name something the image carries.
    for (idx, entry) in plugin_entries(&value) {
        let at = format!("plugins[{idx}]");
        match entry {
            PluginSource::Oci(reference) => {
                if policy == PluginPolicy::FirstPartyOnly && !is_first_party_plugin_ref(&reference)
                {
                    violations.push(TargetViolation {
                        kind: "plugin_not_first_party",
                        detail: format!(
                            "{at}: `{reference}` is not a first-party plugin \
                             (`{FIRST_PARTY_PLUGIN_PREFIX}…`) — referencing your own \
                             plugins requires an enterprise subscription"
                        ),
                    });
                }
            }
            PluginSource::Path(path) => {
                // A release that bundles no plugins cannot satisfy ANY `path:`
                // source, so say that rather than reporting the reference as
                // absent from a set of zero — which reads as a missing file and
                // sends the author looking for it in the image.
                if caps.baked_plugins.is_empty() {
                    violations.push(TargetViolation {
                        kind: "plugin_source_not_supported",
                        detail: format!(
                            "{at}: `{path}` is a file in the gateway image, and images \
                             carry no plugins — name the plugin with `source.oci` \
                             (e.g. `{FIRST_PARTY_PLUGIN_PREFIX}<short-name>`) and the \
                             runtime will fetch, verify and cache it"
                        ),
                    });
                    continue;
                }
                // An older blessed release may still bundle a set; keep
                // validating against what that image actually carries.
                let known = caps
                    .baked_plugins
                    .iter()
                    .any(|p| path.contains(&format!("/{}/", p.id)) || path.ends_with(&p.id));
                if !known {
                    violations.push(TargetViolation {
                        kind: "plugin_not_in_release",
                        detail: format!(
                            "{at}: `{path}` is not baked into the release image \
                             ({} plugin(s) are)",
                            caps.baked_plugins.len()
                        ),
                    });
                }
            }
        }
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(TargetValidationError { violations })
    }
}

enum PluginSource {
    Oci(String),
    Path(String),
}

/// Every `plugins[].source` in the parsed config, with its index.
fn plugin_entries(value: &serde_json::Value) -> Vec<(usize, PluginSource)> {
    let mut out = Vec::new();
    let Some(list) = value.get("plugins").and_then(|p| p.as_array()) else {
        return out;
    };
    for (idx, entry) in list.iter().enumerate() {
        let Some(source) = entry.get("source") else {
            continue;
        };
        if let Some(oci) = source.get("oci").and_then(|v| v.as_str()) {
            out.push((idx, PluginSource::Oci(oci.to_owned())));
        } else if let Some(path) = source.get("path").and_then(|v| v.as_str()) {
            out.push((idx, PluginSource::Path(path.to_owned())));
        }
    }
    out
}

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

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(schema: serde_json::Value) -> GatewayCapabilities {
        GatewayCapabilities {
            manifest_version: 1,
            gateway_version: "0.1.0-beta.23".into(),
            plugin_protocol_version: "1.0".into(),
            config_schema: schema,
            baked_plugins: vec![BakedPlugin {
                id: "dev.mcpg.backend.http".into(),
            }],
        }
    }

    fn permissive() -> serde_json::Value {
        serde_json::json!({"type": "object"})
    }

    #[test]
    fn floating_protocol_tag_passes() {
        let cfg = r#"
plugins:
  - id: dev.mcpg.backend.http
    source: { oci: "ghcr.io/mcpg-dev/plugins/backend-http:protocol-1" }
"#;
        validate_against_gateway(cfg, &caps(permissive()), PluginPolicy::FirstPartyOnly).unwrap();
    }

    /// Plugins are config-defined and fetched from OCI, so a tenant pins the
    /// version it wants — including a digest, which is the form a supply-chain
    /// story actually needs.
    #[test]
    fn version_pin_and_digest_are_allowed_on_first_party() {
        let cfg = r#"
plugins:
  - id: a
    source: { oci: "ghcr.io/mcpg-dev/plugins/backend-http:0.1.0-alpha.16" }
  - id: b
    source: { oci: "ghcr.io/mcpg-dev/plugins/backend-http@sha256:0000000000000000000000000000000000000000000000000000000000000000" }
"#;
        validate_against_gateway(cfg, &caps(permissive()), PluginPolicy::FirstPartyOnly).unwrap();
    }

    #[test]
    fn third_party_ref_needs_enterprise() {
        let cfg = r#"
plugins:
  - id: dev.instruction.backend.s3
    source: { oci: "ghcr.io/instruction-md/mcpg-plugin-instruction-s3@sha256:0000000000000000000000000000000000000000000000000000000000000000" }
"#;
        let err = validate_against_gateway(cfg, &caps(permissive()), PluginPolicy::FirstPartyOnly)
            .unwrap_err();
        assert_eq!(err.violations[0].kind, "plugin_not_first_party");
        // The same config is legitimate once the plan allows it.
        validate_against_gateway(cfg, &caps(permissive()), PluginPolicy::AllowCustom).unwrap();
    }

    /// A private registry is third-party by definition — it is not the
    /// platform's namespace, whatever its host looks like.
    #[test]
    fn private_registry_is_third_party() {
        let cfg = r#"
plugins:
  - id: a
    source: { oci: "registry.internal:5000/plugins/backend-http" }
"#;
        let err = validate_against_gateway(cfg, &caps(permissive()), PluginPolicy::FirstPartyOnly)
            .unwrap_err();
        assert_eq!(err.violations[0].kind, "plugin_not_first_party");
        validate_against_gateway(cfg, &caps(permissive()), PluginPolicy::AllowCustom).unwrap();
    }

    /// Images carry no plugins, so a `path:` source cannot resolve. The
    /// message has to say that — "not among 0 baked plugins" reads as a
    /// missing file and sends the author into the image looking for it.
    #[test]
    fn path_source_is_refused_when_the_release_bundles_nothing() {
        let cfg = r#"
plugins:
  - id: dev.mcpg.backend.http
    source: { path: "/usr/local/lib/mcpg/plugins/dev.mcpg.backend.http/plugin.so" }
"#;
        let mut c = caps(permissive());
        c.baked_plugins.clear();
        let err = validate_against_gateway(cfg, &c, PluginPolicy::FirstPartyOnly).unwrap_err();
        assert_eq!(err.violations[0].kind, "plugin_source_not_supported");
        assert!(
            err.violations[0].detail.contains("source.oci"),
            "the refusal must name the replacement: {}",
            err.violations[0].detail
        );
    }

    #[test]
    fn baked_path_passes_and_unknown_path_fails() {
        let ok = r#"
plugins:
  - id: dev.mcpg.backend.http
    source: { path: "/usr/local/lib/mcpg/plugins/dev.mcpg.backend.http/plugin.so" }
"#;
        validate_against_gateway(ok, &caps(permissive()), PluginPolicy::FirstPartyOnly).unwrap();
        let bad = ok.replace("backend.http", "backend.smb");
        let err = validate_against_gateway(&bad, &caps(permissive()), PluginPolicy::FirstPartyOnly)
            .unwrap_err();
        assert_eq!(err.violations[0].kind, "plugin_not_in_release");
    }

    #[test]
    fn schema_violations_carry_paths() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {"gateway": {"type": "object"}},
            "additionalProperties": false
        });
        let err = validate_against_gateway(
            "gatway:\n  x: 1\n",
            &caps(schema),
            PluginPolicy::FirstPartyOnly,
        )
        .unwrap_err();
        assert_eq!(err.violations[0].kind, "schema_mismatch");
        assert!(err.violations[0].detail.contains("gatway"));
    }

    #[test]
    fn future_manifest_fails_closed() {
        let mut c = caps(permissive());
        c.manifest_version = 99;
        let err = validate_against_gateway("gateway: {}\n", &c, PluginPolicy::FirstPartyOnly)
            .unwrap_err();
        assert_eq!(err.violations[0].kind, "manifest_not_understood");
    }
}
