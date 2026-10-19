//! Plugin ABI layouts at publish.
//!
//! A gateway refuses, at load, a plugin packaged for another ABI layout,
//! though both report the same ABI version. The blessed release reports its
//! layout (`mcpg capabilities`, `plugin_abi_layout`), and a plugin artefact
//! records the layout of the toolchain that packaged it (its OCI config blob,
//! `packaged_with_abi_layout`). This module resolves a config's `oci:` source
//! to the artefacts the gateway would try, and judges what a registry read of
//! them found. The read itself is the control plane's.
//!
//! The recorded layout is the packaging toolchain's: accurate for every
//! first-party plugin, which is packaged from the tree it is built from, and
//! only a claim for any other. So a first-party mismatch holds the publish,
//! and a plugin from another registry is not read at all.

use crate::target_validate::{TargetViolation, is_first_party_plugin_ref};

/// Media type of the config blob a packaged plugin's manifest carries.
pub const CONFIG_MEDIA_TYPE: &str = "application/vnd.mcpg.plugin.config.v1+json";

/// The platform suffixes a plugin tag may carry. Kept in step with the
/// gateway's `oci_wiring.rs` and `tools/plugins/check-abi-layout.mjs`.
pub const PLATFORM_SUFFIX_TOKENS: [&str; 9] = [
    "linux-amd64",
    "linux-arm64",
    "linux-musl-amd64",
    "linux-musl-arm64",
    "darwin-amd64",
    "darwin-arm64",
    "windows-amd64",
    "windows-arm64",
    "wasi-wasm",
];

/// The fallback artefact every platform tries after its native one.
const PORTABLE: &str = "wasi-wasm";

/// The platform tenant gateways run on unless the control plane is told
/// otherwise.
pub const DEFAULT_PLATFORM: &str = "linux-amd64";

/// Whether `platform` is a native platform a gateway can run on.
pub fn is_native_platform(platform: &str) -> bool {
    platform != PORTABLE && PLATFORM_SUFFIX_TOKENS.contains(&platform)
}

fn has_platform_suffix(tag: &str) -> bool {
    PLATFORM_SUFFIX_TOKENS
        .iter()
        .any(|s| tag == *s || tag.ends_with(&format!("-{s}")))
}

/// The major of a plugin protocol version (`1` of `1.0`).
pub fn protocol_major(version: &str) -> &str {
    version.split('.').next().unwrap_or(version)
}

/// The artefacts a gateway on `platform` tries for `reference`, native
/// first: a digest or a platform-suffixed tag as written, a bare tag with
/// the platform's suffix, and no tag as the floating
/// `protocol-<major>-<platform>` tag.
pub fn candidates(reference: &str, platform: &str, major: &str) -> Vec<String> {
    let r = reference
        .strip_prefix("oci://")
        .or_else(|| reference.strip_prefix("oci:"))
        .unwrap_or(reference);
    if r.contains('@') {
        return vec![r.to_owned()];
    }
    let seg_start = r.rfind('/').map_or(0, |i| i + 1);
    match r[seg_start..].find(':') {
        None => vec![
            format!("{r}:protocol-{major}-{platform}"),
            format!("{r}:protocol-{major}-{PORTABLE}"),
        ],
        Some(colon) if has_platform_suffix(&r[seg_start + colon + 1..]) => vec![r.to_owned()],
        Some(_) => vec![format!("{r}-{platform}"), format!("{r}-{PORTABLE}")],
    }
}

/// One artefact: its registry host, repository, and tag or digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtefactRef {
    pub host: String,
    pub repository: String,
    pub reference: String,
}

impl ArtefactRef {
    /// `host/repo:tag` or `host/repo@digest`; `None` without a host, a
    /// repository or a reference.
    pub fn parse(artefact: &str) -> Option<Self> {
        let (host, rest) = artefact.split_once('/')?;
        let (repository, reference) = match rest.split_once('@') {
            Some(split) => split,
            None => rest.rsplit_once(':')?,
        };
        if host.is_empty() || repository.is_empty() || reference.is_empty() {
            return None;
        }
        Some(Self {
            host: host.to_owned(),
            repository: repository.to_owned(),
            reference: reference.to_owned(),
        })
    }
}

/// What a registry read of one plugin source found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackagedLayout {
    /// The artefact records this layout.
    Recorded(String),
    /// The artefact was packaged before the field, or carries another
    /// config: only a load can tell.
    NotRecorded,
    /// The registry has none of the artefacts the gateway would try.
    Missing,
    /// The registry could not be read.
    Unreadable(String),
}

/// One `plugins[]` source of a config and what a read of it found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbedPlugin {
    /// Its index in `plugins[]`.
    pub index: usize,
    /// The source as the config writes it.
    pub reference: String,
    /// The artefact the finding is about; `None` when no artefact was found.
    pub artefact: Option<String>,
    pub found: PackagedLayout,
}

/// What the plugins of a config mean for the blessed release.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LayoutAssessment {
    /// What holds the publish: the gateway would refuse these at load or at
    /// boot.
    pub violations: Vec<TargetViolation>,
    /// What the publisher should know, one sentence each.
    pub warnings: Vec<String>,
    /// One outcome per plugin source: `ok`, `mismatch`, `missing`,
    /// `not_recorded`, `unreadable` or `custom`.
    pub outcomes: Vec<&'static str>,
}

/// The release a config is judged against.
#[derive(Debug, Clone, Copy)]
pub struct TargetRelease<'a> {
    pub gateway_version: &'a str,
    pub abi_layout: &'a str,
    pub platform: &'a str,
}

/// Judge the first-party sources `probed` and the `custom` ones, which are
/// not read, against `release`.
pub fn assess(
    release: TargetRelease<'_>,
    probed: &[ProbedPlugin],
    custom: &[(usize, String)],
) -> LayoutAssessment {
    let mut out = LayoutAssessment::default();
    let version = release.gateway_version;
    let mut not_recorded = Vec::new();
    for p in probed {
        let at = format!("plugins[{}]", p.index);
        let artefact = p.artefact.as_deref().unwrap_or(&p.reference);
        match &p.found {
            PackagedLayout::Recorded(layout) if layout == release.abi_layout => {
                out.outcomes.push("ok");
            }
            PackagedLayout::Recorded(layout) => {
                out.outcomes.push("mismatch");
                out.violations.push(TargetViolation {
                    kind: "plugin_abi_layout_mismatch",
                    detail: format!(
                        "{at}: `{artefact}` was packaged for ABI layout {layout}, and gateway \
                         {version} has {}: the gateway refuses it at load. Pin a release of the \
                         plugin packaged for gateway {version}",
                        release.abi_layout
                    ),
                });
            }
            PackagedLayout::Missing => {
                out.outcomes.push("missing");
                out.violations.push(TargetViolation {
                    kind: "plugin_artifact_missing",
                    detail: format!(
                        "{at}: `{}` has no artefact for {} or {PORTABLE}: the gateway fails at \
                         boot",
                        p.reference, release.platform
                    ),
                });
            }
            PackagedLayout::NotRecorded => {
                out.outcomes.push("not_recorded");
                not_recorded.push(format!("{at} `{artefact}`"));
            }
            PackagedLayout::Unreadable(reason) => {
                out.outcomes.push("unreadable");
                out.warnings.push(format!(
                    "{at}: `{}` could not be checked against gateway {version}'s ABI layout \
                     ({reason}); the gateway checks it at load",
                    p.reference
                ));
            }
        }
    }
    if !not_recorded.is_empty() {
        out.warnings.push(format!(
            "{} plugin(s) were packaged before ABI layout fingerprints, so only the gateway's \
             load tells whether gateway {version} accepts them: {}",
            not_recorded.len(),
            not_recorded.join(", ")
        ));
    }
    if !custom.is_empty() {
        out.outcomes
            .extend(std::iter::repeat_n("custom", custom.len()));
        let listed: Vec<String> = custom
            .iter()
            .map(|(i, r)| format!("plugins[{i}] `{r}`"))
            .collect();
        out.warnings.push(format!(
            "{} plugin(s) from another registry are not checked against gateway {version}'s ABI \
             layout before load: {}",
            custom.len(),
            listed.join(", ")
        ));
    }
    out
}

/// A config's `plugins[]` sources: each index and the source as written.
pub type Sources = Vec<(usize, String)>;

/// Split a config's `oci:` sources into the first-party ones, which the
/// control plane reads, and the rest.
pub fn split_sources(sources: Sources) -> (Sources, Sources) {
    sources
        .into_iter()
        .partition(|(_, r)| is_first_party_plugin_ref(r))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELEASE: TargetRelease<'static> = TargetRelease {
        gateway_version: "0.1.0-beta.66",
        abi_layout: "sha256:00112233445566778899aabbccddeeff",
        platform: "linux-amd64",
    };

    #[test]
    fn a_source_resolves_to_the_artefacts_the_gateway_tries() {
        let p = "ghcr.io/mcpg-dev/plugins/identity-oidc";
        assert_eq!(
            candidates(p, "linux-amd64", "1"),
            [
                format!("{p}:protocol-1-linux-amd64"),
                format!("{p}:protocol-1-wasi-wasm")
            ]
        );
        assert_eq!(
            candidates(&format!("oci://{p}:0.1.0-alpha.46"), "linux-arm64", "1"),
            [
                format!("{p}:0.1.0-alpha.46-linux-arm64"),
                format!("{p}:0.1.0-alpha.46-wasi-wasm")
            ]
        );
        for written in [
            format!("{p}:0.1.0-alpha.46-linux-amd64"),
            format!("{p}:protocol-1-wasi-wasm"),
            format!("{p}@sha256:{}", "a".repeat(64)),
        ] {
            assert_eq!(
                candidates(&written, "linux-amd64", "1"),
                std::slice::from_ref(&written)
            );
        }
        assert_eq!(
            candidates("registry.local:5000/plugins/x", "linux-amd64", "1")[0],
            "registry.local:5000/plugins/x:protocol-1-linux-amd64",
            "a port is not a tag"
        );
    }

    #[test]
    fn an_artefact_parses_into_host_repository_and_reference() {
        assert_eq!(
            ArtefactRef::parse("ghcr.io/mcpg-dev/plugins/identity-oidc:0.1.0-linux-amd64"),
            Some(ArtefactRef {
                host: "ghcr.io".into(),
                repository: "mcpg-dev/plugins/identity-oidc".into(),
                reference: "0.1.0-linux-amd64".into(),
            })
        );
        let digest = format!("sha256:{}", "b".repeat(64));
        assert_eq!(
            ArtefactRef::parse(&format!("ghcr.io/mcpg-dev/plugins/x@{digest}"))
                .map(|a| a.reference),
            Some(digest)
        );
        assert_eq!(ArtefactRef::parse("no-host"), None);
        assert_eq!(ArtefactRef::parse("ghcr.io/repo-without-tag"), None);
    }

    #[test]
    fn platforms_and_protocol_majors() {
        assert!(is_native_platform("linux-amd64"));
        assert!(is_native_platform("linux-musl-arm64"));
        assert!(!is_native_platform("wasi-wasm"));
        assert!(!is_native_platform("linux-x86"));
        assert_eq!(protocol_major("1.0"), "1");
        assert_eq!(protocol_major("2"), "2");
    }

    fn probed(index: usize, found: PackagedLayout) -> ProbedPlugin {
        ProbedPlugin {
            index,
            reference: format!("ghcr.io/mcpg-dev/plugins/p{index}:1.0.0"),
            artefact: matches!(
                found,
                PackagedLayout::Recorded(_) | PackagedLayout::NotRecorded
            )
            .then(|| format!("ghcr.io/mcpg-dev/plugins/p{index}:1.0.0-linux-amd64")),
            found,
        }
    }

    #[test]
    fn a_first_party_plugin_of_another_layout_or_with_no_artefact_holds_the_publish() {
        let a = assess(
            RELEASE,
            &[
                probed(0, PackagedLayout::Recorded(RELEASE.abi_layout.into())),
                probed(
                    1,
                    PackagedLayout::Recorded("sha256:ffffffffffffffffffffffffffffffff".into()),
                ),
                probed(2, PackagedLayout::Missing),
            ],
            &[],
        );
        assert_eq!(a.outcomes, ["ok", "mismatch", "missing"]);
        assert_eq!(a.violations.len(), 2);
        assert_eq!(a.violations[0].kind, "plugin_abi_layout_mismatch");
        assert!(
            a.violations[0].detail.starts_with(
                "plugins[1]: `ghcr.io/mcpg-dev/plugins/p1:1.0.0-linux-amd64` was packaged for ABI \
                 layout sha256:ffffffffffffffffffffffffffffffff, and gateway 0.1.0-beta.66 has \
                 sha256:00112233445566778899aabbccddeeff"
            ),
            "{}",
            a.violations[0].detail
        );
        assert_eq!(a.violations[1].kind, "plugin_artifact_missing");
        assert!(a.violations[1].detail.contains("linux-amd64 or wasi-wasm"));
        assert!(a.warnings.is_empty());
    }

    #[test]
    fn what_cannot_be_judged_is_a_warning() {
        let a = assess(
            RELEASE,
            &[
                probed(0, PackagedLayout::NotRecorded),
                probed(1, PackagedLayout::NotRecorded),
                probed(
                    2,
                    PackagedLayout::Unreadable("registry answered 503".into()),
                ),
            ],
            &[(3, "registry.example.com/team/plugin:2.0.0".into())],
        );
        assert!(a.violations.is_empty());
        assert_eq!(
            a.outcomes,
            ["not_recorded", "not_recorded", "unreadable", "custom"]
        );
        assert_eq!(a.warnings.len(), 3);
        assert!(a.warnings[0].contains("registry answered 503"), "{a:?}");
        assert!(
            a.warnings[1].starts_with("2 plugin(s) were packaged before ABI layout fingerprints"),
            "{a:?}"
        );
        assert!(
            a.warnings[2].contains("plugins[3] `registry.example.com/team/plugin:2.0.0`"),
            "{a:?}"
        );
    }

    #[test]
    fn first_party_sources_are_split_from_the_rest() {
        let (first, other) = split_sources(vec![
            (0, "ghcr.io/mcpg-dev/plugins/identity-oidc:1".into()),
            (1, "oci://ghcr.io/mcpg-dev/plugins/backend-http".into()),
            (2, "ghcr.io/someone/plugins/x:1".into()),
        ]);
        assert_eq!(first.iter().map(|(i, _)| *i).collect::<Vec<_>>(), [0, 1]);
        assert_eq!(other.iter().map(|(i, _)| *i).collect::<Vec<_>>(), [2]);
    }
}
