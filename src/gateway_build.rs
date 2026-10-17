//! Which gateway builds a managed control plane admits.
//!
//! A gateway reports the calls its metrics buffer dropped on overflow, and
//! the control plane bills them. Builds released before the overflow split
//! reported every dropped sample as billable, refusals and replays included,
//! so an org running one is billed for calls that never ran. A managed
//! publish and a gateway enrollment refuse such a build; a release cut
//! later carries the split.
//!
//! Versions are the release versions a gateway reports (`0.1.0-beta.58`,
//! with or without a leading `v`). The `0.0.0` an unreleased build carries,
//! and a version that does not parse, say nothing about the build and are
//! not refused here.

use std::cmp::Ordering;

/// The last gateway release on each pre-release channel of the `0.1.0` line
/// that was built before the metrics overflow split. A channel cut from a
/// branch the split has not reached yet (the beta channel is cut from `main`)
/// can release another such build, which belongs here too.
pub const LAST_BEFORE_OVERFLOW_SPLIT: &[(&str, u64)] =
    &[("alpha", 1), ("beta", 59), ("canary", 917)];

/// A gateway release version: `major.minor.patch` and an optional
/// pre-release.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayVersion {
    pub core: (u64, u64, u64),
    pub pre: Vec<String>,
}

impl GatewayVersion {
    /// Parse `version`, tolerating a leading `v` and ignoring build metadata.
    pub fn parse(version: &str) -> Option<Self> {
        let v = version.trim();
        let v = v.strip_prefix('v').unwrap_or(v);
        let v = v.split('+').next()?;
        let (core, pre) = match v.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (v, None),
        };
        let mut parts = core.split('.');
        let mut next = || parts.next()?.parse::<u64>().ok();
        let core = (next()?, next()?, next()?);
        if parts.next().is_some() {
            return None;
        }
        let pre = match pre {
            Some(p) if p.is_empty() || p.split('.').any(str::is_empty) => return None,
            Some(p) => p.split('.').map(str::to_owned).collect(),
            None => Vec::new(),
        };
        Some(Self { core, pre })
    }

    /// The `0.0.0` an unreleased build reports.
    pub fn is_unreleased(&self) -> bool {
        self.core == (0, 0, 0) && self.pre.is_empty()
    }
}

impl Ord for GatewayVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.core
            .cmp(&other.core)
            .then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => {
                    for (a, b) in self.pre.iter().zip(&other.pre) {
                        let o = match (a.parse::<u64>(), b.parse::<u64>()) {
                            (Ok(x), Ok(y)) => x.cmp(&y),
                            (Ok(_), Err(_)) => Ordering::Less,
                            (Err(_), Ok(_)) => Ordering::Greater,
                            (Err(_), Err(_)) => a.cmp(b),
                        };
                        if o != Ordering::Equal {
                            return o;
                        }
                    }
                    self.pre.len().cmp(&other.pre.len())
                }
            })
    }
}

impl std::fmt::Display for GatewayVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (major, minor, patch) = self.core;
        write!(f, "{major}.{minor}.{patch}")?;
        if !self.pre.is_empty() {
            write!(f, "-{}", self.pre.join("."))?;
        }
        Ok(())
    }
}

impl PartialOrd for GatewayVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Whether a gateway reporting `version` was released before the metrics
/// overflow split.
pub fn before_overflow_split(version: &str) -> bool {
    let Some(v) = GatewayVersion::parse(version) else {
        return false;
    };
    if v.is_unreleased() {
        return false;
    }
    match v.core.cmp(&(0, 1, 0)) {
        Ordering::Less => true,
        Ordering::Greater => false,
        Ordering::Equal => match v.pre.as_slice() {
            [channel, n] => LAST_BEFORE_OVERFLOW_SPLIT
                .iter()
                .any(|(c, last)| c == channel && n.parse::<u64>().is_ok_and(|n| n <= *last)),
            _ => false,
        },
    }
}

/// The error code every refusal of an old gateway build carries.
pub const TOO_OLD: &str = "gateway_build_too_old";

/// Why a managed control plane refuses a gateway reporting `version`, or
/// `None` when it admits it.
pub fn overflow_split_refusal(version: &str) -> Option<String> {
    before_overflow_split(version).then(|| {
        format!(
            "gateway {} was released before its metrics report kept refused and \
             replayed calls apart from billable ones; use a later release",
            version.trim()
        )
    })
}

/// Whether `version` is at least `floor`. A version that does not parse is
/// not.
pub fn at_least(version: &str, floor: &GatewayVersion) -> bool {
    GatewayVersion::parse(version).is_some_and(|v| v >= *floor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_released_before_the_split_are_known() {
        for old in [
            "0.1.0-beta.58",
            "0.1.0-beta.59",
            "v0.1.0-beta.1",
            "0.1.0-alpha.1",
            "0.0.2-beta.1",
            "0.1.0-canary.913",
            "0.1.0-canary.915",
            "0.1.0-canary.917",
            "0.1.0-canary.876",
            "0.0.1-beta.14",
        ] {
            assert!(before_overflow_split(old), "{old}");
        }
        for new in [
            "0.1.0-beta.60",
            "0.1.0-canary.920",
            "0.1.0",
            "1.0.0-rc.1",
            "v1.0.0",
            "0.0.0",
            "test",
            "",
        ] {
            assert!(!before_overflow_split(new), "{new}");
        }
    }

    #[test]
    fn versions_order_as_releases_do() {
        let v = |s| GatewayVersion::parse(s).unwrap();
        assert!(v("0.1.0-beta.9") < v("0.1.0-beta.10"));
        assert!(v("0.1.0-beta.58") < v("0.1.0"));
        assert!(v("0.1.0") < v("1.0.0-rc.1"));
        assert!(v("1.0.0-rc.1") < v("1.0.0-rc.1.1"));
        assert!(v("1.0.0-1") < v("1.0.0-rc"));
        assert_eq!(v("v1.2.3+build.5"), v("1.2.3"));
        assert_eq!(v("v1.0.0-rc.3").to_string(), "1.0.0-rc.3");
        for bad in ["1.2", "1.2.3.4", "1.2.3-", "1..3", "x.y.z", "1.2.3-a..b"] {
            assert_eq!(GatewayVersion::parse(bad), None, "{bad}");
        }
        let floor = v("1.0.0-rc.2");
        assert!(at_least("1.0.0-rc.2", &floor));
        assert!(at_least("v1.0.0", &floor));
        assert!(!at_least("1.0.0-rc.1", &floor));
        assert!(!at_least("dev", &floor));
    }
}
