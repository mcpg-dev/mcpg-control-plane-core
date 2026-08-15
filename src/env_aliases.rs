//! Long-form env var aliases for the control-plane CLIs.
//!
//! `mcpg-cp` and `mcpg-admin` use `MCPG_CP_*` env vars by default —
//! the prefix is short, established, and matches the binaries' clap
//! output. For operators who prefer the explicit spelling we also
//! accept `MCPG_CONTROL_PLANE_*` as a synonym for every `MCPG_CP_*`
//! variable.
//!
//! clap only takes a single `env = "..."` per argument, so we can't
//! declare both names at the arg level. Instead, [`mirror_long_to_short`]
//! runs once at process start, before [`clap::Parser::parse`], and
//! copies any `MCPG_CONTROL_PLANE_X` value into `MCPG_CP_X` if the
//! short form isn't already set. clap then reads the short form
//! transparently.
//!
//! Precedence: `MCPG_CP_*` (if set) wins over `MCPG_CONTROL_PLANE_*`.
//! The shell environment is the source of truth — a deployment that
//! sets the canonical short form keeps using it; a deployment that
//! prefers the explicit long form sets that and never has to think
//! about the alias.

const SHORT: &str = "MCPG_CP_";
const LONG: &str = "MCPG_CONTROL_PLANE_";

/// Mirror `MCPG_CONTROL_PLANE_X` → `MCPG_CP_X` for any `X` whose
/// short form is unset.
///
/// Must be called from a single-threaded context — typically as the
/// first statement in `main()`, before tokio is spawned and before
/// `clap::Parser::parse()`. Calling it later is unsafe in the Rust
/// 2024 edition (`std::env::set_var` is `unsafe` because env-var
/// mutation is racy with reads from other threads).
pub fn mirror_long_to_short() {
    // Snapshot first so we don't mutate the iterator we're walking.
    let pending: Vec<(String, std::ffi::OsString)> = std::env::vars_os()
        .filter_map(|(k, v)| {
            let key = k.to_str()?;
            let suffix = key.strip_prefix(LONG)?;
            let short = format!("{SHORT}{suffix}");
            if std::env::var_os(&short).is_some() {
                // Short form already set — short wins.
                return None;
            }
            Some((short, v))
        })
        .collect();
    for (short, value) in pending {
        // SAFETY: callers contract this pre-clap, before any thread
        // is spawned. Aliasing a known-unset env var is safe at that
        // point. See module doc.
        unsafe { std::env::set_var(&short, &value) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test the mirror logic. Uses a unique prefix per test
    /// (timestamp + pid) because env vars are process-global.
    #[test]
    fn mirrors_long_to_short_when_short_unset() {
        let suffix = format!("TEST_MIRROR_{}", std::process::id());
        let short = format!("{SHORT}{suffix}");
        let long = format!("{LONG}{suffix}");
        // SAFETY: single-threaded test, no other threads touch these.
        unsafe { std::env::set_var(&long, "long-value") };
        unsafe { std::env::remove_var(&short) };

        mirror_long_to_short();

        assert_eq!(std::env::var(&short).as_deref(), Ok("long-value"));

        // Cleanup.
        unsafe { std::env::remove_var(&long) };
        unsafe { std::env::remove_var(&short) };
    }

    #[test]
    fn short_wins_when_both_set() {
        let suffix = format!("TEST_PRECEDENCE_{}", std::process::id());
        let short = format!("{SHORT}{suffix}");
        let long = format!("{LONG}{suffix}");
        unsafe { std::env::set_var(&short, "short-wins") };
        unsafe { std::env::set_var(&long, "long-loses") };

        mirror_long_to_short();

        assert_eq!(std::env::var(&short).as_deref(), Ok("short-wins"));

        unsafe { std::env::remove_var(&long) };
        unsafe { std::env::remove_var(&short) };
    }

    #[test]
    fn ignores_unrelated_vars() {
        let other = format!("UNRELATED_{}", std::process::id());
        unsafe { std::env::set_var(&other, "x") };
        mirror_long_to_short();
        assert_eq!(std::env::var(&other).as_deref(), Ok("x"));
        unsafe { std::env::remove_var(&other) };
    }
}
