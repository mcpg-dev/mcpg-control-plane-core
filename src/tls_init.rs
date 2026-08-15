//! rustls process-default `CryptoProvider` installer.
//!
//! Required because jsonwebtoken 10.x with the `aws_lc_rs` feature
//! pulls aws-lc-rs into the workspace dep graph alongside ring
//! (which sqlx / reqwest / kube / tonic transitively pull). rustls
//! 0.23 then refuses to auto-pick a provider and panics on the
//! first TLS handshake:
//!
//! ```text
//! Could not automatically determine the process-level
//! CryptoProvider … exactly one of 'aws-lc-rs' and 'ring' features
//! must be enabled
//! ```
//!
//! The fix is a one-shot install at process boot. The gateway has
//! its own copy at `apps/gateway/src/transports/tls.rs`; this is
//! the shared cp-side equivalent. Both cp-server and cloud-provisioner
//! call this from their `AppState::build` / `AppState::initialize`
//! choke-points so production binaries and integration tests pick
//! it up automatically.

use std::sync::Once;

/// Install aws-lc-rs as the rustls process-default `CryptoProvider`.
/// Idempotent — safe to call from anywhere.
pub fn install_default_crypto_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // install_default returns Err if another caller already
        // installed a provider; that's fine — whatever-was-installed
        // wins. We just need *some* provider to be the default.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}
