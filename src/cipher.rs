//! Envelope encryption primitive for sensitive at-rest data
//! (per-tenant KMS DEK envelope encryption).
//!
//! v0 ships two implementations:
//!
//! - **`NoopCipher`** — pass-through, used when no master key is
//!   configured (Tier-0 / dev / self-host). Existing DB rows
//!   stay readable; no extra security but no operational
//!   overhead either.
//!
//! - **`LocalCipher`** — AES-256-GCM with a single 32-byte master
//!   key from config (`kms_master_key_b64`). Per-tenant
//!   cryptographic isolation comes from binding the tenant slug
//!   into AEAD associated data: an attacker who steals one
//!   tenant's ciphertext can't decrypt it as a different
//!   tenant, even with the same master key.
//!
//! Production Cloud builds will swap in a `KmsCipher` (behind a
//! feature flag, deferred) that delegates `encrypt` / `decrypt`
//! to AWS KMS / GCP KMS / Azure KeyVault. The trait shape stays
//! the same so call sites don't change.
//!
//! Lives in `cp-core` so every control-plane + cloud binary (CP
//! server, provisioner, …) shares one implementation. Context
//! (the AAD) is a caller-chosen string — a tenant slug for CP
//! payloads, a `cluster_id` for provisioner credentials.
//!
//! Wire format: `nonce(12) || ciphertext`. Nonce is freshly
//! generated per call. The master key is never written to the
//! wire — only the AEAD authentication tag travels with the
//! ciphertext, and decryption requires the same master key +
//! context.

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use async_trait::async_trait;
use base64::Engine as _;

#[derive(thiserror::Error, Debug)]
pub enum CipherError {
    #[error("invalid master key: must be base64-encoded 32 bytes (got {0} bytes)")]
    BadKey(usize),
    #[error("ciphertext too short to contain nonce")]
    Truncated,
    #[error("AEAD decryption failed (tampered or wrong tenant context)")]
    DecryptFailed,
    #[error("AEAD encryption failed: {0}")]
    EncryptFailed(String),
    #[error(
        "at-rest encryption is required but no master key / KMS is configured — \
         refusing to fall back to the plaintext NoopCipher"
    )]
    EncryptionRequired,
    #[error("KMS error: {0}")]
    Kms(String),
}

#[async_trait]
pub trait EnvelopeCipher: Send + Sync {
    /// Encrypt `plaintext` bound to `context`. Returns
    /// `nonce || ciphertext` ready for storage. The context
    /// becomes the AEAD AAD so decryption with a different
    /// context fails — defense against cross-tenant blob swap
    /// on a compromised DB.
    async fn encrypt(&self, context: &str, plaintext: &[u8]) -> Result<Vec<u8>, CipherError>;

    async fn decrypt(&self, context: &str, ciphertext: &[u8]) -> Result<Vec<u8>, CipherError>;
}

/// Pass-through cipher — used when no master key is configured.
/// Encrypt and decrypt return their input unchanged.
#[derive(Clone, Default)]
pub struct NoopCipher;

#[async_trait]
impl EnvelopeCipher for NoopCipher {
    async fn encrypt(&self, _context: &str, plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
        Ok(plaintext.to_vec())
    }
    async fn decrypt(&self, _context: &str, ciphertext: &[u8]) -> Result<Vec<u8>, CipherError> {
        Ok(ciphertext.to_vec())
    }
}

/// AES-256-GCM cipher with a configured 32-byte master key. Per-
/// context isolation via AAD = context bytes.
#[derive(Clone)]
pub struct LocalCipher {
    cipher: Aes256Gcm,
}

impl LocalCipher {
    /// `master_key_b64` is a base64-encoded 32 bytes (random,
    /// generated once and stored alongside the DB key material).
    pub fn from_master_key_b64(master_key_b64: &str) -> Result<Self, CipherError> {
        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(master_key_b64)
            .map_err(|_| CipherError::BadKey(0))?;
        if key_bytes.len() != 32 {
            return Err(CipherError::BadKey(key_bytes.len()));
        }
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        Ok(Self {
            cipher: Aes256Gcm::new(key),
        })
    }
}

#[async_trait]
impl EnvelopeCipher for LocalCipher {
    async fn encrypt(&self, context: &str, plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ct = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: context.as_bytes(),
                },
            )
            .map_err(|e| CipherError::EncryptFailed(format!("{e}")))?;
        let mut out = Vec::with_capacity(nonce.len() + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    async fn decrypt(&self, context: &str, ciphertext: &[u8]) -> Result<Vec<u8>, CipherError> {
        if ciphertext.len() < 12 {
            return Err(CipherError::Truncated);
        }
        let (nonce_bytes, ct) = ciphertext.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        self.cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ct,
                    aad: context.as_bytes(),
                },
            )
            .map_err(|_| CipherError::DecryptFailed)
    }
}

/// Build the right cipher for the configured master key. None ⇒
/// Noop (Tier-0 / dev), Some ⇒ LocalCipher.
pub fn build(
    master_key_b64: Option<&str>,
) -> Result<std::sync::Arc<dyn EnvelopeCipher>, CipherError> {
    match master_key_b64 {
        Some(k) if !k.is_empty() => Ok(std::sync::Arc::new(LocalCipher::from_master_key_b64(k)?)),
        _ => Ok(std::sync::Arc::new(NoopCipher)),
    }
}

/// Fail-closed variant of [`build`]. When `require_encryption` is set and no
/// usable master key is configured, returns [`CipherError::EncryptionRequired`]
/// instead of silently falling back to the plaintext [`NoopCipher`]. Managed /
/// production deployments pass `require_encryption = true` so secrets at rest
/// (cluster kubeconfigs, payload DEKs, CA private key) can never be persisted in
/// the clear by accident. The key is trimmed and empty-checked here so a
/// whitespace-only value is treated as unset (and refused under the guard).
pub fn build_strict(
    master_key_b64: Option<&str>,
    require_encryption: bool,
) -> Result<std::sync::Arc<dyn EnvelopeCipher>, CipherError> {
    let key = master_key_b64.map(str::trim).filter(|k| !k.is_empty());
    match key {
        Some(k) => Ok(std::sync::Arc::new(LocalCipher::from_master_key_b64(k)?)),
        None if require_encryption => Err(CipherError::EncryptionRequired),
        None => Ok(std::sync::Arc::new(NoopCipher)),
    }
}

/// HashiCorp Vault Transit KMS backend (feature `kms`). Delegates encrypt /
/// decrypt to a Vault Transit key over HTTP, so the master key never leaves the
/// KMS — only `vault:vN:…` ciphertexts are stored. The caller-chosen `context`
/// is passed as Transit's derivation `context`, so a Transit key created with
/// `derived=true` gives the same per-context (per-tenant / per-cluster) crypto
/// isolation as `LocalCipher`'s AAD. Cloud-agnostic and self-hostable; AWS KMS /
/// GCP KMS impls can follow the same [`EnvelopeCipher`] shape.
#[cfg(feature = "kms")]
#[derive(Clone, Debug)]
pub struct VaultKmsConfig {
    /// Vault address, e.g. `https://vault.internal:8200`.
    pub addr: String,
    /// Vault token (`X-Vault-Token`).
    pub token: String,
    /// Transit mount path (usually `transit`).
    pub mount: String,
    /// Transit key name.
    pub key: String,
}

#[cfg(feature = "kms")]
pub struct VaultTransitCipher {
    cfg: VaultKmsConfig,
    http: reqwest::Client,
}

#[cfg(feature = "kms")]
impl VaultTransitCipher {
    pub fn new(cfg: VaultKmsConfig) -> Result<Self, CipherError> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| CipherError::Kms(format!("http client: {e}")))?;
        Ok(Self { cfg, http })
    }

    fn url(&self, op: &str) -> String {
        format!(
            "{}/v1/{}/{}/{}",
            self.cfg.addr.trim_end_matches('/'),
            self.cfg.mount.trim_matches('/'),
            op,
            self.cfg.key,
        )
    }

    async fn call(
        &self,
        op: &str,
        body: serde_json::Value,
        field: &str,
    ) -> Result<String, CipherError> {
        let resp = self
            .http
            .post(self.url(op))
            .header("X-Vault-Token", &self.cfg.token)
            .json(&body)
            .send()
            .await
            .map_err(|e| CipherError::Kms(format!("vault {op}: {e}")))?;
        if !resp.status().is_success() {
            return Err(CipherError::Kms(format!(
                "vault {op}: status {}",
                resp.status()
            )));
        }
        let v: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| CipherError::Kms(format!("vault {op}: bad body: {e}")))?;
        v["data"][field]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| CipherError::Kms(format!("vault {op}: missing data.{field}")))
    }
}

#[cfg(feature = "kms")]
#[async_trait]
impl EnvelopeCipher for VaultTransitCipher {
    async fn encrypt(&self, context: &str, plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let ct = self
            .call(
                "encrypt",
                serde_json::json!({
                    "plaintext": b64.encode(plaintext),
                    "context": b64.encode(context.as_bytes()),
                }),
                "ciphertext",
            )
            .await?;
        // Store the `vault:vN:…` token verbatim; it round-trips through decrypt.
        Ok(ct.into_bytes())
    }

    async fn decrypt(&self, context: &str, ciphertext: &[u8]) -> Result<Vec<u8>, CipherError> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let ct_str = std::str::from_utf8(ciphertext).map_err(|_| CipherError::DecryptFailed)?;
        let pt_b64 = self
            .call(
                "decrypt",
                serde_json::json!({
                    "ciphertext": ct_str,
                    "context": b64.encode(context.as_bytes()),
                }),
                "plaintext",
            )
            .await?;
        b64.decode(pt_b64).map_err(|_| CipherError::DecryptFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_master_key_b64() -> String {
        let mut bytes = [0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    #[tokio::test]
    async fn noop_passes_through() {
        let c = NoopCipher;
        let pt = b"hello".to_vec();
        let ct = c.encrypt("acme", &pt).await.unwrap();
        assert_eq!(ct, pt);
        let pt2 = c.decrypt("acme", &ct).await.unwrap();
        assert_eq!(pt2, pt);
    }

    #[tokio::test]
    async fn local_round_trip() {
        let c = LocalCipher::from_master_key_b64(&fresh_master_key_b64()).unwrap();
        let pt = b"sensitive license payload".to_vec();
        let ct = c.encrypt("acme", &pt).await.unwrap();
        assert_ne!(ct, pt);
        // Length: 12-byte nonce + ct + 16-byte tag.
        assert_eq!(ct.len(), 12 + pt.len() + 16);
        let pt2 = c.decrypt("acme", &ct).await.unwrap();
        assert_eq!(pt2, pt);
    }

    #[tokio::test]
    async fn local_rejects_cross_context_decrypt() {
        let c = LocalCipher::from_master_key_b64(&fresh_master_key_b64()).unwrap();
        let ct = c.encrypt("acme", b"payload").await.unwrap();
        // Same key, different context → decryption fails.
        let err = c.decrypt("globex", &ct).await.unwrap_err();
        assert!(matches!(err, CipherError::DecryptFailed));
    }

    #[tokio::test]
    async fn local_rejects_tampered_ciphertext() {
        let c = LocalCipher::from_master_key_b64(&fresh_master_key_b64()).unwrap();
        let mut ct = c.encrypt("acme", b"payload").await.unwrap();
        // Flip a byte in the ciphertext (after the 12-byte nonce
        // so we hit the encrypted-payload region).
        ct[15] ^= 0x01;
        let err = c.decrypt("acme", &ct).await.unwrap_err();
        assert!(matches!(err, CipherError::DecryptFailed));
    }

    #[tokio::test]
    async fn local_rejects_truncated_ciphertext() {
        let c = LocalCipher::from_master_key_b64(&fresh_master_key_b64()).unwrap();
        let err = c.decrypt("acme", &[0u8; 5]).await.unwrap_err();
        assert!(matches!(err, CipherError::Truncated));
    }

    #[tokio::test]
    async fn build_returns_noop_for_none() {
        let c = build(None).unwrap();
        let ct = c.encrypt("x", b"hi").await.unwrap();
        assert_eq!(ct, b"hi");
    }

    #[test]
    fn rejects_short_master_key() {
        let bad = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        match LocalCipher::from_master_key_b64(&bad) {
            Err(CipherError::BadKey(16)) => {}
            other => panic!("expected BadKey(16); got {:?}", other.err()),
        }
    }

    #[tokio::test]
    async fn build_strict_refuses_noop_when_encryption_required() {
        // No key + require_encryption ⇒ refuse to boot (no silent plaintext).
        // (Match on the Result — the Ok type `Arc<dyn EnvelopeCipher>` is not Debug.)
        assert!(matches!(
            build_strict(None, true),
            Err(CipherError::EncryptionRequired)
        ));
        // A whitespace-only key is treated as unset and also refused.
        assert!(matches!(
            build_strict(Some("   "), true),
            Err(CipherError::EncryptionRequired)
        ));
    }

    #[tokio::test]
    async fn build_strict_allows_noop_when_not_required_and_local_with_key() {
        // require_encryption=false ⇒ Noop fallback is fine (self-host / dev).
        let noop = build_strict(None, false).unwrap();
        assert_eq!(noop.encrypt("x", b"hi").await.unwrap(), b"hi");
        // A real key ⇒ LocalCipher, regardless of the require flag.
        let local = build_strict(Some(&fresh_master_key_b64()), true).unwrap();
        let ct = local.encrypt("acme", b"secret").await.unwrap();
        assert_ne!(ct, b"secret");
        assert_eq!(local.decrypt("acme", &ct).await.unwrap(), b"secret");
    }

    #[cfg(feature = "kms")]
    #[tokio::test]
    async fn vault_transit_encrypt_decrypt_over_http() {
        use wiremock::matchers::{body_partial_json, header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let b64 = base64::engine::general_purpose::STANDARD;
        let vault = MockServer::start().await;

        // encrypt: requires our token + the base64 plaintext + context; returns
        // a Transit ciphertext token.
        Mock::given(method("POST"))
            .and(path("/v1/transit/encrypt/mcpg"))
            .and(header("x-vault-token", "tok"))
            .and(body_partial_json(serde_json::json!({
                "plaintext": b64.encode(b"sa-token-secret"),
                "context": b64.encode(b"cluster-1"),
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "ciphertext": "vault:v1:ABCDEF" }
            })))
            .mount(&vault)
            .await;
        // decrypt: echoes the plaintext back (base64) for the known ciphertext.
        Mock::given(method("POST"))
            .and(path("/v1/transit/decrypt/mcpg"))
            .and(body_partial_json(
                serde_json::json!({ "ciphertext": "vault:v1:ABCDEF" }),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "plaintext": b64.encode(b"sa-token-secret") }
            })))
            .mount(&vault)
            .await;

        let cipher = VaultTransitCipher::new(VaultKmsConfig {
            addr: vault.uri(),
            token: "tok".into(),
            mount: "transit".into(),
            key: "mcpg".into(),
        })
        .unwrap();
        let ct = cipher
            .encrypt("cluster-1", b"sa-token-secret")
            .await
            .unwrap();
        assert_eq!(ct, b"vault:v1:ABCDEF");
        let pt = cipher.decrypt("cluster-1", &ct).await.unwrap();
        assert_eq!(pt, b"sa-token-secret");
    }
}
