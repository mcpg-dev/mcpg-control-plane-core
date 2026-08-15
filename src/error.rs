//! Top-level error and Result types for `cp-core`.
//!
//! Every cp-core API returns `Result<T, Error>`. Server code wraps
//! these with axum / tonic-specific error types at the boundary.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("not found: {0}")]
    NotFound(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("license: {0}")]
    License(#[from] crate::license::LicenseError),

    #[error("quota exceeded: {resource}: current={current}, max={max}")]
    QuotaExceeded {
        resource: String,
        current: u64,
        max: u64,
    },

    #[error("provider {provider} unsupported: {operation}")]
    Unsupported {
        provider: &'static str,
        operation: &'static str,
    },

    #[error("db: {0}")]
    Db(#[from] sqlx::Error),

    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("internal: {0}")]
    Internal(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
