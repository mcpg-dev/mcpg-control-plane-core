//! `mcpg-control-plane-core` — shared types, traits, and protocol
//! definitions for the MCPG Control Plane.
//!
//! This crate is consumed by:
//! - `mcpg-control-plane-server` — the CP (binary `mcpg-cp`: HTTP API +
//!   gRPC server).
//! - `mcpg-admin` — the platform-operator CLI (tenant-claim slug rules).
//! - `mcpg-control-plane-client` — the gateway-side plugin
//!   that registers and pulls config.
//! - `mcpg-cloud-federation` (Cloud-only) — license issuer service.
//! - `mcpg-cloud-provisioner` (Cloud-only) — gateway provisioning.

pub mod cipher;
pub mod env_aliases;
pub mod error;
pub use mcpg_control_plane_license::ids;
pub use mcpg_control_plane_license::license;
pub mod model;
pub mod provider;
pub mod publish_guard;
pub mod ratelimit;
pub mod tls_init;
pub mod usage_report;

/// gRPC types compiled from `proto/mcpg/cp/v1/agent.proto`.
///
/// The proto package is `mcpg.cp.v1`; the wire contract is a
/// public stability commitment.
pub mod proto {
    tonic::include_proto!("mcpg.cp.v1");
}

pub use cipher::{CipherError, EnvelopeCipher, LocalCipher, NoopCipher};
pub use error::{Error, Result};
pub use ids::{
    EnvironmentId, InstanceId, InstanceSlug, OrgId, OrgSlug, RESERVED_SLUGS, SessionId, UserId,
    WorkspaceId, WorkspaceSlug, is_reserved,
};
pub use license::{LicenseClaims, LicenseError, Quotas};
pub use model::{Environment, Instance, InstanceState, Org, PluginEntry, PluginSet, Workspace};
pub use provider::{InstanceEvent, InstanceProvider, RegistrationClaim};
