//! `InstanceProvider` trait — the discovery abstraction.
//!
//! Implementations live in `cp-server` (Static,
//! SelfRegistration) and `cloud-provisioner` (Kube). Composite
//! is a thin combinator.

use std::collections::BTreeMap;

use async_trait::async_trait;
use futures::stream::BoxStream;
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::ids::{EnvironmentId, InstanceId, OrgId, WorkspaceId};
use crate::model::{Instance, InstanceState, ProviderName};

/// Discovery + lifecycle abstraction.
#[async_trait]
pub trait InstanceProvider: Send + Sync + 'static {
    /// Stable identifier; appears in metric labels + audit logs.
    fn name(&self) -> &'static str;

    /// One-shot list, scoped to the given Org.
    async fn list(&self, org: OrgId) -> Result<Vec<Instance>>;

    /// Long-lived event stream of changes. Implementations may
    /// emit `Added` / `Updated` / `Departed`.
    fn watch(&self, org: OrgId) -> BoxStream<'static, Result<InstanceEvent>>;

    /// Optional: register a new instance via this provider.
    /// Most providers return `Err(Unsupported)`. Only
    /// `SelfRegistrationProvider` supports it as the primary
    /// path.
    async fn register(&self, _org: OrgId, _claim: RegistrationClaim) -> Result<Instance> {
        Err(crate::error::Error::Unsupported {
            provider: "default",
            operation: "register",
        })
    }

    /// Optional: deregister.
    async fn deregister(&self, _org: OrgId, _id: InstanceId) -> Result<()> {
        Err(crate::error::Error::Unsupported {
            provider: "default",
            operation: "deregister",
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InstanceEvent {
    Added(Instance),
    Updated(Instance),
    Departed {
        id: InstanceId,
        reason: DepartedReason,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DepartedReason {
    GracefulShutdown,
    HeartbeatTimeout,
    OperatorRevoked,
    ProviderRemoved,
}

/// Claim presented by a self-registering instance. Matches the
/// `Register` gRPC request (see proto/mcpg/cp/v1/agent.proto).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistrationClaim {
    pub workspace_id: WorkspaceId,
    pub environment_id: EnvironmentId,
    pub instance_uid: String,
    pub version: String,
    pub labels: BTreeMap<String, String>,
    pub capabilities: Vec<String>,
    pub addressable_endpoints: Vec<AddressableEndpoint>,
    pub discovered_via: ProviderName,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressableEndpoint {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path_prefix: String,
}

/// Returns whether the given state is considered "live" for
/// purposes of inventory dashboards.
pub fn is_live(state: InstanceState) -> bool {
    matches!(state, InstanceState::Online | InstanceState::Stale)
}
