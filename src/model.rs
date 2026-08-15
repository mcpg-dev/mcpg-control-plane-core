//! Domain model shared between CP server, CLI, plugin, and Cloud
//! services. These shapes are persisted in the DB and exposed via
//! the HTTP API.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ids::{EnvironmentId, InstanceId, OrgId, OrgSlug, UserId, WorkspaceId, WorkspaceSlug};

/// Lifecycle status of an [`Org`]. `active` is the default; `suspended`
/// blocks publish/mutation (delinquent / non-paying tenant) while
/// keeping the org readable. `decommissioning` is a terminal, in-progress
/// teardown state — the org is being torn down by the decommission
/// reconciliation loop and finalised via the `deleted_at` soft-delete once
/// every instance + namespace is reclaimed; like `suspended`, it blocks
/// publish. Hard deletion is separate (soft-delete via `deleted_at`).
pub const ORG_STATUS_ACTIVE: &str = "active";
pub const ORG_STATUS_SUSPENDED: &str = "suspended";
pub const ORG_STATUS_DECOMMISSIONING: &str = "decommissioning";

/// Top-level tenant — billing boundary, license JWT scope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Org {
    pub id: OrgId,
    pub slug: OrgSlug,
    pub name: String,
    pub plan_tier: String,
    /// `active` | `suspended` — see [`ORG_STATUS_ACTIVE`].
    pub status: String,
    pub created_at: DateTime<Utc>,
}

impl Org {
    /// True when the org is suspended (delinquent / non-paying) and must
    /// be blocked from publish/mutation while staying readable.
    pub fn is_suspended(&self) -> bool {
        self.status == ORG_STATUS_SUSPENDED
    }

    /// True when the org is being torn down by the decommission reconciler.
    /// Like suspension, this blocks publish (no new workloads into an org
    /// that's going away).
    pub fn is_decommissioning(&self) -> bool {
        self.status == ORG_STATUS_DECOMMISSIONING
    }
}

/// Department / sub-tenant within an Org. Has its own RBAC,
/// quota, and optional SSO connector.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Workspace {
    pub id: WorkspaceId,
    pub org_id: OrgId,
    pub slug: WorkspaceSlug,
    pub name: String,
    pub quota: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

/// Deployment stage within a Workspace (dev / staging / prod).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Environment {
    pub id: EnvironmentId,
    pub workspace_id: WorkspaceId,
    pub slug: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

/// A registered MCPG gateway instance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instance {
    pub id: InstanceId,
    pub org_id: OrgId,
    pub workspace_id: WorkspaceId,
    pub environment_id: EnvironmentId,
    /// Stable, gateway-generated id; persists across restarts.
    pub instance_uid: String,
    pub version: String,
    pub labels: BTreeMap<String, String>,
    pub state: InstanceState,
    pub last_seen_at: Option<DateTime<Utc>>,
    /// Last time this instance actually served traffic. `last_seen_at` is a
    /// heartbeat and moves even when nobody is using it; this does not.
    #[serde(default)]
    pub last_activity_at: Option<DateTime<Utc>>,
    /// Set when the tenant was warned the instance is going idle and will be
    /// reclaimed; cleared by any traffic.
    #[serde(default)]
    pub idle_warned_at: Option<DateTime<Utc>>,
    pub discovered_via: ProviderName,
    /// Canonical reachable endpoint URL(s) for this instance — e.g.
    /// `https://{slug}.mcpg.cloud/mcp` — recorded from the provisioner
    /// coords when the gateway reaches READY. Empty until then (and for
    /// self-host instances with no managed edge).
    #[serde(default)]
    pub addressable: Vec<String>,
    /// Instance size class (`s` | `m` | `l` | `xl`), set by the publish path;
    /// `s` for instances discovered outside it.
    #[serde(default = "default_instance_size")]
    pub size: String,
    /// Where this instance runs. Recorded from the provisioner's coordinates
    /// when a publish reaches READY; empty for self-host instances and for
    /// anything discovered outside the publish path. Advisory — the
    /// provisioner's placement record stays the authority for teardown.
    #[serde(default)]
    pub placement: InstancePlacement,
    pub created_at: DateTime<Utc>,
}

/// The cell an instance was scheduled onto.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstancePlacement {
    /// Opaque cell id from the provisioner registry. Empty when unplaced.
    #[serde(default)]
    pub cell_id: String,
    /// The cell's region (`us-east-1`). Empty when unplaced.
    #[serde(default)]
    pub region: String,
    /// Kubernetes namespace the instance occupies in that cell.
    #[serde(default)]
    pub namespace: String,
}

impl InstancePlacement {
    /// True once a publish has recorded where this instance landed.
    pub fn is_placed(&self) -> bool {
        !self.cell_id.is_empty()
    }
}

fn default_instance_size() -> String {
    "s".into()
}

/// Instance lifecycle state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstanceState {
    /// mTLS exchange in flight.
    Enrolling,
    /// Heartbeat within last 90s.
    Online,
    /// 90s..300s since last heartbeat.
    Stale,
    /// >300s since last heartbeat OR explicit deregister.
    Departed,
    /// Operator-initiated; refuses commands.
    Quarantined,
}

impl InstanceState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Enrolling => "enrolling",
            Self::Online => "online",
            Self::Stale => "stale",
            Self::Departed => "departed",
            Self::Quarantined => "quarantined",
        }
    }
}

/// Where this `Instance` was first observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderName {
    Static,
    Kube,
    SelfRegistration,
    DnsService,
}

impl ProviderName {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::Kube => "kube",
            Self::SelfRegistration => "self_registration",
            Self::DnsService => "dns_service",
        }
    }
}

/// Plugin set definition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginSet {
    pub id: uuid::Uuid,
    pub org_id: OrgId,
    pub workspace_id: WorkspaceId,
    pub name: String,
    pub entries: Vec<PluginEntry>,
    pub capability_grants: BTreeMap<String, Vec<String>>,
    pub content_hash: String,
    pub created_at: DateTime<Utc>,
}

/// One plugin within a `PluginSet`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginEntry {
    pub id: String,
    pub oci_ref: String,
    pub digest: String,
    pub enabled: bool,
    pub enforce: bool,
    pub config: serde_json::Value,
}

/// Authenticated user. Tier 1 = synced from federation IdP via
/// SCIM / OIDC userinfo; Tier 2 = synced from customer IdP via
/// SCIM; Tier 0 = OS user.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    /// Federation `sub` claim (or OS uid for Tier 0).
    pub federation_sub: Option<String>,
    pub email: String,
    pub name: Option<String>,
    pub created_at: DateTime<Utc>,
}
