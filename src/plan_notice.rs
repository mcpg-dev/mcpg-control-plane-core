//! Plan-loss notices, between the control plane and the billing federation.
//!
//! The control plane decides when an org loses a paid plan and what it keeps
//! running through the grace; the federation holds the org's owners and the
//! mail relay. The control plane asks the federation to tell the owners, and
//! the federation writes the message itself from these fields, so nothing a
//! caller sends becomes mail markup. One definition for both sides, for the
//! reason [`crate::usage_report`] gives.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The federation route a notice is sent through (`POST`, billing or admin
/// token).
pub const PLAN_NOTICE_PATH: &str = "/v1/billing/plan-notice";

/// Why an org lost its plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanLossReason {
    /// Moved to a lower paid plan.
    Downgraded,
    /// The paid plan ended: cancelled, or held on the free plan.
    PlanEnded,
    /// A renewal went unpaid past its grace.
    Unpaid,
    /// The licence issuer no longer licenses the org.
    Revoked,
    /// An operator suspended the org.
    Suspended,
}

impl PlanLossReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Downgraded => "downgraded",
            Self::PlanEnded => "plan_ended",
            Self::Unpaid => "unpaid",
            Self::Revoked => "revoked",
            Self::Suspended => "suspended",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "downgraded" => Self::Downgraded,
            "plan_ended" => Self::PlanEnded,
            "unpaid" => Self::Unpaid,
            "revoked" => Self::Revoked,
            "suspended" => Self::Suspended,
            _ => return None,
        })
    }
}

/// Which notice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanNoticeKind {
    /// The grace began: what runs keeps running until `grace_until`.
    GraceStarted,
    /// The grace ended and the org was brought down to its plan.
    Enforced,
    /// A revoked org's paid retention windows end at `grace_until`, when the
    /// free plan's apply and older records are deleted.
    RetentionEnding,
}

impl PlanNoticeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GraceStarted => "plan_loss.grace_started",
            Self::Enforced => "plan_loss.enforced",
            Self::RetentionEnding => "plan_loss.retention_ending",
        }
    }
}

/// `POST` body of [`PLAN_NOTICE_PATH`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanNotice {
    pub org_slug: String,
    pub kind: PlanNoticeKind,
    pub reason: PlanLossReason,
    /// The plan lost.
    pub from_plan: String,
    /// The plan what runs is brought down to when the grace ends, unless
    /// `unpaid_renewal_plan` is paid first.
    pub to_plan: String,
    /// The plan of a renewal still unpaid, issued through the grace: paying
    /// it before `grace_until` brings the org to this plan instead of
    /// `to_plan`, and new work is judged by it meanwhile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unpaid_renewal_plan: Option<String>,
    /// When the loss happened; with `kind` it names the notice, so a retry
    /// is sent once.
    pub lost_at: DateTime<Utc>,
    /// When what runs is brought down to `to_plan`.
    pub grace_until: DateTime<Utc>,
    /// An operator's suspension with no grace: what runs is brought down at
    /// once, and `grace_until` is when.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub immediate: bool,
    /// The gateways stopped ([`PlanNoticeKind::Enforced`] only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stopped_gateways: Vec<String>,
    /// The gateways resized in place to the plan's compute type and replicas
    /// ([`PlanNoticeKind::Enforced`] only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resized_gateways: Vec<String>,
    /// How many tunnels were closed ([`PlanNoticeKind::Enforced`] only).
    #[serde(default)]
    pub closed_tunnels: u64,
}

/// The federation's answer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanNoticeResponse {
    /// `sent`, `already_sent`, `no_recipients` or `no_org`.
    pub outcome: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The names are the contract between two services; a rename must come
    /// past this test.
    #[test]
    fn the_wire_names_are_pinned() {
        let notice = PlanNotice {
            org_slug: "acme".into(),
            kind: PlanNoticeKind::GraceStarted,
            reason: PlanLossReason::PlanEnded,
            from_plan: "team".into(),
            to_plan: "community".into(),
            unpaid_renewal_plan: None,
            lost_at: DateTime::from_timestamp(1_000, 0).unwrap(),
            grace_until: DateTime::from_timestamp(2_000, 0).unwrap(),
            immediate: false,
            stopped_gateways: vec![],
            resized_gateways: vec![],
            closed_tunnels: 0,
        };
        let v = serde_json::to_value(&notice).unwrap();
        assert_eq!(v["kind"], "grace_started");
        assert_eq!(v["reason"], "plan_ended");
        assert_eq!(v["from_plan"], "team");
        assert!(v.get("stopped_gateways").is_none());
        assert!(v.get("unpaid_renewal_plan").is_none());
        assert!(
            v.get("immediate").is_none(),
            "a graced notice reads as before"
        );
        assert_eq!(serde_json::from_value::<PlanNotice>(v).unwrap(), notice);

        let unpaid = PlanNotice {
            reason: PlanLossReason::Downgraded,
            unpaid_renewal_plan: Some("pro".into()),
            ..notice.clone()
        };
        let v = serde_json::to_value(&unpaid).unwrap();
        assert_eq!(v["unpaid_renewal_plan"], "pro");
        assert_eq!(serde_json::from_value::<PlanNotice>(v).unwrap(), unpaid);

        let immediate = PlanNotice {
            reason: PlanLossReason::Suspended,
            immediate: true,
            ..notice
        };
        let v = serde_json::to_value(&immediate).unwrap();
        assert_eq!(v["immediate"], true);
        assert_eq!(serde_json::from_value::<PlanNotice>(v).unwrap(), immediate);
        for r in [
            PlanLossReason::Downgraded,
            PlanLossReason::PlanEnded,
            PlanLossReason::Unpaid,
            PlanLossReason::Revoked,
            PlanLossReason::Suspended,
        ] {
            assert_eq!(PlanLossReason::parse(r.as_str()), Some(r));
        }
    }
}
