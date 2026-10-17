//! Self-serve changes to an org's paid subscription, between the control
//! plane and the billing federation.
//!
//! An owner moves the org to another plan or billing interval, ends the
//! subscription when its paid period ends, or takes a pending cancel back. A
//! move to a higher plan, or to the same plan billed yearly, is an upgrade.
//! It applies at once, and the prorated difference goes on the next invoice,
//! or is invoiced at once on a change of interval. One between yearly plans
//! is invoiced at once and applies only once that invoice is paid, so a
//! declined card never costs the year already paid for; until then it awaits
//! payment. Any other move takes effect when the paid period ends and is
//! pending until then. The latest request replaces whatever is pending,
//! except an upgrade that awaits payment. One definition for both sides, for
//! the reason [`crate::usage_report`] gives.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The federation route an org's subscription is read from (`GET`) and
/// changed through (`POST`).
pub const SUBSCRIPTION_PATH: &str = "/v1/billing/subscription";

/// How often a plan price recurs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BillingInterval {
    Month,
    Year,
}

impl BillingInterval {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Month => "month",
            Self::Year => "year",
        }
    }
}

/// What an owner asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionAction {
    /// Move to `plan` at `interval`.
    ChangePlan,
    /// End the subscription when its paid period ends.
    Cancel,
    /// Take back a pending cancel.
    Resume,
}

/// `POST` body of [`SUBSCRIPTION_PATH`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionChange {
    /// Required on the service-token path; a tenant token names its own org.
    #[serde(default)]
    pub org_slug: Option<String>,
    pub action: SubscriptionAction,
    /// The plan to move to (`change_plan` only).
    #[serde(default)]
    pub plan: Option<String>,
    /// The interval to bill it at; the current one when absent
    /// (`change_plan` only).
    #[serde(default)]
    pub interval: Option<BillingInterval>,
    /// Who asked, for the billing audit trail (service-token path only; an
    /// owner's id_token names its owner).
    #[serde(default)]
    pub actor: Option<String>,
}

/// Who changes the org's plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionSource {
    /// No live paid subscription: a plan is bought through checkout.
    None,
    /// A live Stripe subscription the owner changes here.
    SelfServe,
    /// A plan sales manages; only sales changes it.
    Sales,
    /// Billing is held after a lost payment dispute; support lifts it.
    OnHold,
}

/// A plan the org can move to, at an interval it has a price for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanOffer {
    pub plan: String,
    pub interval: BillingInterval,
}

/// A move that takes effect when the paid period ends.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingChange {
    pub plan: String,
    pub interval: Option<BillingInterval>,
    pub effective_at: DateTime<Utc>,
}

/// An upgrade that awaits payment of the invoice it raised. It applies once
/// that invoice is paid and lapses at `expires_at`; until then the plan
/// billed now continues.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingPayment {
    pub plan: String,
    pub interval: Option<BillingInterval>,
    pub expires_at: Option<DateTime<Utc>>,
    /// Where the owner pays the invoice, card authentication included.
    pub payment_url: Option<String>,
}

/// The org's subscription as the owner sees it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionView {
    pub source: SubscriptionSource,
    /// The plan billed now.
    pub plan: String,
    #[serde(default)]
    pub interval: Option<BillingInterval>,
    /// Stripe's status of a self-serve subscription (`active`, `past_due`,
    /// `unpaid`, ...); an annual plan's usage subscription owing a payment
    /// shows as its plan's.
    #[serde(default)]
    pub status: Option<String>,
    /// End of the plan's paid period.
    #[serde(default)]
    pub current_period_end: Option<DateTime<Utc>>,
    /// When a pending cancel ends the subscription.
    #[serde(default)]
    pub cancel_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub pending_change: Option<PendingChange>,
    #[serde(default)]
    pub pending_payment: Option<PendingPayment>,
    /// Every plan and interval this deployment sells.
    #[serde(default)]
    pub offers: Vec<PlanOffer>,
}

/// What a change did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeOutcome {
    /// The new plan applies now; the prorated difference goes on the next
    /// invoice, or is invoiced at once (a change of interval, or between
    /// yearly plans, paid).
    Upgraded,
    /// The upgrade waits for its invoice to be paid (`pending_payment`); the
    /// plan billed now continues.
    AwaitingPayment,
    /// The new plan starts when the paid period ends.
    DowngradeScheduled,
    /// The request matched the plan billed now, and a pending change or
    /// cancel was dropped.
    PendingChangeDropped,
    /// The request matched the plan billed now and nothing was pending.
    Unchanged,
    /// The subscription ends when its paid period ends.
    CancelScheduled,
    /// A pending cancel was taken back.
    CancelUndone,
}

/// Answer to a `POST` of [`SUBSCRIPTION_PATH`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionChangeResponse {
    pub outcome: ChangeOutcome,
    pub subscription: SubscriptionView,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_change_request_reads_as_the_console_sends_it() {
        let req: SubscriptionChange = serde_json::from_value(serde_json::json!({
            "action": "change_plan", "plan": "team", "interval": "year"
        }))
        .unwrap();
        assert_eq!(req.action, SubscriptionAction::ChangePlan);
        assert_eq!(req.plan.as_deref(), Some("team"));
        assert_eq!(req.interval, Some(BillingInterval::Year));
        assert_eq!(req.org_slug, None);

        let req: SubscriptionChange =
            serde_json::from_value(serde_json::json!({ "action": "cancel" })).unwrap();
        assert_eq!(req.action, SubscriptionAction::Cancel);
        assert!(
            serde_json::from_value::<SubscriptionChange>(serde_json::json!({ "action": "delete" }))
                .is_err()
        );
    }

    #[test]
    fn outcomes_and_sources_are_snake_case_on_the_wire() {
        assert_eq!(
            serde_json::to_value(ChangeOutcome::DowngradeScheduled).unwrap(),
            "downgrade_scheduled"
        );
        assert_eq!(
            serde_json::to_value(ChangeOutcome::AwaitingPayment).unwrap(),
            "awaiting_payment"
        );
        assert_eq!(
            serde_json::to_value(SubscriptionSource::SelfServe).unwrap(),
            "self_serve"
        );
    }

    #[test]
    fn a_view_without_a_pending_payment_reads() {
        let view: SubscriptionView = serde_json::from_value(serde_json::json!({
            "source": "self_serve", "plan": "pro", "offers": []
        }))
        .unwrap();
        assert_eq!(view.pending_payment, None);
    }
}
