//! The serving-limit exchange between the control plane and the billing
//! federation.
//!
//! The control plane reports each org's billable calls in the current period;
//! the federation answers with how far the org may be served in it: the
//! included allowance, the prepaid pack credits still live, and the
//! pay-as-you-go headroom the owner's spend cap buys. One definition for both
//! sides, for the reason [`crate::usage_report`] gives.

use chrono::{DateTime, Datelike, Months, NaiveDate, TimeZone, Utc};
use serde::{Deserialize, Serialize};

/// The federation route the control plane posts [`ServingRequest`] to.
pub const SERVING_PATH: &str = "/v1/billing/serving";

/// The federation route an owner's spend cap is read from and written to.
pub const SPEND_CAP_PATH: &str = "/v1/billing/spend-cap";

/// The billing period `at` falls in: the calendar month in UTC, as
/// `(YYYY-MM, start, end)` with `end` exclusive.
///
/// Allowance, serving and rating all count calls over this one window.
pub fn calendar_period(at: DateTime<Utc>) -> (String, DateTime<Utc>, DateTime<Utc>) {
    let first = NaiveDate::from_ymd_opt(at.year(), at.month(), 1)
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .expect("the first of a month at midnight exists");
    let start = Utc.from_utc_datetime(&first);
    let end = start + Months::new(1);
    (format!("{:04}-{:02}", at.year(), at.month()), start, end)
}

/// Every org's calls in the current period, as one control plane counts them.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ServingRequest {
    /// `YYYY-MM` (UTC).
    pub period: String,
    pub orgs: Vec<OrgPeriodUsage>,
}

/// One org's billable calls, tunnel bytes and MCP Events deliveries since the
/// period started.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct OrgPeriodUsage {
    /// The join key between the two services.
    pub slug: String,
    pub used: u64,
    /// Tunnel bytes relayed in the period; their overage draws on the same
    /// spend cap as the calls.
    #[serde(default)]
    pub tunnel_bytes: u64,
    /// Of `tunnel_bytes`, those a paid plan the control plane relayed them on
    /// includes (see [`crate::usage_report::OrgUsage::held_plan_tunnel_bytes`]):
    /// no overage and no draw on the cap.
    #[serde(default)]
    pub held_plan_tunnel_bytes: u64,
    /// Billable MCP Events deliveries in the period; their overage draws on
    /// the same spend cap. Defaulted, so a control plane that does not send
    /// it reads as none.
    #[serde(default)]
    pub events_delivered: u64,
    /// Of `events_delivered`, those a paid plan the control plane delivered
    /// them on includes (see
    /// [`crate::usage_report::OrgUsage::held_plan_events_delivered`]).
    #[serde(default)]
    pub held_plan_events_delivered: u64,
}

/// The federation's answer: one entry per org it bills. An org it does not
/// know is absent, and the control plane serves it on its licence alone.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ServingResponse {
    pub period: String,
    #[serde(default)]
    pub orgs: Vec<OrgServingLimits>,
}

/// How far one org may be served in a period, and what it is made of.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OrgServingLimits {
    pub slug: String,
    pub period: String,
    pub plan: String,
    /// Billable calls the org may be served in the period, counted from the
    /// period start. `None` is no ceiling.
    pub ceiling: Option<u64>,
    /// The included allowance the period is rated against. `0` is unlimited,
    /// as everywhere in the licence vocabulary.
    pub included: u64,
    /// Prepaid pack credits still live and unspent.
    pub pack_credits: u64,
    /// Calls billed pay-as-you-go in the period so far.
    pub payg_used: u64,
    /// Calls the spend cap allows pay-as-you-go in the period, after the
    /// tunnel-byte overage it already pays for. `None` is no cap; `Some(0)` is
    /// no pay-as-you-go at all.
    pub payg_limit: Option<u64>,
    /// Tunnel bytes the org may relay in the period before its tunnels stop:
    /// the included bytes plus the overage the spend cap leaves after the
    /// calls it pays for. `None`: the cap sets no stop — no cap, an unlimited
    /// allowance, tunnel bytes not billed, or the free plan, which is
    /// throttled past its licence allowance instead.
    #[serde(default)]
    pub tunnel_bytes_ceiling: Option<u64>,
    /// Where the org's MCP Events deliveries hold in the period. Absent: the
    /// federation does not rate deliveries, so the control plane holds them
    /// at the licence allowance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_deliveries: Option<EventDeliveryLimit>,
    pub spend_cap: SpendCap,
    /// Usage notices already sent for the period.
    #[serde(default)]
    pub notices: Vec<UsageNotice>,
    pub computed_at: DateTime<Utc>,
}

/// The delivery hold the federation rates for an org's period.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventDeliveryLimit {
    /// Deliveries counted from the period start at which the org's
    /// deliveries hold: the included deliveries plus what the spend cap
    /// still buys. `None`: no hold (no cap).
    pub ceiling: Option<u64>,
}

/// Where an org's spend cap comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpendCapKind {
    /// The plan's default: one month of its list price.
    Default,
    /// An amount the owner set.
    Custom,
    /// The owner opted out of a cap.
    Uncapped,
    /// The plan has no pay-as-you-go: a free plan, or a subscription that
    /// carries no overage price.
    NotOffered,
}

/// The monthly pay-as-you-go spend cap as the owner sees it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SpendCap {
    pub kind: SpendCapKind,
    /// The cap in minor units of `currency`. Absent when uncapped, not
    /// offered, or when no price is known yet.
    pub amount_minor: Option<i64>,
    /// ISO currency code of the subscription's prices, lower case as Stripe
    /// states it.
    pub currency: Option<String>,
    /// Price of one pay-as-you-go call in minor units, as a decimal string.
    pub unit_price_minor: Option<String>,
    /// The cap the plan applies when the owner sets none.
    pub default_amount_minor: Option<i64>,
}

/// A usage notice sent to the org's owners.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageNotice {
    /// One of [`notice_kind`].
    pub kind: String,
    pub sent_at: DateTime<Utc>,
}

/// The notices an org receives, each at most once per period.
pub mod notice_kind {
    pub const ALLOWANCE_80: &str = "allowance_80";
    pub const ALLOWANCE_100: &str = "allowance_100";
    pub const SPEND_CAP_80: &str = "spend_cap_80";
    pub const SPEND_CAP_100: &str = "spend_cap_100";
}

/// A spend cap the owner may choose.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SpendCapSetting {
    /// Follow the plan's default.
    Default,
    /// A fixed amount in minor units. `0` stops at the allowance and packs.
    Amount { amount_minor: i64 },
    /// No cap. Only ever set by an explicit choice.
    Uncapped,
}

/// `PUT` body of [`SPEND_CAP_PATH`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendCapChange {
    /// Required on the service-token path; a tenant token names its own org.
    #[serde(default)]
    pub org_slug: Option<String>,
    pub cap: SpendCapSetting,
    /// Who asked, for the billing audit trail.
    #[serde(default)]
    pub actor: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_period_is_the_calendar_month_in_utc() {
        let at = DateTime::parse_from_rfc3339("2026-09-30T23:59:59Z")
            .unwrap()
            .with_timezone(&Utc);
        let (label, start, end) = calendar_period(at);
        assert_eq!(label, "2026-09");
        assert_eq!(start.to_rfc3339(), "2026-09-01T00:00:00+00:00");
        assert_eq!(end.to_rfc3339(), "2026-10-01T00:00:00+00:00");

        let (label, _, end) = calendar_period(end);
        assert_eq!(label, "2026-10");
        assert_eq!(end.to_rfc3339(), "2026-11-01T00:00:00+00:00");
    }

    #[test]
    fn a_spend_cap_setting_is_tagged_by_kind() {
        let set: SpendCapSetting =
            serde_json::from_str(r#"{"kind":"amount","amount_minor":0}"#).unwrap();
        assert_eq!(set, SpendCapSetting::Amount { amount_minor: 0 });
        let set: SpendCapSetting = serde_json::from_str(r#"{"kind":"uncapped"}"#).unwrap();
        assert_eq!(set, SpendCapSetting::Uncapped);
        assert!(serde_json::from_str::<SpendCapSetting>(r#"{"kind":"unlimited"}"#).is_err());
    }

    /// The delivery fields are additive both ways: an answer or a request
    /// from a side that does not know them still parses, and their names
    /// are the contract.
    #[test]
    fn an_answer_without_event_deliveries_is_not_rated() {
        let answer = serde_json::json!({
            "slug": "acme", "period": "2026-09", "plan": "team",
            "ceiling": null, "included": 0, "pack_credits": 0, "payg_used": 0,
            "payg_limit": null,
            "spend_cap": {"kind": "uncapped", "amount_minor": null, "currency": null,
                          "unit_price_minor": null, "default_amount_minor": null},
            "computed_at": "2026-09-20T00:00:00Z"
        });
        let l: OrgServingLimits = serde_json::from_value(answer.clone()).unwrap();
        assert_eq!(l.event_deliveries, None, "absent: not rated");
        let v = serde_json::to_value(&l).unwrap();
        assert!(v.get("event_deliveries").is_none(), "{v}");

        let mut uncapped = answer.clone();
        uncapped["event_deliveries"] = serde_json::json!({"ceiling": null});
        let l: OrgServingLimits = serde_json::from_value(uncapped).unwrap();
        assert_eq!(
            l.event_deliveries,
            Some(EventDeliveryLimit { ceiling: None })
        );

        let mut held = answer;
        held["event_deliveries"] = serde_json::json!({"ceiling": 7});
        let l: OrgServingLimits = serde_json::from_value(held).unwrap();
        assert_eq!(
            l.event_deliveries,
            Some(EventDeliveryLimit { ceiling: Some(7) })
        );
        let v = serde_json::to_value(&l).unwrap();
        assert_eq!(v["event_deliveries"]["ceiling"], 7);

        let old: OrgPeriodUsage =
            serde_json::from_value(serde_json::json!({"slug": "acme", "used": 3})).unwrap();
        assert_eq!(old.events_delivered, 0);
        assert_eq!(old.held_plan_events_delivered, 0);
        let v = serde_json::to_value(OrgPeriodUsage {
            slug: "acme".into(),
            used: 1,
            tunnel_bytes: 2,
            held_plan_tunnel_bytes: 3,
            events_delivered: 4,
            held_plan_events_delivered: 5,
        })
        .unwrap();
        assert_eq!(v["events_delivered"], 4);
        assert_eq!(v["held_plan_events_delivered"], 5);
    }
}
