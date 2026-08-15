//! The usage-report wire contract between the control plane and the billing
//! federation.
//!
//! The control plane serves this from `GET /v1/admin/usage`; the federation's
//! export loop consumes it and turns each figure into a meter event. It lived
//! as two hand-written structs, one per crate, with nothing tying them
//! together — and the consumer side defaults the fields it cannot find. A
//! rename on the producer side therefore did not fail: it deserialized to
//! zero, and the tenant was billed nothing for real consumption.
//!
//! One definition, used by both, so that cannot happen.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// One org's billable quantities for a period.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct OrgUsage {
    pub org_id: String,
    /// The join key between the two services. They share the SLUG, not the id.
    pub slug: String,
    pub plan_tier: String,
    /// Billable tool calls in the period (excludes idempotent replays).
    pub tool_calls: i64,
    /// Billable instance-hours per size class (`s`|`m`|`l`|`xl` → hours, with
    /// replicas multiplied and the result floored to two decimals). Sizes with
    /// no usage are absent.
    ///
    /// Defaulted so a report from a control plane predating instance metering
    /// still parses. That tolerance is why this type is shared: with two
    /// definitions, the default silently absorbed a field rename as well.
    #[serde(default)]
    pub instance_hours: BTreeMap<String, f64>,
    /// Reverse-tunnel bytes relayed in the period. Defaulted for the same
    /// reason as [`Self::instance_hours`].
    #[serde(default)]
    pub tunnel_bytes: i64,
}

/// The full report for one billing period.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct UsageReport {
    pub period: String,
    pub period_start: chrono::DateTime<chrono::Utc>,
    pub period_end: chrono::DateTime<chrono::Utc>,
    pub orgs: Vec<OrgUsage>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The field names ARE the contract — the consumer defaults two of them,
    /// so a rename would bill zero rather than fail. Spelling them out here
    /// means a rename has to come past this test.
    #[test]
    fn the_wire_names_are_pinned() {
        let report = UsageReport {
            period: "2026-06".into(),
            period_start: chrono::DateTime::from_timestamp(0, 0).unwrap(),
            period_end: chrono::DateTime::from_timestamp(0, 0).unwrap(),
            orgs: vec![OrgUsage {
                org_id: "org-1".into(),
                slug: "acme".into(),
                plan_tier: "team".into(),
                tool_calls: 1_234,
                instance_hours: BTreeMap::from([("m".to_owned(), 1.5)]),
                tunnel_bytes: 4_096,
            }],
        };
        let v: serde_json::Value = serde_json::to_value(&report).unwrap();
        assert_eq!(v["period"], "2026-06");
        let org = &v["orgs"][0];
        for name in ["org_id", "slug", "plan_tier", "tool_calls"] {
            assert!(!org[name].is_null(), "`{name}` is part of the contract");
        }
        assert_eq!(org["tool_calls"], 1_234);
        assert_eq!(org["instance_hours"]["m"], 1.5);
        assert_eq!(org["tunnel_bytes"], 4_096);

        // And it round-trips, so producer and consumer cannot disagree.
        assert_eq!(serde_json::from_value::<UsageReport>(v).unwrap(), report);
    }

    /// A control plane that predates instance and tunnel metering emits
    /// neither field; that must parse rather than fail the whole export.
    #[test]
    fn an_older_report_still_parses() {
        let json = serde_json::json!({
            "period": "2026-06",
            "period_start": "2026-06-01T00:00:00Z",
            "period_end": "2026-07-01T00:00:00Z",
            "orgs": [{
                "org_id": "org-1", "slug": "acme",
                "plan_tier": "community", "tool_calls": 7
            }]
        });
        let report: UsageReport = serde_json::from_value(json).unwrap();
        assert_eq!(report.orgs[0].tool_calls, 7);
        assert!(report.orgs[0].instance_hours.is_empty());
        assert_eq!(report.orgs[0].tunnel_bytes, 0);
    }
}
