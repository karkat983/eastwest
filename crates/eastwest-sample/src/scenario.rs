//! A controlled, deterministic EastWest scenario.
//!
//! A web workload (`web-1`) normally talks only to a database (`db-1`) on 5432. For fourteen
//! days that is all the baseline sees. Then, in the current window, `web-1` opens a connection
//! to a brand-new peer (`exfil-1`) on an unusual port — and that peer happens to be flagged
//! vulnerable. The scenario builds the baseline from history, ingests the current window from a
//! raw sensor fixture, and surfaces the anomaly with its feature contributions — as context,
//! never a verdict.

use chrono::{DateTime, TimeZone, Utc};

use eastwest_baseline::{AnomalyAssessment, Baseline, BaselineConfig, AssetInventory};
use eastwest_ingest::{parse_fixture, resolve_workloads, FlowAggregate, WindowAggregator};
use eastwest_flow::{Protocol, WorkloadBinding, WorkloadMap};

/// The raw current-window fixture, in the MVP line format. `web-1` (10.0.0.10) makes its usual
/// db call and one connection to a new external peer on 4444.
const CURRENT_FIXTURE: &str = "\
# current window sensor export
2026-01-15T00:00:00Z 2026-01-15T00:00:02Z 10.0.0.10 5000 10.0.0.20 5432 tcp 2048 12 sensor-1
2026-01-15T00:00:05Z 2026-01-15T00:00:06Z 10.0.0.10 5100 10.0.0.66 4444 tcp 900000 40 sensor-1
";

fn win(day: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(1_767_225_600 + day * 86_400, 0).unwrap()
}

/// Fourteen daily windows of web-1 -> db-1:5432, the normal baseline.
fn history() -> Vec<FlowAggregate> {
    (0..14)
        .map(|d| FlowAggregate {
            tenant_id: "alpha".into(),
            src: "web-1".into(),
            dst: "db-1".into(),
            dst_port: 5432,
            protocol: Protocol::Tcp,
            window_start: win(d),
            window_end: win(d) + chrono::Duration::seconds(86_400),
            flow_count: 20,
            bytes: 40_000,
            packets: 240,
            has_unknown_counts: false,
            flow_ids: vec![format!("hist-{d}")],
        })
        .collect()
}

/// Addresses → workloads for the current window.
fn workload_map() -> WorkloadMap {
    let mut m = WorkloadMap::new();
    for (addr, wl) in [("10.0.0.10", "web-1"), ("10.0.0.20", "db-1"), ("10.0.0.66", "exfil-1")] {
        m.bind(WorkloadBinding {
            address: addr.into(),
            workload: wl.into(),
            tenant_id: "alpha".into(),
            valid_from: win(0),
            valid_to: None,
        });
    }
    m
}

fn inventory() -> AssetInventory {
    let mut inv = AssetInventory::new();
    inv.set_role("web-1", "web");
    inv.set_role("db-1", "db");
    inv.set_role("exfil-1", "unknown");
    inv.mark_vulnerable("exfil-1");
    inv
}

/// The scenario output.
pub struct ScenarioOutput {
    /// Whether the baseline had enough history (not cold start).
    pub warm_baseline: bool,
    /// The current window's aggregates (resolved to workloads).
    pub current_aggregates: Vec<FlowAggregate>,
    /// The anomaly assessments.
    pub anomalies: Vec<AnomalyAssessment>,
}

/// Run the scenario deterministically.
pub fn run() -> ScenarioOutput {
    let inv = inventory();
    let baseline = Baseline::build(&history(), &inv, BaselineConfig::default());

    // ingest the current window: parse -> resolve workloads -> aggregate
    let map = workload_map();
    let parsed = parse_fixture("alpha", CURRENT_FIXTURE);
    let resolved: Vec<_> = parsed
        .flows
        .into_iter()
        .map(|f| resolve_workloads(f, &map))
        .collect();
    let current = WindowAggregator::new(86_400).aggregate(&resolved);

    let anomalies = baseline.assess(&current, &inv);

    ScenarioOutput {
        warm_baseline: !baseline.is_cold_start(),
        current_aggregates: current,
        anomalies,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eastwest_baseline::AnomalyFeature;

    #[test]
    fn normal_db_traffic_is_not_flagged_but_the_exfil_edge_is() {
        let out = run();
        assert!(out.warm_baseline);
        // exactly one anomalous edge: web-1 -> exfil-1
        assert_eq!(out.anomalies.len(), 1);
        let a = &out.anomalies[0];
        assert_eq!(a.src, "web-1");
        assert_eq!(a.dst, "exfil-1");
        let labels: Vec<_> = a.features.iter().map(|f| f.label()).collect();
        assert!(labels.contains(&"new_peer"));
        assert!(labels.contains(&"rare_port"));
        assert!(labels.contains(&"vulnerable_asset_contact"));
    }

    #[test]
    fn the_exfil_assessment_is_context_only_with_evidence() {
        let out = run();
        let a = &out.anomalies[0];
        assert!(matches!(a.verdict, eastwest_baseline::Verdict::ContextOnly));
        assert!(!a.evidence.is_empty());
        // a vulnerable-asset contact contributes weight, so the score is non-trivial
        assert!(a.score >= 0.6);
    }

    #[test]
    fn current_window_aggregates_both_conversations() {
        let out = run();
        assert_eq!(out.current_aggregates.len(), 2);
        assert!(out.current_aggregates.iter().any(|a| a.dst == "db-1"));
    }

    #[test]
    fn feature_contributions_are_present_and_match() {
        let out = run();
        // the vulnerable-asset feature names exfil-1 specifically
        assert!(out.anomalies[0]
            .features
            .iter()
            .any(|f| matches!(f, AnomalyFeature::VulnerableAssetContact { asset } if asset == "exfil-1")));
    }
}
