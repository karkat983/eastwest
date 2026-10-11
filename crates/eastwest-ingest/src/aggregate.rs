//! Workload resolution and window aggregation.
//!
//! Raw flows are noisy and address-keyed; baselines and the graph want workload-keyed edges
//! over time windows. This module (1) resolves each flow's endpoints to workloads at the flow's
//! own start time — so a reused IP is attributed to whoever held it then — and (2) folds flows
//! into [`FlowAggregate`]s bucketed by `(src, dst, dst_port, protocol, window)`.
//!
//! Late and out-of-order flows are fine: a flow is placed in the window its start falls in,
//! regardless of arrival order. Unknown byte/packet counts are tracked (`has_unknown_counts`)
//! instead of being summed as zero, so an aggregate never reports a confident total it doesn't
//! have.

use chrono::{DateTime, TimeZone, Utc};

use eastwest_flow::{FlowEvent, Protocol, WorkloadMap};

/// Resolve a flow's endpoints to workloads using the map, at the flow's start time. Returns a
/// new flow with `workload` filled where a unique mapping existed.
pub fn resolve_workloads(mut flow: FlowEvent, map: &WorkloadMap) -> FlowEvent {
    if flow.src.workload.is_none() {
        if let Some(w) = map.resolve(&flow.tenant_id, &flow.src.address, flow.start).workload() {
            flow.src.workload = Some(w.to_string());
        }
    }
    if flow.dst.workload.is_none() {
        if let Some(w) = map.resolve(&flow.tenant_id, &flow.dst.address, flow.start).workload() {
            flow.dst.workload = Some(w.to_string());
        }
    }
    flow
}

/// An aggregated edge over a time window.
#[derive(Clone, Debug, PartialEq)]
pub struct FlowAggregate {
    /// The tenant.
    pub tenant_id: String,
    /// Source workload or address.
    pub src: String,
    /// Destination workload or address.
    pub dst: String,
    /// Destination (service) port.
    pub dst_port: u16,
    /// Protocol.
    pub protocol: Protocol,
    /// Window start (aligned).
    pub window_start: DateTime<Utc>,
    /// Window end (start + window).
    pub window_end: DateTime<Utc>,
    /// Number of flows folded in.
    pub flow_count: u64,
    /// Total bytes over flows that reported them.
    pub bytes: u64,
    /// Total packets over flows that reported them.
    pub packets: u64,
    /// Whether any folded flow had unknown counts (so totals are a lower bound).
    pub has_unknown_counts: bool,
    /// Supporting flow ids, for provenance.
    pub flow_ids: Vec<String>,
}

/// Aggregates flows into fixed-width time windows.
pub struct WindowAggregator {
    window_secs: i64,
}

impl WindowAggregator {
    /// A new aggregator with the given window width in seconds (minimum 1).
    pub fn new(window_secs: i64) -> Self {
        WindowAggregator {
            window_secs: window_secs.max(1),
        }
    }

    fn bucket_start(&self, t: DateTime<Utc>) -> DateTime<Utc> {
        let secs = t.timestamp();
        let aligned = secs - secs.rem_euclid(self.window_secs);
        Utc.timestamp_opt(aligned, 0).single().unwrap_or(t)
    }

    /// Aggregate flows (already workload-resolved) into windowed edges, ordered deterministically.
    pub fn aggregate(&self, flows: &[FlowEvent]) -> Vec<FlowAggregate> {
        use std::collections::HashMap;
        let mut map: HashMap<(String, String, String, u16, String, i64), FlowAggregate> =
            HashMap::new();

        for flow in flows {
            let window_start = self.bucket_start(flow.start);
            let key = (
                flow.tenant_id.clone(),
                flow.src.label().to_string(),
                flow.dst.label().to_string(),
                flow.dst.port,
                format!("{:?}", flow.protocol),
                window_start.timestamp(),
            );
            let entry = map.entry(key).or_insert_with(|| FlowAggregate {
                tenant_id: flow.tenant_id.clone(),
                src: flow.src.label().to_string(),
                dst: flow.dst.label().to_string(),
                dst_port: flow.dst.port,
                protocol: flow.protocol,
                window_start,
                window_end: window_start + chrono::Duration::seconds(self.window_secs),
                flow_count: 0,
                bytes: 0,
                packets: 0,
                has_unknown_counts: false,
                flow_ids: Vec::new(),
            });
            entry.flow_count += 1;
            entry.flow_ids.push(flow.id.clone());
            match flow.counts.bytes {
                Some(b) => entry.bytes += b,
                None => entry.has_unknown_counts = true,
            }
            match flow.counts.packets {
                Some(p) => entry.packets += p,
                None => entry.has_unknown_counts = true,
            }
        }

        let mut out: Vec<FlowAggregate> = map.into_values().collect();
        out.sort_by(|a, b| {
            a.window_start
                .cmp(&b.window_start)
                .then_with(|| a.src.cmp(&b.src))
                .then_with(|| a.dst.cmp(&b.dst))
                .then_with(|| a.dst_port.cmp(&b.dst_port))
        });
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eastwest_flow::{Counts, Endpoint, WorkloadBinding};

    fn t(s: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_767_225_600 + s, 0).unwrap() // 2026-01-01T00:00:00Z + s
    }

    fn flow(id: &str, src: &str, dst: &str, dp: u16, bytes: Option<u64>, start: i64) -> FlowEvent {
        FlowEvent {
            id: id.into(),
            tenant_id: "alpha".into(),
            src: Endpoint::new(src, 5000),
            dst: Endpoint::new(dst, dp),
            protocol: Protocol::Tcp,
            counts: Counts { bytes, packets: Some(1) },
            start: t(start),
            end: t(start + 1),
            sensor_id: "s".into(),
            raw_ref: None,
        }
    }

    #[test]
    fn resolve_fills_workloads_at_flow_time() {
        let mut map = WorkloadMap::new();
        map.bind(WorkloadBinding {
            address: "10.0.0.1".into(),
            workload: "web-1".into(),
            tenant_id: "alpha".into(),
            valid_from: t(0),
            valid_to: None,
        });
        let resolved = resolve_workloads(flow("f1", "10.0.0.1", "10.0.0.2", 443, Some(10), 5), &map);
        assert_eq!(resolved.src.workload.as_deref(), Some("web-1"));
        assert!(resolved.dst.workload.is_none());
    }

    #[test]
    fn flows_in_same_window_and_edge_are_summed() {
        let agg = WindowAggregator::new(60);
        let flows = vec![
            flow("f1", "a", "b", 443, Some(100), 5),
            flow("f2", "a", "b", 443, Some(50), 30), // same 60s window
        ];
        let out = agg.aggregate(&flows);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].flow_count, 2);
        assert_eq!(out[0].bytes, 150);
        assert_eq!(out[0].flow_ids, vec!["f1", "f2"]);
    }

    #[test]
    fn different_windows_are_separate_even_if_late() {
        let agg = WindowAggregator::new(60);
        // out-of-order: the later window arrives first
        let flows = vec![
            flow("f2", "a", "b", 443, Some(50), 70),
            flow("f1", "a", "b", 443, Some(100), 5),
        ];
        let out = agg.aggregate(&flows);
        assert_eq!(out.len(), 2);
        // sorted by window start: the 0-60 window first
        assert!(out[0].window_start < out[1].window_start);
    }

    #[test]
    fn unknown_counts_flag_the_aggregate() {
        let agg = WindowAggregator::new(60);
        let out = agg.aggregate(&[flow("f1", "a", "b", 443, None, 5)]);
        assert!(out[0].has_unknown_counts);
        assert_eq!(out[0].bytes, 0); // lower bound, flagged
    }
}
