//! Role-aware baselines and anomaly context.
//!
//! A [`Baseline`] summarises a reference period (14 days by default) of aggregated flows into a
//! few per-source facts: the peers a source talked to, the destination ports it used, the
//! role-pairs observed across the fleet, and its typical per-window fan-out. Assessing a current
//! window against that baseline yields [`AnomalyAssessment`]s whose **feature contributions are
//! inspectable** — each flagged feature says exactly why it fired.
//!
//! Two rules from the spec are load-bearing here:
//!
//! * an anomaly is **context, never a verdict** — an assessment carries `Verdict::ContextOnly`
//!   and never asserts malice;
//! * when history is too thin the baseline says so (`cold_start`), rather than treating
//!   everything new as anomalous.

use std::collections::{HashMap, HashSet};

use eastwest_ingest::FlowAggregate;

use crate::inventory::AssetInventory;

/// A feature that can contribute to an anomaly assessment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnomalyFeature {
    /// The source contacted a destination it never talked to in the reference period.
    NewPeer {
        /// The new peer.
        peer: String,
    },
    /// The destination port was not seen for this source in the reference period.
    RareDestinationPort {
        /// The port.
        port: u16,
    },
    /// The (source role, destination role) pair was never observed in the reference period.
    UnexpectedRolePair {
        /// Source role.
        src_role: String,
        /// Destination role.
        dst_role: String,
    },
    /// The source's fan-out in the current window rose well above its typical level.
    FanOutIncrease {
        /// Observed distinct peers this window.
        observed: usize,
        /// Typical (baseline) distinct peers.
        typical: usize,
    },
    /// The destination is a known-vulnerable asset.
    VulnerableAssetContact {
        /// The vulnerable asset.
        asset: String,
    },
}

impl AnomalyFeature {
    /// A weight expressing how much this feature contributes to the score, in `[0, 1]`.
    pub fn weight(&self) -> f64 {
        match self {
            AnomalyFeature::NewPeer { .. } => 0.3,
            AnomalyFeature::RareDestinationPort { .. } => 0.3,
            AnomalyFeature::UnexpectedRolePair { .. } => 0.5,
            AnomalyFeature::FanOutIncrease { .. } => 0.4,
            AnomalyFeature::VulnerableAssetContact { .. } => 0.6,
        }
    }

    /// A short, stable label for grouping/dedup.
    pub fn label(&self) -> &'static str {
        match self {
            AnomalyFeature::NewPeer { .. } => "new_peer",
            AnomalyFeature::RareDestinationPort { .. } => "rare_port",
            AnomalyFeature::UnexpectedRolePair { .. } => "unexpected_role_pair",
            AnomalyFeature::FanOutIncrease { .. } => "fan_out_increase",
            AnomalyFeature::VulnerableAssetContact { .. } => "vulnerable_asset_contact",
        }
    }
}

/// What an assessment means. EastWest provides context; it never confirms malice on its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Context for an analyst or the correlator — not a confirmed malicious event.
    ContextOnly,
}

/// An inspectable anomaly assessment for one edge in one window.
#[derive(Clone, Debug, PartialEq)]
pub struct AnomalyAssessment {
    /// The tenant.
    pub tenant_id: String,
    /// Source workload/address.
    pub src: String,
    /// Destination workload/address.
    pub dst: String,
    /// Destination port.
    pub dst_port: u16,
    /// The features that fired, each explaining itself.
    pub features: Vec<AnomalyFeature>,
    /// The aggregate score in `[0, 1]` (saturating sum of weights).
    pub score: f64,
    /// Whether the baseline had too little history to be confident.
    pub cold_start: bool,
    /// Supporting flow ids for provenance.
    pub evidence: Vec<String>,
    /// Always context-only.
    pub verdict: Verdict,
}

/// Tunables for baseline building and assessment.
#[derive(Clone, Copy, Debug)]
pub struct BaselineConfig {
    /// Minimum distinct windows of history before the baseline is considered warm.
    pub min_history_windows: usize,
    /// Fan-out is flagged when current distinct peers exceed `typical * multiplier` (and > 1).
    pub fan_out_multiplier: f64,
}

impl Default for BaselineConfig {
    fn default() -> Self {
        BaselineConfig {
            min_history_windows: 14,
            fan_out_multiplier: 2.0,
        }
    }
}

/// A summarised reference period.
pub struct Baseline {
    peers: HashMap<String, HashSet<String>>,
    ports: HashMap<String, HashSet<u16>>,
    role_pairs: HashSet<(String, String)>,
    typical_fan_out: HashMap<String, usize>,
    window_count: usize,
    config: BaselineConfig,
}

impl Baseline {
    /// Build a baseline from historical aggregates.
    pub fn build(history: &[FlowAggregate], inventory: &AssetInventory, config: BaselineConfig) -> Self {
        let mut peers: HashMap<String, HashSet<String>> = HashMap::new();
        let mut ports: HashMap<String, HashSet<u16>> = HashMap::new();
        let mut role_pairs: HashSet<(String, String)> = HashSet::new();
        let mut windows: HashSet<i64> = HashSet::new();
        // per (src, window) distinct peers, to find each src's typical max fan-out
        let mut fan: HashMap<(String, i64), HashSet<String>> = HashMap::new();

        for a in history {
            peers.entry(a.src.clone()).or_default().insert(a.dst.clone());
            ports.entry(a.src.clone()).or_default().insert(a.dst_port);
            if let (Some(sr), Some(dr)) = (inventory.role_of(&a.src), inventory.role_of(&a.dst)) {
                role_pairs.insert((sr.to_string(), dr.to_string()));
            }
            windows.insert(a.window_start.timestamp());
            fan.entry((a.src.clone(), a.window_start.timestamp()))
                .or_default()
                .insert(a.dst.clone());
        }

        let mut typical_fan_out: HashMap<String, usize> = HashMap::new();
        for ((src, _), peers_in_window) in fan {
            let n = peers_in_window.len();
            let e = typical_fan_out.entry(src).or_insert(0);
            if n > *e {
                *e = n;
            }
        }

        Baseline {
            peers,
            ports,
            role_pairs,
            typical_fan_out,
            window_count: windows.len(),
            config,
        }
    }

    /// Whether the baseline is in cold-start (too little history).
    pub fn is_cold_start(&self) -> bool {
        self.window_count < self.config.min_history_windows
    }

    /// Assess a current window of aggregates against the baseline, returning one assessment per
    /// edge that fired at least one feature.
    pub fn assess(&self, current: &[FlowAggregate], inventory: &AssetInventory) -> Vec<AnomalyAssessment> {
        // current fan-out per source
        let mut current_fan: HashMap<String, HashSet<String>> = HashMap::new();
        for a in current {
            current_fan.entry(a.src.clone()).or_default().insert(a.dst.clone());
        }

        let cold = self.is_cold_start();
        let mut out = Vec::new();

        for a in current {
            let mut features = Vec::new();

            let known_peers = self.peers.get(&a.src);
            if known_peers.map(|s| !s.contains(&a.dst)).unwrap_or(true) {
                features.push(AnomalyFeature::NewPeer { peer: a.dst.clone() });
            }
            let known_ports = self.ports.get(&a.src);
            if known_ports.map(|s| !s.contains(&a.dst_port)).unwrap_or(true) {
                features.push(AnomalyFeature::RareDestinationPort { port: a.dst_port });
            }
            if let (Some(sr), Some(dr)) = (inventory.role_of(&a.src), inventory.role_of(&a.dst)) {
                if !self.role_pairs.contains(&(sr.to_string(), dr.to_string())) {
                    features.push(AnomalyFeature::UnexpectedRolePair {
                        src_role: sr.to_string(),
                        dst_role: dr.to_string(),
                    });
                }
            }
            let observed = current_fan.get(&a.src).map(|s| s.len()).unwrap_or(0);
            let typical = *self.typical_fan_out.get(&a.src).unwrap_or(&0);
            if typical > 0
                && observed as f64 > (typical as f64 * self.config.fan_out_multiplier)
                && observed > typical
            {
                features.push(AnomalyFeature::FanOutIncrease { observed, typical });
            }
            if inventory.is_vulnerable(&a.dst) {
                features.push(AnomalyFeature::VulnerableAssetContact { asset: a.dst.clone() });
            }

            if features.is_empty() {
                continue;
            }
            let score = features.iter().map(|f| f.weight()).sum::<f64>().min(1.0);
            out.push(AnomalyAssessment {
                tenant_id: a.tenant_id.clone(),
                src: a.src.clone(),
                dst: a.dst.clone(),
                dst_port: a.dst_port,
                features,
                score,
                cold_start: cold,
                evidence: a.flow_ids.clone(),
                verdict: Verdict::ContextOnly,
            });
        }

        out.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.src.cmp(&b.src))
                .then_with(|| a.dst.cmp(&b.dst))
        });
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, TimeZone, Utc};
    use eastwest_flow::Protocol;

    fn win(day: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_767_225_600 + day * 86_400, 0).unwrap()
    }

    fn agg(src: &str, dst: &str, port: u16, day: i64) -> FlowAggregate {
        FlowAggregate {
            tenant_id: "alpha".into(),
            src: src.into(),
            dst: dst.into(),
            dst_port: port,
            protocol: Protocol::Tcp,
            window_start: win(day),
            window_end: win(day) + chrono::Duration::seconds(86_400),
            flow_count: 1,
            bytes: 100,
            packets: 1,
            has_unknown_counts: false,
            flow_ids: vec![format!("{src}-{dst}-{day}")],
        }
    }

    // 14 days of web-1 -> db-1:5432 so the baseline is warm.
    fn warm_history() -> Vec<FlowAggregate> {
        (0..14).map(|d| agg("web-1", "db-1", 5432, d)).collect()
    }

    fn inventory() -> AssetInventory {
        let mut inv = AssetInventory::new();
        inv.set_role("web-1", "web");
        inv.set_role("db-1", "db");
        inv.set_role("db-legacy", "db");
        inv.set_role("evil-1", "unknown");
        inv
    }

    #[test]
    fn baseline_normal_traffic_has_no_anomalies() {
        let b = Baseline::build(&warm_history(), &inventory(), BaselineConfig::default());
        assert!(!b.is_cold_start());
        let current = vec![agg("web-1", "db-1", 5432, 14)];
        assert!(b.assess(&current, &inventory()).is_empty());
    }

    #[test]
    fn new_peer_and_rare_port_are_flagged() {
        let b = Baseline::build(&warm_history(), &inventory(), BaselineConfig::default());
        let current = vec![agg("web-1", "evil-1", 4444, 14)];
        let out = b.assess(&current, &inventory());
        assert_eq!(out.len(), 1);
        let labels: Vec<_> = out[0].features.iter().map(|f| f.label()).collect();
        assert!(labels.contains(&"new_peer"));
        assert!(labels.contains(&"rare_port"));
        assert_eq!(out[0].verdict, Verdict::ContextOnly);
    }

    #[test]
    fn unexpected_role_pair_is_flagged() {
        // history only has web->db; a db->web connection is a new role pair
        let b = Baseline::build(&warm_history(), &inventory(), BaselineConfig::default());
        let mut inv = inventory();
        inv.set_role("web-2", "web");
        let current = vec![agg("db-1", "web-2", 8080, 14)];
        let out = b.assess(&current, &inv);
        assert!(out[0]
            .features
            .iter()
            .any(|f| matches!(f, AnomalyFeature::UnexpectedRolePair { .. })));
    }

    #[test]
    fn fan_out_increase_detects_autoscaling_spike() {
        // baseline: web-1 talks to exactly 1 peer per window
        let b = Baseline::build(&warm_history(), &inventory(), BaselineConfig::default());
        // current window: web-1 suddenly talks to 5 distinct peers
        let current: Vec<FlowAggregate> = (0..5)
            .map(|i| agg("web-1", &format!("peer-{i}"), 5432, 14))
            .collect();
        let out = b.assess(&current, &inventory());
        assert!(out
            .iter()
            .any(|a| a.features.iter().any(|f| matches!(f, AnomalyFeature::FanOutIncrease { .. }))));
    }

    #[test]
    fn vulnerable_asset_contact_is_flagged() {
        let b = Baseline::build(&warm_history(), &inventory(), BaselineConfig::default());
        let mut inv = inventory();
        inv.mark_vulnerable("db-legacy");
        // web-1 -> db-legacy on the normal db port: only the vulnerability feature should fire,
        // but db-legacy is a new peer too
        let current = vec![agg("web-1", "db-legacy", 5432, 14)];
        let out = b.assess(&current, &inv);
        assert!(out[0]
            .features
            .iter()
            .any(|f| matches!(f, AnomalyFeature::VulnerableAssetContact { .. })));
    }

    #[test]
    fn cold_start_is_labelled_not_suppressed() {
        // only 3 days of history -> cold start
        let history: Vec<FlowAggregate> = (0..3).map(|d| agg("web-1", "db-1", 5432, d)).collect();
        let b = Baseline::build(&history, &inventory(), BaselineConfig::default());
        assert!(b.is_cold_start());
        let current = vec![agg("web-1", "evil-1", 4444, 3)];
        let out = b.assess(&current, &inventory());
        // still assessed, but flagged cold-start so the uncertainty is explicit
        assert!(!out.is_empty());
        assert!(out[0].cold_start);
    }
}
