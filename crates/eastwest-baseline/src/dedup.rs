//! Alert deduplication.
//!
//! The same edge trips the same features window after window (a scheduled backup job, a new but
//! stable dependency). Without dedup an analyst drowns. The deduper collapses repeat assessments
//! of the same `(src, dst, port, feature-set)` to a single alert, while a *change* in the
//! feature set — a new kind of anomaly on the same edge — is treated as fresh.

use std::collections::HashSet;

use crate::baseline::AnomalyAssessment;

/// Collapses repeat assessments by their stable signature.
#[derive(Default)]
pub struct AlertDeduper {
    seen: HashSet<String>,
}

impl AlertDeduper {
    /// A new, empty deduper.
    pub fn new() -> Self {
        AlertDeduper::default()
    }

    /// The signature of an assessment: edge plus the sorted set of feature labels.
    pub fn signature(a: &AnomalyAssessment) -> String {
        let mut labels: Vec<&str> = a.features.iter().map(|f| f.label()).collect();
        labels.sort_unstable();
        labels.dedup();
        format!("{}|{}|{}|{}", a.tenant_id, a.src, a.dst, a.dst_port) + "|" + &labels.join(",")
    }

    /// Filter assessments, keeping only ones not seen before. Updates internal state.
    pub fn dedup(&mut self, assessments: Vec<AnomalyAssessment>) -> Vec<AnomalyAssessment> {
        assessments
            .into_iter()
            .filter(|a| self.seen.insert(Self::signature(a)))
            .collect()
    }

    /// Number of distinct signatures seen.
    pub fn seen_count(&self) -> usize {
        self.seen.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::baseline::{AnomalyFeature, Verdict};

    fn assessment(dst: &str, features: Vec<AnomalyFeature>) -> AnomalyAssessment {
        AnomalyAssessment {
            tenant_id: "alpha".into(),
            src: "web-1".into(),
            dst: dst.into(),
            dst_port: 443,
            features,
            score: 0.3,
            cold_start: false,
            evidence: vec![],
            verdict: Verdict::ContextOnly,
        }
    }

    #[test]
    fn repeat_identical_alerts_are_collapsed() {
        let mut d = AlertDeduper::new();
        let a1 = assessment("b", vec![AnomalyFeature::NewPeer { peer: "b".into() }]);
        let a2 = a1.clone();
        let first = d.dedup(vec![a1]);
        let second = d.dedup(vec![a2]);
        assert_eq!(first.len(), 1);
        assert!(second.is_empty());
        assert_eq!(d.seen_count(), 1);
    }

    #[test]
    fn a_new_feature_on_the_same_edge_is_fresh() {
        let mut d = AlertDeduper::new();
        d.dedup(vec![assessment("b", vec![AnomalyFeature::NewPeer { peer: "b".into() }])]);
        let changed = assessment(
            "b",
            vec![
                AnomalyFeature::NewPeer { peer: "b".into() },
                AnomalyFeature::RareDestinationPort { port: 443 },
            ],
        );
        assert_eq!(d.dedup(vec![changed]).len(), 1);
    }
}
