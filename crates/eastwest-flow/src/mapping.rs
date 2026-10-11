//! Time-bounded IP-to-workload mapping.
//!
//! Addresses are not identities: NAT hides many workloads behind one address, and an IP is
//! leased to different workloads over time. So a mapping is valid only over an interval, and a
//! lookup must name the instant the flow was observed. When several workloads claim one address
//! at the same instant (NAT), the lookup is *ambiguous* and the resolver says so rather than
//! picking one — the flow keeps its raw address and is marked unresolved.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A time-bounded claim that an address belonged to a workload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadBinding {
    /// The address.
    pub address: String,
    /// The workload id.
    pub workload: String,
    /// The owning tenant.
    pub tenant_id: String,
    /// When the binding became valid.
    pub valid_from: DateTime<Utc>,
    /// When it stopped (`None` = still valid).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_to: Option<DateTime<Utc>>,
}

impl WorkloadBinding {
    /// Whether valid at `at` (`[valid_from, valid_to)`).
    pub fn is_valid_at(&self, at: DateTime<Utc>) -> bool {
        at >= self.valid_from && self.valid_to.map(|end| at < end).unwrap_or(true)
    }
}

/// The result of resolving an address at a time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MapResult {
    /// Exactly one workload.
    Resolved(String),
    /// Several workloads claim the address at that instant (NAT / shared host).
    Ambiguous(Vec<String>),
    /// No valid binding.
    Unknown,
}

impl MapResult {
    /// The workload if unambiguous.
    pub fn workload(&self) -> Option<&str> {
        match self {
            MapResult::Resolved(w) => Some(w),
            _ => None,
        }
    }
}

/// A set of time-bounded workload bindings.
#[derive(Default)]
pub struct WorkloadMap {
    bindings: Vec<WorkloadBinding>,
}

impl WorkloadMap {
    /// An empty map.
    pub fn new() -> Self {
        WorkloadMap::default()
    }

    /// Add a binding.
    pub fn bind(&mut self, binding: WorkloadBinding) {
        self.bindings.push(binding);
    }

    /// Resolve an address within a tenant at an instant.
    pub fn resolve(&self, tenant: &str, address: &str, at: DateTime<Utc>) -> MapResult {
        let mut hits: Vec<String> = self
            .bindings
            .iter()
            .filter(|b| b.tenant_id == tenant && b.address == address && b.is_valid_at(at))
            .map(|b| b.workload.clone())
            .collect();
        hits.sort();
        hits.dedup();
        match hits.len() {
            0 => MapResult::Unknown,
            1 => MapResult::Resolved(hits.into_iter().next().unwrap()),
            _ => MapResult::Ambiguous(hits),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn t(day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, day, 0, 0, 0).unwrap()
    }

    fn binding(addr: &str, wl: &str, from: u32, to: Option<u32>) -> WorkloadBinding {
        WorkloadBinding {
            address: addr.into(),
            workload: wl.into(),
            tenant_id: "alpha".into(),
            valid_from: t(from),
            valid_to: to.map(t),
        }
    }

    #[test]
    fn reused_ip_resolves_by_time() {
        let mut m = WorkloadMap::new();
        m.bind(binding("10.0.0.5", "web-1", 1, Some(5)));
        m.bind(binding("10.0.0.5", "web-2", 5, None));
        assert_eq!(m.resolve("alpha", "10.0.0.5", t(3)).workload(), Some("web-1"));
        assert_eq!(m.resolve("alpha", "10.0.0.5", t(6)).workload(), Some("web-2"));
    }

    #[test]
    fn nat_shared_address_is_ambiguous() {
        let mut m = WorkloadMap::new();
        m.bind(binding("1.2.3.4", "pod-a", 1, None));
        m.bind(binding("1.2.3.4", "pod-b", 1, None));
        assert!(matches!(m.resolve("alpha", "1.2.3.4", t(2)), MapResult::Ambiguous(_)));
    }

    #[test]
    fn unknown_address_is_unknown() {
        let m = WorkloadMap::new();
        assert_eq!(m.resolve("alpha", "9.9.9.9", t(1)), MapResult::Unknown);
    }

    #[test]
    fn mapping_is_tenant_scoped() {
        let mut m = WorkloadMap::new();
        m.bind(binding("10.0.0.5", "web-1", 1, None));
        assert_eq!(m.resolve("bravo", "10.0.0.5", t(2)), MapResult::Unknown);
    }
}
