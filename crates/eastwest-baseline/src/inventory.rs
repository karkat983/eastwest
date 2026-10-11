//! Asset inventory: workload roles and known-vulnerable assets.
//!
//! Role-aware comparisons are the whole point of the baseline: "a web pod talking to a database
//! on 5432" is normal, "a web pod talking to another web pod's admin port" is not, even if the
//! specific peer was seen before. The inventory supplies the roles those comparisons need, plus
//! the set of assets a vulnerability scan has flagged, so contact with a known-vulnerable asset
//! can be surfaced as context.

use std::collections::{HashMap, HashSet};

/// A mapping of workloads to roles, and the set of vulnerable workloads, for one tenant.
#[derive(Default)]
pub struct AssetInventory {
    roles: HashMap<String, String>,
    vulnerable: HashSet<String>,
}

impl AssetInventory {
    /// An empty inventory.
    pub fn new() -> Self {
        AssetInventory::default()
    }

    /// Record a workload's role.
    pub fn set_role(&mut self, workload: impl Into<String>, role: impl Into<String>) {
        self.roles.insert(workload.into(), role.into());
    }

    /// Mark a workload as known-vulnerable.
    pub fn mark_vulnerable(&mut self, workload: impl Into<String>) {
        self.vulnerable.insert(workload.into());
    }

    /// The role of a workload, if known.
    pub fn role_of(&self, workload: &str) -> Option<&str> {
        self.roles.get(workload).map(String::as_str)
    }

    /// Whether a workload is known-vulnerable.
    pub fn is_vulnerable(&self, workload: &str) -> bool {
        self.vulnerable.contains(workload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_and_vulnerability_are_recorded() {
        let mut inv = AssetInventory::new();
        inv.set_role("web-1", "web");
        inv.mark_vulnerable("db-legacy");
        assert_eq!(inv.role_of("web-1"), Some("web"));
        assert_eq!(inv.role_of("unknown"), None);
        assert!(inv.is_vulnerable("db-legacy"));
        assert!(!inv.is_vulnerable("web-1"));
    }
}
