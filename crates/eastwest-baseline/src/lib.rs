//! EastWest anomaly context.
//!
//! Detect *unusual* communication with simple, role-aware baselines — and present it as context
//! for an analyst or the correlator, never as a confirmed verdict.
//!
//! * [`inventory`] — workload roles and known-vulnerable assets, for role-aware comparison;
//! * [`baseline`] — summarise a 14-day reference period and assess a current window, flagging
//!   new peers, rare ports, unexpected role pairs, fan-out spikes and vulnerable-asset contact,
//!   each with an inspectable contribution and an explicit cold-start label;
//! * [`dedup`] — collapse repeat alerts on the same edge so a stable dependency is reported once.
//!
//! Every assessment is [`Verdict::ContextOnly`](baseline::Verdict): EastWest never turns an
//! anomaly into confirmed malicious activity on its own.
//!
//! ```
//! use eastwest_baseline::{Baseline, BaselineConfig, AssetInventory};
//! use eastwest_ingest::FlowAggregate;
//! use eastwest_flow::Protocol;
//! use chrono::{TimeZone, Utc};
//!
//! let hist: Vec<FlowAggregate> = (0..14).map(|d| FlowAggregate {
//!     tenant_id: "alpha".into(), src: "web-1".into(), dst: "db-1".into(), dst_port: 5432,
//!     protocol: Protocol::Tcp,
//!     window_start: Utc.timestamp_opt(1_767_225_600 + d*86_400, 0).unwrap(),
//!     window_end: Utc.timestamp_opt(1_767_225_600 + (d+1)*86_400, 0).unwrap(),
//!     flow_count: 1, bytes: 1, packets: 1, has_unknown_counts: false, flow_ids: vec![],
//! }).collect();
//!
//! let inv = AssetInventory::new();
//! let base = Baseline::build(&hist, &inv, BaselineConfig::default());
//! assert!(!base.is_cold_start());
//! ```

pub mod baseline;
pub mod dedup;
pub mod inventory;

pub use baseline::{AnomalyAssessment, AnomalyFeature, Baseline, BaselineConfig, Verdict};
pub use dedup::AlertDeduper;
pub use inventory::AssetInventory;
