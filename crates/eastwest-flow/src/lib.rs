//! EastWest canonical flow model.
//!
//! The shared, I/O-free vocabulary for network evidence: a normalized [`FlowEvent`] with
//! direction-independent conversation keys and explicitly-partial counts, and a time-bounded
//! [`WorkloadMap`] that turns an observed address into a workload — or says, honestly, that NAT
//! or a stale lease makes the answer ambiguous or unknown.
//!
//! ```
//! use eastwest_flow::{FlowEvent, Endpoint, Protocol, Counts};
//! use chrono::{TimeZone, Utc};
//!
//! let fwd = FlowEvent {
//!     id: "f1".into(), tenant_id: "alpha".into(),
//!     src: Endpoint::new("10.0.0.1", 5000), dst: Endpoint::new("10.0.0.2", 443),
//!     protocol: Protocol::Tcp, counts: Counts { bytes: Some(512), packets: Some(4) },
//!     start: Utc.with_ymd_and_hms(2026,1,1,0,0,0).unwrap(),
//!     end: Utc.with_ymd_and_hms(2026,1,1,0,0,1).unwrap(),
//!     sensor_id: "sensor-1".into(), raw_ref: None,
//! };
//! // the response direction groups to the same conversation
//! let rev = FlowEvent { src: fwd.dst.clone(), dst: fwd.src.clone(), ..fwd.clone() };
//! assert_eq!(fwd.conversation_key(), rev.conversation_key());
//! ```

pub mod flow;
pub mod mapping;

pub use flow::{Counts, Endpoint, FlowEvent, Protocol};
pub use mapping::{MapResult, WorkloadBinding, WorkloadMap};
