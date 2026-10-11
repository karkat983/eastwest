//! The canonical network flow event.
//!
//! EastWest adds *network evidence*, not a full NDR, so the model is deliberately small: two
//! observed endpoints, a protocol, byte/packet counts, a time interval, and the sensor that
//! saw it, plus a reference to the raw record. Two subtleties the spec calls out are handled
//! here:
//!
//! * **reversed flows** — a sensor may report the response direction; a
//!   [`FlowEvent::conversation_key`] is direction-independent so both halves of a conversation
//!   group together while the observed direction is preserved;
//! * **missing counts** — a flow with no byte count is valid but explicitly marked
//!   [`Counts::is_complete`] false, so downstream never treats "unknown" as "zero".

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A transport protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// ICMP.
    Icmp,
    /// Anything else, by IANA protocol number.
    Other(u8),
}

impl Protocol {
    /// Parse from a lowercase name or numeric string.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "tcp" | "6" => Some(Protocol::Tcp),
            "udp" | "17" => Some(Protocol::Udp),
            "icmp" | "1" => Some(Protocol::Icmp),
            other => other.parse::<u8>().ok().map(Protocol::Other),
        }
    }
}

/// One end of a flow: an address, a port, and (once resolved) a workload.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Endpoint {
    /// The observed address (post-NAT as the sensor saw it).
    pub address: String,
    /// The port.
    pub port: u16,
    /// The resolved workload, if a mapping was found.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload: Option<String>,
}

impl Endpoint {
    /// An endpoint with no resolved workload.
    pub fn new(address: impl Into<String>, port: u16) -> Self {
        Endpoint {
            address: address.into(),
            port,
            workload: None,
        }
    }

    /// The workload if resolved, else the raw address — a stable label for grouping.
    pub fn label(&self) -> &str {
        self.workload.as_deref().unwrap_or(&self.address)
    }
}

/// Byte and packet counts, which may be partially unknown.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counts {
    /// Bytes, if the sensor reported them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    /// Packets, if the sensor reported them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packets: Option<u64>,
}

impl Counts {
    /// Both counts known.
    pub fn is_complete(&self) -> bool {
        self.bytes.is_some() && self.packets.is_some()
    }
}

/// A normalized network flow observed by a sensor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowEvent {
    /// A stable id for the flow record.
    pub id: String,
    /// The owning tenant.
    pub tenant_id: String,
    /// The source endpoint (initiator, as observed).
    pub src: Endpoint,
    /// The destination endpoint.
    pub dst: Endpoint,
    /// The protocol.
    pub protocol: Protocol,
    /// Byte/packet counts.
    pub counts: Counts,
    /// Start of the observed interval.
    pub start: DateTime<Utc>,
    /// End of the observed interval.
    pub end: DateTime<Utc>,
    /// The sensor that reported it.
    pub sensor_id: String,
    /// A reference to the raw record for provenance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_ref: Option<String>,
}

impl FlowEvent {
    /// The flow duration in milliseconds (never negative).
    pub fn duration_ms(&self) -> i64 {
        (self.end - self.start).num_milliseconds().max(0)
    }

    /// A direction-independent key identifying the conversation, so a flow and its reverse map
    /// together. Endpoints are ordered by (label, port) and the destination port is kept for
    /// grouping by service.
    pub fn conversation_key(&self) -> String {
        let a = format!("{}:{}", self.src.label(), self.src.port);
        let b = format!("{}:{}", self.dst.label(), self.dst.port);
        let (lo, hi) = if a <= b { (&a, &b) } else { (&b, &a) };
        format!("{lo}|{hi}|{:?}", self.protocol)
    }

    /// A directed key: source workload/label → destination workload/label on the service port.
    pub fn directed_key(&self) -> String {
        format!(
            "{}->{}:{}|{:?}",
            self.src.label(),
            self.dst.label(),
            self.dst.port,
            self.protocol
        )
    }

    /// Whether either endpoint is still unresolved to a workload.
    pub fn has_unknown_workload(&self) -> bool {
        self.src.workload.is_none() || self.dst.workload.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn t(s: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, s).unwrap()
    }

    fn flow(src: &str, sp: u16, dst: &str, dp: u16) -> FlowEvent {
        FlowEvent {
            id: "f1".into(),
            tenant_id: "alpha".into(),
            src: Endpoint::new(src, sp),
            dst: Endpoint::new(dst, dp),
            protocol: Protocol::Tcp,
            counts: Counts {
                bytes: Some(100),
                packets: Some(2),
            },
            start: t(0),
            end: t(1),
            sensor_id: "sensor-1".into(),
            raw_ref: None,
        }
    }

    #[test]
    fn protocol_parses_names_and_numbers() {
        assert_eq!(Protocol::parse("TCP"), Some(Protocol::Tcp));
        assert_eq!(Protocol::parse("17"), Some(Protocol::Udp));
        assert_eq!(Protocol::parse("89"), Some(Protocol::Other(89)));
        assert_eq!(Protocol::parse("nonsense"), None);
    }

    #[test]
    fn reversed_flow_shares_conversation_key() {
        let fwd = flow("10.0.0.1", 5000, "10.0.0.2", 443);
        let rev = flow("10.0.0.2", 443, "10.0.0.1", 5000);
        assert_eq!(fwd.conversation_key(), rev.conversation_key());
        // but the directed keys differ
        assert_ne!(fwd.directed_key(), rev.directed_key());
    }

    #[test]
    fn missing_bytes_are_incomplete_not_zero() {
        let mut f = flow("a", 1, "b", 2);
        f.counts.bytes = None;
        assert!(!f.counts.is_complete());
        assert_eq!(f.counts.bytes, None);
    }

    #[test]
    fn label_prefers_workload_then_address() {
        let mut f = flow("10.0.0.1", 1, "10.0.0.2", 2);
        assert_eq!(f.src.label(), "10.0.0.1");
        f.src.workload = Some("web-1".into());
        assert_eq!(f.src.label(), "web-1");
        assert!(f.has_unknown_workload()); // dst still unknown
    }

    #[test]
    fn duration_is_never_negative() {
        let mut f = flow("a", 1, "b", 2);
        f.end = t(0);
        f.start = t(5);
        assert_eq!(f.duration_ms(), 0);
    }
}
