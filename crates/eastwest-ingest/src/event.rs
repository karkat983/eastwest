//! Mapping a flow into the platform's canonical event envelope.
//!
//! A network flow is an *observed* fact: a sensor saw these bytes move between these endpoints
//! in this interval. The event is marked observed and references the raw record for provenance,
//! so a flow "appears in the asset graph with traceable provenance and correct time windows"
//! exactly as the definition of done requires.

use lattivant_event::{ActorKind, Assertion, Event, EventError};

use eastwest_flow::FlowEvent;

/// The event type for a network flow.
pub const EVENT_TYPE: &str = "net.flow";

/// The source engine name.
pub const SOURCE_ENGINE: &str = "eastwest";

/// Build the canonical platform event for a flow.
pub fn flow_event(flow: &FlowEvent) -> Result<Event, EventError> {
    let mut builder = Event::builder(EVENT_TYPE, &flow.tenant_id)
        .source_engine(SOURCE_ENGINE)
        .actor(ActorKind::NetworkEndpoint, flow.src.label())
        .action("protocol", format!("{:?}", flow.protocol).to_lowercase())
        .action("src_port", flow.src.port.to_string())
        .action("dst_port", flow.dst.port.to_string())
        .action("sensor_id", flow.sensor_id.clone())
        .target("type", "workload")
        .target("id", flow.dst.label().to_string())
        .outcome("observed", None)
        .assertion(Assertion::Observed)
        .timestamp(flow.start)
        .observed_at(flow.end);

    if let Some(bytes) = flow.counts.bytes {
        builder = builder.action("bytes", bytes.to_string());
    }
    if let Some(packets) = flow.counts.packets {
        builder = builder.action("packets", packets.to_string());
    }
    if let Some(raw) = &flow.raw_ref {
        builder = builder.raw_ref(raw.clone());
    }

    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use eastwest_flow::{Counts, Endpoint, Protocol};

    fn flow() -> FlowEvent {
        FlowEvent {
            id: "f1".into(),
            tenant_id: "alpha".into(),
            src: Endpoint {
                address: "10.0.0.1".into(),
                port: 5000,
                workload: Some("web-1".into()),
            },
            dst: Endpoint {
                address: "10.0.0.2".into(),
                port: 443,
                workload: Some("api-1".into()),
            },
            protocol: Protocol::Tcp,
            counts: Counts { bytes: Some(512), packets: Some(4) },
            start: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            end: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 1).unwrap(),
            sensor_id: "sensor-1".into(),
            raw_ref: Some("flow-raw://abc".into()),
        }
    }

    #[test]
    fn maps_to_a_valid_observed_net_flow_event() {
        let e = flow_event(&flow()).unwrap();
        e.validate().unwrap();
        assert_eq!(e.event_type, EVENT_TYPE);
        assert_eq!(e.source_engine, SOURCE_ENGINE);
        assert_eq!(e.actor.kind, ActorKind::NetworkEndpoint);
        assert_eq!(e.actor.id, "web-1");
        assert!(e.is_observed());
        assert_eq!(e.action["dst_port"], "443");
        assert_eq!(e.action["bytes"], "512");
        assert_eq!(e.target["id"], "api-1");
        assert_eq!(e.provenance.raw_ref.as_deref(), Some("flow-raw://abc"));
    }

    #[test]
    fn unknown_bytes_are_omitted_from_the_event() {
        let mut f = flow();
        f.counts.bytes = None;
        let e = flow_event(&f).unwrap();
        assert!(!e.action.contains_key("bytes"));
    }
}
