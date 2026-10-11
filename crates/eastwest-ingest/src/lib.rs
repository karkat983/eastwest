//! EastWest flow ingestion.
//!
//! Turns raw sensor lines into normalized, workload-resolved, windowed network evidence that
//! the platform can store and the graph can correlate.
//!
//! * [`parse`] — the MVP line format → [`FlowEvent`](eastwest_flow::FlowEvent)s, with bad lines
//!   returned as errors (never silently dropped) and unknown counts preserved as unknown;
//! * [`aggregate`] — resolve endpoints to workloads at flow time, then fold flows into
//!   [`FlowAggregate`]s over fixed time windows, tolerant of late and out-of-order input;
//! * [`event`] — map a flow into the platform's canonical observed event with provenance.
//!
//! ```
//! use eastwest_ingest::{parse_fixture, WindowAggregator};
//!
//! let line = "2026-01-01T00:00:00Z 2026-01-01T00:00:01Z 10.0.0.1 5000 10.0.0.2 443 tcp 512 4 sensor-1";
//! let parsed = parse_fixture("alpha", line);
//! assert_eq!(parsed.flows.len(), 1);
//!
//! let aggregates = WindowAggregator::new(60).aggregate(&parsed.flows);
//! assert_eq!(aggregates[0].bytes, 512);
//! ```

pub mod aggregate;
pub mod event;
pub mod parse;

pub use aggregate::{resolve_workloads, FlowAggregate, WindowAggregator};
pub use event::{flow_event, EVENT_TYPE, SOURCE_ENGINE};
pub use parse::{parse_fixture, parse_line, ParseError, ParsedFixture};
