//! The MVP flow parser.
//!
//! One flow source for the MVP: a simple whitespace-separated line format that a Zeek, Hubble
//! or VPC-flow adapter can be made to emit. Each line is:
//!
//! ```text
//! <start_rfc3339> <end_rfc3339> <src_ip> <src_port> <dst_ip> <dst_port> <proto> <bytes> <packets> <sensor_id>
//! ```
//!
//! `bytes` and `packets` may be `-` when the sensor did not report them (kept as *unknown*,
//! never coerced to zero). Parsing validates the time interval and the fields; a bad line is
//! returned as a [`ParseError`] with its line number so a replay never silently drops input.

use chrono::{DateTime, Utc};

use eastwest_flow::{Counts, Endpoint, FlowEvent, Protocol};

/// Why a line failed to parse.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ParseError {
    /// Wrong number of fields.
    #[error("line {line}: expected 10 fields, got {got}")]
    FieldCount {
        /// 1-based line number.
        line: usize,
        /// Fields seen.
        got: usize,
    },
    /// A field could not be parsed.
    #[error("line {line}: bad {field}: {value:?}")]
    BadField {
        /// 1-based line number.
        line: usize,
        /// The field name.
        field: &'static str,
        /// The offending value.
        value: String,
    },
    /// The interval ended before it started.
    #[error("line {line}: end {end} precedes start {start}")]
    BadInterval {
        /// 1-based line number.
        line: usize,
        /// Start timestamp.
        start: String,
        /// End timestamp.
        end: String,
    },
}

fn parse_count(s: &str) -> Option<Option<u64>> {
    if s == "-" {
        Some(None) // explicitly unknown
    } else {
        s.parse::<u64>().ok().map(Some)
    }
}

fn parse_time(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s).ok().map(|t| t.with_timezone(&Utc))
}

/// Parse one line into a flow, given its tenant, 1-based line number, and a stable id.
pub fn parse_line(tenant: &str, line_no: usize, id: &str, line: &str) -> Result<FlowEvent, ParseError> {
    let f: Vec<&str> = line.split_whitespace().collect();
    if f.len() != 10 {
        return Err(ParseError::FieldCount {
            line: line_no,
            got: f.len(),
        });
    }
    let bad = |field: &'static str, value: &str| ParseError::BadField {
        line: line_no,
        field,
        value: value.to_string(),
    };

    let start = parse_time(f[0]).ok_or_else(|| bad("start", f[0]))?;
    let end = parse_time(f[1]).ok_or_else(|| bad("end", f[1]))?;
    if end < start {
        return Err(ParseError::BadInterval {
            line: line_no,
            start: f[0].to_string(),
            end: f[1].to_string(),
        });
    }
    let src_port: u16 = f[3].parse().map_err(|_| bad("src_port", f[3]))?;
    let dst_port: u16 = f[5].parse().map_err(|_| bad("dst_port", f[5]))?;
    let protocol = Protocol::parse(f[6]).ok_or_else(|| bad("protocol", f[6]))?;
    let bytes = parse_count(f[7]).ok_or_else(|| bad("bytes", f[7]))?;
    let packets = parse_count(f[8]).ok_or_else(|| bad("packets", f[8]))?;

    Ok(FlowEvent {
        id: id.to_string(),
        tenant_id: tenant.to_string(),
        src: Endpoint::new(f[2], src_port),
        dst: Endpoint::new(f[4], dst_port),
        protocol,
        counts: Counts { bytes, packets },
        start,
        end,
        sensor_id: f[9].to_string(),
        raw_ref: None,
    })
}

/// The result of parsing a fixture: the flows that parsed, and the errors for lines that did
/// not. Blank lines and `#` comments are skipped.
#[derive(Debug, Default)]
pub struct ParsedFixture {
    /// Successfully parsed flows.
    pub flows: Vec<FlowEvent>,
    /// Errors, by line.
    pub errors: Vec<ParseError>,
}

/// Parse a whole fixture (many lines) for a tenant. Ids are `<tenant>-flow-<n>`.
pub fn parse_fixture(tenant: &str, text: &str) -> ParsedFixture {
    let mut out = ParsedFixture::default();
    let mut n = 0usize;
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        n += 1;
        let id = format!("{tenant}-flow-{n}");
        match parse_line(tenant, i + 1, &id, line) {
            Ok(flow) => out.flows.push(flow),
            Err(e) => out.errors.push(e),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINE: &str =
        "2026-01-01T00:00:00Z 2026-01-01T00:00:01Z 10.0.0.1 5000 10.0.0.2 443 tcp 512 4 sensor-1";

    #[test]
    fn parses_a_well_formed_line() {
        let f = parse_line("alpha", 1, "f1", LINE).unwrap();
        assert_eq!(f.src.port, 5000);
        assert_eq!(f.dst.port, 443);
        assert_eq!(f.protocol, Protocol::Tcp);
        assert_eq!(f.counts.bytes, Some(512));
    }

    #[test]
    fn missing_counts_are_unknown_not_zero() {
        let line =
            "2026-01-01T00:00:00Z 2026-01-01T00:00:01Z 10.0.0.1 5000 10.0.0.2 443 tcp - - sensor-1";
        let f = parse_line("alpha", 1, "f1", line).unwrap();
        assert_eq!(f.counts.bytes, None);
        assert!(!f.counts.is_complete());
    }

    #[test]
    fn reversed_interval_is_rejected() {
        let line =
            "2026-01-01T00:00:05Z 2026-01-01T00:00:01Z 10.0.0.1 5000 10.0.0.2 443 tcp 1 1 s";
        assert!(matches!(parse_line("alpha", 3, "f1", line), Err(ParseError::BadInterval { line: 3, .. })));
    }

    #[test]
    fn bad_port_is_reported_with_line() {
        let line =
            "2026-01-01T00:00:00Z 2026-01-01T00:00:01Z 10.0.0.1 99999 10.0.0.2 443 tcp 1 1 s";
        assert!(matches!(
            parse_line("alpha", 2, "f1", line),
            Err(ParseError::BadField { field: "src_port", line: 2, .. })
        ));
    }

    #[test]
    fn fixture_skips_comments_and_collects_errors() {
        let text = "# header\n\n{good}\n{bad}\n"
            .replace("{good}", LINE)
            .replace("{bad}", "garbage line here");
        let parsed = parse_fixture("alpha", &text);
        assert_eq!(parsed.flows.len(), 1);
        assert_eq!(parsed.errors.len(), 1);
        assert_eq!(parsed.flows[0].id, "alpha-flow-1");
    }
}
