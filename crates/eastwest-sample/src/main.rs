//! Sample: ingest network flows and surface anomaly context.
//!
//! Running this binary plays the built-in scenario — fourteen days of normal web→db traffic,
//! then a current window with a new connection to a vulnerable external peer — and prints the
//! anomaly assessment with its inspectable feature contributions.

mod scenario;

use serde_json::json;

fn main() {
    let out = scenario::run();

    let anomalies: Vec<_> = out
        .anomalies
        .iter()
        .map(|a| {
            json!({
                "src": a.src,
                "dst": a.dst,
                "dst_port": a.dst_port,
                "score": a.score,
                "cold_start": a.cold_start,
                "verdict": format!("{:?}", a.verdict),
                "features": a.features.iter().map(|f| json!({
                    "feature": f.label(),
                    "weight": f.weight(),
                    "detail": format!("{f:?}"),
                })).collect::<Vec<_>>(),
                "evidence": a.evidence,
            })
        })
        .collect();

    let summary = json!({
        "warm_baseline": out.warm_baseline,
        "current_window_edges": out.current_aggregates.len(),
        "anomalies": anomalies,
    });

    println!("{}", serde_json::to_string_pretty(&summary).expect("summary serializes"));
}
