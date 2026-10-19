# eastwest

EastWest is the network-context engine of [Lattivant](https://github.com/karkat983), an
evidence-first security platform. It adds network evidence — who talked to whom, when, over what
— **without pretending to be a full NDR**, and surfaces unusual communication as *context* for an
analyst or the correlator, never as a standalone verdict.

Two honesty rules run through it:

- **Addresses are not identities.** An IP is NAT'd and reused, so every address→workload mapping
  is time-bounded, and a lookup that can't be made uniquely says *ambiguous* or *unknown* rather
  than guessing.
- **An anomaly is context, not a conviction.** Every assessment carries inspectable feature
  contributions and a `ContextOnly` verdict, and when history is too thin it is labelled
  *cold-start* instead of calling everything new "malicious".

Flows map into the platform's canonical event envelope from
[`lattivant-platform`](https://github.com/karkat983/lattivant-platform), so network evidence sits
in the same graph as AuthZ findings and agent activity.

## Crates

| Crate | What it provides |
|-------|------------------|
| [`eastwest-flow`](crates/eastwest-flow) | The canonical [`FlowEvent`]: normalized endpoints, protocol, partial-aware counts, interval and sensor, with direction-independent conversation keys (so a flow and its reverse group together) and a time-bounded [`WorkloadMap`] that resolves addresses to workloads or reports NAT ambiguity. |
| [`eastwest-ingest`](crates/eastwest-ingest) | The MVP line parser (Zeek/Hubble/VPC-shaped), with bad lines returned as errors not dropped; workload resolution at flow time; window aggregation tolerant of late and out-of-order input; and the mapping of a flow to an observed platform event with provenance. |
| [`eastwest-baseline`](crates/eastwest-baseline) | Role-aware baselines over a 14-day reference period, flagging new peers, rare ports, unexpected role pairs, fan-out spikes and vulnerable-asset contact — each an inspectable contribution — with explicit cold-start labelling and alert deduplication. |
| [`eastwest-sample`](crates/eastwest-sample) | A worked scenario: normal web→db traffic, then a new connection to a vulnerable external peer, surfaced with its feature contributions. |

## Anomaly features

| Feature | Meaning |
|---------|---------|
| `new_peer` | A destination the source never contacted in the reference period. |
| `rare_port` | A destination port not seen for this source before. |
| `unexpected_role_pair` | A (source role → destination role) never observed across the fleet. |
| `fan_out_increase` | The source's distinct peers this window rose well above its typical level. |
| `vulnerable_asset_contact` | The destination is a known-vulnerable asset. |

## Try it

```sh
cargo run -p eastwest-sample
```

The scenario builds a baseline from fourteen days of `web-1 → db-1:5432`, then ingests a current
window where `web-1` also opens a connection to a new, vulnerable external peer on port 4444. The
normal database traffic is not flagged; the new edge is surfaced as context with all four
contributing features, scored and marked `ContextOnly`.

```sh
cargo test              # all crates
cargo clippy --all-targets
```

Requires a recent stable Rust toolchain (edition 2021, rustc ≥ 1.80).

## License

MIT. See [LICENSE](LICENSE).

## Authorized testing only

All tenants, identities, resources and events in this repository are synthetic. Use these tools
only against systems you own or are explicitly authorized to test.
