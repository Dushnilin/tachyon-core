# Local patch to quinn-proto 0.11.18

Source: crates.io quinn-proto 0.11.18 (Quinn project, MIT OR Apache-2.0).
Original license files retained. This crate is pinned through Cargo's patch table.

Changes are limited to congestion.rs, connection/mod.rs and connection/pacing.rs:

- Optional Controller::pacing_rate_bytes hook, in bytes/second, distinct from qlog metrics.
- Optional per-packet loss callback, excluding ACK-only and MTU-probe packets and paths under validation.
- The connection passes the explicit rate to its actual token-bucket pacer. Controllers returning None preserve the original cwnd/RTT path unchanged.
- Explicit-rate pacing uses a bounded burst and overflow-safe elapsed-time accounting.

Keep this patch synchronized if Quinn is upgraded. No crypto backend is changed.
