# TUIC Outbound

TUIC v5 proxy over QUIC with 0-RTT handshake support and flexible UDP relay modes.

## Schema

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | — | Must be `"tuic"` |
| `tag` | string | — | Unique outbound identifier |
| `server` | string | — | Server hostname or IP address |
| `server_port` | integer | — | Server port |
| `uuid` | string | — | **Required.** Client UUID (RFC 4122 format) |
| `password` | string | — | **Required.** Authentication password |
| `congestion_control` | string | `"cubic"` | QUIC congestion control algorithm: `"cubic"`, `"new_reno"`, or `"bbr"` |
| `udp_relay_mode` | string | `"native"` | UDP relay mode: `"native"` (UDP-over-UDP) or `"quic"` (UDP-over-QUIC streams) |
| `zero_rtt_handshake` | bool | `false` | Enable 0-RTT QUIC handshake (reduces latency, minor replay risk) |
| `heartbeat` | duration | `"10s"` | Keep-alive heartbeat interval |
| `tls.enabled` | bool | — | **Required**, must be `true` |
| `tls.server_name` | string | — | SNI override |
| `tls.alpn` | string[] | `["h3"]` | ALPN list |
| `tls.insecure` | bool | `false` | Skip TLS certificate verification |

> Dial fields (`detour`, `bind_interface`, `connect_timeout`, `domain_strategy`, etc.) are supported — see the common dial documentation.

## Example

```json
{
  "type": "tuic",
  "tag": "tuic-out",
  "server": "example.com",
  "server_port": 443,
  "uuid": "c5d6e7f8-1234-5678-90ab-cdef01234567",
  "password": "s3cr3tP@ss",
  "congestion_control": "bbr",
  "udp_relay_mode": "quic",
  "tls": {
    "enabled": true,
    "server_name": "example.com",
    "alpn": ["h3"]
  }
}
```

## Notes

- `tls.enabled` must always be `true`; TUIC v5 is TLS-only.
- `udp_relay_mode: "quic"` encapsulates UDP inside QUIC streams, which is more reliable on lossy links but has higher overhead than `"native"`.
- `congestion_control: "bbr"` generally performs better on high-latency or high-bandwidth paths; `"cubic"` is the safe default.
- `zero_rtt_handshake` can reduce connection setup latency but may expose the client to replay attacks — do not enable on untrusted networks without additional mitigations.
- `uuid` must be a valid RFC 4122 UUID and must match the server configuration exactly.
