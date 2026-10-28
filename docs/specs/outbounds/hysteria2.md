# Hysteria2 Outbound

Fast UDP-based proxy protocol built on QUIC with BRUTAL congestion control and optional obfuscation.

## Schema

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | — | Must be `"hysteria2"` |
| `tag` | string | — | Unique outbound identifier |
| `server` | string | — | Server hostname or IP address |
| `server_port` | integer | — | Server port (mutually exclusive with `server_ports`) |
| `server_ports` | string | — | Port hopping range, e.g. `"10000:20000"` |
| `hop_interval` | duration | `"30s"` | How often to hop ports (port hopping mode only) |
| `obfs.type` | string | — | Obfuscation type; only `"salamander"` is supported |
| `obfs.password` | string | — | Obfuscation password |
| `password` | string | — | **Required.** Hysteria2 authentication password |
| `up_mbps` | integer | `0` | Upload bandwidth limit in Mbit/s; `0` = unlimited |
| `down_mbps` | integer | `0` | Download bandwidth limit in Mbit/s; `0` = unlimited |
| `brutal_debug` | bool | `false` | Enable BRUTAL CC debug logging |
| `tls.enabled` | bool | — | **Required**, must be `true` |
| `tls.server_name` | string | — | SNI override |
| `tls.insecure` | bool | `false` | Skip TLS certificate verification |
| `tls.alpn` | string[] | `["h3"]` | ALPN list |
| `tls.certificate_path` | string | — | Path to custom CA certificate |

> Dial fields (`detour`, `bind_interface`, `inet4_bind_address`, `inet6_bind_address`, `connect_timeout`, `tcp_fast_open`, `domain_strategy`) are supported but not listed individually — see the common dial documentation.

## Example

```json
{
  "type": "hysteria2",
  "tag": "hy2-out",
  "server": "example.com",
  "server_port": 443,
  "password": "your-hy2-password",
  "up_mbps": 100,
  "down_mbps": 200,
  "tls": {
    "enabled": true,
    "server_name": "example.com"
  }
}
```

### Port hopping example

```json
{
  "type": "hysteria2",
  "tag": "hy2-hop",
  "server": "example.com",
  "server_ports": "10000:20000",
  "hop_interval": "30s",
  "password": "your-hy2-password",
  "obfs": {
    "type": "salamander",
    "password": "obfs-secret"
  },
  "tls": {
    "enabled": true,
    "server_name": "example.com"
  }
}
```

## Notes

- `server_port` and `server_ports` are mutually exclusive; use `server_ports` for port hopping.
- `tls.enabled` must always be `true`; Hysteria2 is TLS-only.
- BRUTAL congestion control ignores network fairness signals — set `up_mbps`/`down_mbps` accurately to avoid degrading shared links.
- Salamander obfuscation makes packets look like random UDP; requires matching server-side config.
- `alpn` defaults to `["h3"]`; changing it will likely break compatibility with standard Hysteria2 servers.
