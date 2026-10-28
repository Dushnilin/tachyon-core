# Inbound: TrustTunnel

TrustTunnel server inbound over HTTP/2 (TCP TLS) or HTTP/3 (QUIC). Supports TCP CONNECT streams, `_udp2` datagram multiplexing, and `_icmp` echo tunneling.

## Configuration Schema

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | Yes | Must be `"trusttunnel"`. |
| `tag` | string | No | Unique identifier for this inbound. |
| `listen` | string | Yes | Listen address. |
| `listen_port` | uint16 | Yes | Port to listen on. |
| `users` | array | Yes | List of users (`{"username": "...", "password": "..."}`). |
| `quic` | boolean | No | Listen over HTTP/3 QUIC (UDP) instead of HTTP/2 TCP (default: `false`). |
| `tls` | object | Yes | Server TLS configuration. |

## Example

```json
{
  "type": "trusttunnel",
  "tag": "tt-in",
  "listen": "::",
  "listen_port": 443,
  "users": [
    {
      "username": "ttuser",
      "password": "ttpassword"
    }
  ],
  "tls": {
    "enabled": true,
    "certificate_path": "/etc/tachyon/cert.pem",
    "key_path": "/etc/tachyon/key.pem"
  }
}
```
