# Inbound: MASQUE

MASQUE (RFC 9484 CONNECT-IP over HTTP/3 QUIC) server inbound. Bridges client IP datagrams into the routing engine via an internal userspace TCP/UDP stack.

## Configuration Schema

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | Yes | Must be `"masque"`. |
| `tag` | string | No | Unique identifier for this inbound. |
| `listen` | string | Yes | Listen address. |
| `listen_port` | uint16 | Yes | UDP port to listen on. |
| `mtu` | uint16 | No | Tunnel MTU (default: `1280`, minimum: `1200`). |
| `tls` | object | Yes | Server TLS configuration. |

## Example

```json
{
  "type": "masque",
  "tag": "masque-in",
  "listen": "::",
  "listen_port": 443,
  "mtu": 1280,
  "tls": {
    "enabled": true,
    "certificate_path": "/etc/tachyon/cert.pem",
    "key_path": "/etc/tachyon/key.pem"
  }
}
```
