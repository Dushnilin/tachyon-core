# Inbound: Hysteria2

Hysteria 2 server inbound over QUIC/HTTP3 with optional Salamander UDP obfuscation.

## Configuration Schema

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | Yes | Must be `"hysteria2"`. |
| `tag` | string | No | Unique identifier for this inbound. |
| `listen` | string | Yes | Listen address. |
| `listen_port` | uint16 | Yes | UDP port to listen on. |
| `users` | array | Yes | List of users (`{"name": "...", "password": "..."}`). |
| `up_mbps` | uint64 | No | Max upload bandwidth in Mbps. |
| `down_mbps` | uint64 | No | Max download bandwidth in Mbps. |
| `obfs` | object | No | Salamander obfuscation (`{"type": "salamander", "password": "..."}`). |
| `tls` | object | Yes | Server TLS configuration. |

## Example

```json
{
  "type": "hysteria2",
  "tag": "hy2-in",
  "listen": "::",
  "listen_port": 443,
  "users": [
    {
      "name": "client1",
      "password": "hy2-secret-password"
    }
  ],
  "up_mbps": 100,
  "down_mbps": 100,
  "obfs": {
    "type": "salamander",
    "password": "salamander-obfs-key"
  },
  "tls": {
    "enabled": true,
    "certificate_path": "/etc/tachyon/cert.pem",
    "key_path": "/etc/tachyon/key.pem"
  }
}
```
