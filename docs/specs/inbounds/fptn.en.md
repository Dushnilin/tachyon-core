# Inbound: FPTN

FPTN server inbound. Tunnels IP packets over WebSocket/HTTPS and assigns virtual IP addresses to authenticated clients.

## Configuration Schema

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | Yes | Must be `"fptn"`. |
| `tag` | string | No | Unique identifier for this inbound. |
| `listen` | string | Yes | Listen address. |
| `listen_port` | uint16 | Yes | Port to listen on. |
| `users` | array | Yes | List of users (`{"username": "...", "password": "..."}`). |
| `dns` | string | No | IPv4 DNS server address pushed to clients. |
| `ipv4_pool` | string | No | CIDR pool for client IPv4 assignment (e.g., `"10.10.0.0/24"`). |
| `ipv6_pool` | string | No | CIDR pool for client IPv6 assignment. |
| `obfuscation` | string | No | Handshake obfuscation mode (`"tls"` or `"none"`). |
| `tls` | object | Yes | Server TLS configuration. |

## Example

```json
{
  "type": "fptn",
  "tag": "fptn-in",
  "listen": "::",
  "listen_port": 8443,
  "users": [
    {
      "username": "user1",
      "password": "password123"
    }
  ],
  "ipv4_pool": "10.10.0.0/24",
  "dns": "1.1.1.1",
  "tls": {
    "enabled": true,
    "certificate_path": "/etc/tachyon/cert.pem",
    "key_path": "/etc/tachyon/key.pem"
  }
}
```
