# Inbound: Trojan

Trojan server inbound. Authenticates clients via SHA-224 password hashes over TLS/REALITY and supports pluggable transports (`ws`, `grpc`, `http`, `httpupgrade`, `xhttp`) and multiplexing.

## Configuration Schema

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | Yes | Must be `"trojan"`. |
| `tag` | string | No | Unique identifier for this inbound. |
| `listen` | string | Yes | Listen address. |
| `listen_port` | uint16 | Yes | Port to listen on. |
| `users` | array | Yes | List of users (`{"name": "...", "password": "..."}`). |
| `fallback` | object | No | Decoy fallback address (`{"server": "...", "server_port": 80}`). |
| `tls` | object | No | Server TLS / REALITY configuration. |
| `transport` | object | No | Transport layer (`ws`, `grpc`, `http`, `httpupgrade`, `xhttp`). |
| `multiplex` | object | No | Multiplexing settings (`h2mux`). |

## Example

```json
{
  "type": "trojan",
  "tag": "trojan-in",
  "listen": "::",
  "listen_port": 443,
  "users": [
    {
      "name": "user1",
      "password": "trojan-secret-password"
    }
  ],
  "tls": {
    "enabled": true,
    "certificate_path": "/etc/tachyon/cert.pem",
    "key_path": "/etc/tachyon/key.pem"
  }
}
```
