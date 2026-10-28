# Inbound: AnyTLS

AnyTLS server inbound. Masks proxy traffic inside standard TLS 1.3 connections with customizable padding schemes and multiplexing.

## Configuration Schema

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | Yes | Must be `"anytls"`. |
| `tag` | string | No | Unique identifier for this inbound. |
| `listen` | string | Yes | Listen address (e.g., `"::"` or `"0.0.0.0"`). |
| `listen_port` | uint16 | Yes | Port to listen on. |
| `users` | array | Yes | List of authorized users (`{"name": "...", "password": "..."}`). |
| `padding_scheme` | array of strings | No | Custom traffic padding rules. |
| `tls` | object | Yes | Server TLS configuration (`enabled: true`, `certificate_path`, `key_path`). |

## Example

```json
{
  "type": "anytls",
  "tag": "anytls-in",
  "listen": "::",
  "listen_port": 443,
  "users": [
    {
      "name": "user1",
      "password": "super-secret-password"
    }
  ],
  "tls": {
    "enabled": true,
    "certificate_path": "/etc/tachyon/cert.pem",
    "key_path": "/etc/tachyon/key.pem"
  }
}
```
