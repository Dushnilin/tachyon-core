# Inbound: Naive

NaiveProxy server inbound. Terminates HTTP/2 (TCP) and HTTP/3 (QUIC) CONNECT tunnels with Naive padding and Basic Authentication.

## Configuration Schema

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | Yes | Must be `"naive"`. |
| `tag` | string | No | Unique identifier for this inbound. |
| `listen` | string | Yes | Listen address. |
| `listen_port` | uint16 | Yes | Port to listen on. |
| `network` | string | No | `"tcp"` for HTTP/2 only, or omitted for both HTTP/2 and HTTP/3 QUIC. |
| `users` | array | Yes | List of users (`{"username": "...", "password": "..."}`). |
| `tls` | object | Yes | Server TLS configuration. |

## Example

```json
{
  "type": "naive",
  "tag": "naive-in",
  "listen": "::",
  "listen_port": 443,
  "users": [
    {
      "username": "naiveuser",
      "password": "naivepassword"
    }
  ],
  "tls": {
    "enabled": true,
    "certificate_path": "/etc/tachyon/cert.pem",
    "key_path": "/etc/tachyon/key.pem"
  }
}
```
