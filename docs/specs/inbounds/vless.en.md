# VLESS Inbound

VLESS is a lightweight proxy protocol without encryption, designed to be used with TLS/REALITY for security. Supports Vision flow control and XUDP.

## Schema

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| type | string | - | Must be "vless" |
| tag | string | - | Unique identifier |
| listen | string | "0.0.0.0" | Bind address |
| listen_port | integer | - | Required |
| users | array | - | List of allowed users |
| tls | object | - | TLS server configuration |

## Example

```json
{
  "type": "vless",
  "tag": "vless-in",
  "listen": "0.0.0.0",
  "listen_port": 443,
  "users": [
    {
      "name": "user1",
      "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf",
      "flow": "xtls-rprx-vision"
    }
  ],
  "tls": {
    "enabled": true,
    "reality": {
      "enabled": true,
      "handshake": { "server": "google.com", "server_port": 443 },
      "private_key": "..."
    }
  }
}
```

## Notes

- VLESS itself provides no encryption. TLS or REALITY must be used for transport security.
- Vision flow control is highly recommended for anti-DPI performance.
