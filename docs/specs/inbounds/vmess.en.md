# VMess Inbound

VMess is the classic V2Ray protocol with built-in authentication, supporting various transports (TCP, WS, GRPC, HTTPUpgrade).

## Schema

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| type | string | - | Must be "vmess" |
| tag | string | - | Unique identifier |
| listen | string | "0.0.0.0" | Bind address |
| listen_port | integer | - | Required |
| users | array | - | Allowed users (uuid, alterId) |
| tls | object | - | TLS server configuration |

## Example

```json
{
  "type": "vmess",
  "tag": "vmess-in",
  "listen": "0.0.0.0",
  "listen_port": 10000,
  "users": [
    {
      "name": "user1",
      "uuid": "b3e4e91a-8a6d-4b88-b7e5-3b7a8c1e2f3d",
      "alterId": 0
    }
  ],
  "tls": {
    "enabled": true,
    "certificate_path": "/etc/tachyon/cert.pem",
    "key_path": "/etc/tachyon/key.pem"
  }
}
```

## Notes

- `alterId` should be set to 0 to enable AEAD.
- VMess supports a variety of transports; ensure transport configuration matches client expectations.
