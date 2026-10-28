# TUIC Inbound

TUIC v5 is a high-performance, QUIC-based proxy protocol with 0-RTT support and built-in multiplexing.

## Schema

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| type | string | - | Must be "tuic" |
| tag | string | - | Unique identifier |
| listen | string | "0.0.0.0" | Bind address |
| listen_port | integer | - | Required |
| users | array | - | Users (uuid, password) |
| tls | object | - | TLS configuration (Required) |

## Example

```json
{
  "type": "tuic",
  "tag": "tuic-in",
  "listen": "0.0.0.0",
  "listen_port": 443,
  "users": [
    {
      "name": "user1",
      "uuid": "c5d6e7f8-1234-5678-90ab-cdef01234567",
      "password": "password"
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

- TLS is mandatory for TUIC v5.
- TUIC is excellent for high-latency connections due to QUIC foundations.
