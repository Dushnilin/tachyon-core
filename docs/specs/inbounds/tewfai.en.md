# Inbound: Tewfai

Tewfai adaptive multi-carrier server inbound. Supports TCP (TLS 1.3 / REALITY) and QUIC carriers, seamless session handover (`RESUME`), Forward Error Correction (FEC), and traffic morphing/shaping.

## Configuration Schema

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | Yes | Must be `"tewfai"`. |
| `tag` | string | No | Unique identifier for this inbound. |
| `listen` | string | Yes | Listen address. |
| `listen_port` | uint16 | Yes | Port to listen on. |
| `users` | array | Yes | List of users (`{"uuid": "..."}` or `{"password": "..."}`). |
| `transport` | string / array | No | `"tcp"`, `"quic"`, or `["tcp", "quic"]`. |
| `inner_cipher` | string | No | `"aes-256-gcm"` or `"none"` (defaults to `"none"` when outer TLS is active). |
| `fec` | boolean | No | Enable XOR Forward Error Correction for UDP datagrams. |
| `max_streams` | uint16 | No | Max concurrent multiplexed streams per session (default: `256`). |
| `handover` | object | No | Session resumption configuration (`{"enabled": true, "grace_secs": 60}`). |
| `tls` | object | No | Server TLS or REALITY configuration. |

## Example

```json
{
  "type": "tewfai",
  "tag": "tewfai-in",
  "listen": "::",
  "listen_port": 443,
  "transport": ["tcp", "quic"],
  "users": [
    {
      "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811"
    }
  ],
  "fec": true,
  "tls": {
    "enabled": true,
    "certificate_path": "/etc/tachyon/cert.pem",
    "key_path": "/etc/tachyon/key.pem"
  }
}
```
