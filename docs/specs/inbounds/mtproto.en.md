# Inbound: MTProto

Telegram MTProto proxy server inbound with obfuscated stream framing.

## Configuration Schema

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | Yes | Must be `"mtproto"`. |
| `tag` | string | No | Unique identifier for this inbound. |
| `listen` | string | Yes | Listen address. |
| `listen_port` | uint16 | Yes | Port to listen on. |
| `secret` | string | No | Single 16-byte hex secret (or `dd`/`ee` prefixed). |
| `users` | array | No | Multiple client secrets (`{"secret": "..."}`). |
| `transport` | string | No | Enforce specific framing (`"abridged"`, `"intermediate"`, `"padded"`, `"full"`). |
| `tls` | object | No | Optional Server TLS wrapper. |

## Example

```json
{
  "type": "mtproto",
  "tag": "mtproto-in",
  "listen": "::",
  "listen_port": 443,
  "users": [
    {
      "secret": "0123456789abcdef0123456789abcdef"
    }
  ],
  "transport": "padded"
}
```
