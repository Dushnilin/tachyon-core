# Inbound: Snell

Snell v4/v5/v6 server inbound supporting TCP connection reuse (`CMD_CONNECT_V2`) and UDP relay (`CMD_UDP`).

## Configuration Schema

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | Yes | Must be `"snell"`. |
| `tag` | string | No | Unique identifier for this inbound. |
| `listen` | string | Yes | Listen address. |
| `listen_port` | uint16 | Yes | Port to listen on. |
| `psk` | string | Yes | Pre-shared key. |
| `version` | uint8 | No | Protocol version: `4`, `5` (default), or `6`. |
| `mode` | string | No | Snell v6 mode (`"default"`, `"ascii"`, `"custom"`). |
| `users` | array | No | Optional user passwords (`{"password": "..."}`). |

## Example

```json
{
  "type": "snell",
  "tag": "snell-in",
  "listen": "::",
  "listen_port": 8389,
  "version": 5,
  "psk": "my-snell-pre-shared-key"
}
```
