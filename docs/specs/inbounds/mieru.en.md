# Inbound: Mieru

Mieru server inbound supporting both TCP and UDP encrypted transports.

## Configuration Schema

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | Yes | Must be `"mieru"`. |
| `tag` | string | No | Unique identifier for this inbound. |
| `listen` | string | Yes | Listen address. |
| `listen_port` | uint16 | Yes | Port to listen on. |
| `transport` | string | No | `"tcp"` (default) or `"udp"`. |
| `users` | array | Yes | List of users (`{"name": "...", "password": "..."}`). |

## Example

```json
{
  "type": "mieru",
  "tag": "mieru-in",
  "listen": "::",
  "listen_port": 8388,
  "transport": "tcp",
  "users": [
    {
      "name": "alice",
      "password": "alice-secret-password"
    }
  ]
}
```
