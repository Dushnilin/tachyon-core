# Inbound: Mixed / SOCKS / HTTP

Standard local proxy listener.
- `"mixed"`: Accepts SOCKS4, SOCKS4a, SOCKS5 (with UDP ASSOCIATE), and HTTP/HTTPS CONNECT on the same port.
- `"socks"`: Accepts SOCKS protocols only.
- `"http"`: Accepts HTTP/HTTPS proxy requests only.

## Configuration Schema

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | Yes | `"mixed"`, `"socks"`, or `"http"`. |
| `tag` | string | No | Unique identifier for this inbound. |
| `listen` | string | No | Listen address (default: `"127.0.0.1"`). |
| `listen_port` | uint16 | Yes | Port to listen on. |
| `users` | array | No | Optional authentication (`{"username": "...", "password": "..."}`). |
| `network` | string | No | Enable `"udp"` for SOCKS5 UDP ASSOCIATE (enabled by default). |

## Example

```json
{
  "type": "mixed",
  "tag": "mixed-in",
  "listen": "127.0.0.1",
  "listen_port": 7890,
  "users": [
    {
      "username": "localuser",
      "password": "localpassword"
    }
  ]
}
```
