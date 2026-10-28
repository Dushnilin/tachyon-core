# Inbound: ShadowTLS

ShadowTLS v2/v3 server inbound. Validates HMAC-SHA1 handshake authentication and transparently proxies unauthenticated connections to a real TLS decoy server.

## Configuration Schema

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | Yes | Must be `"shadowtls"`. |
| `tag` | string | No | Unique identifier for this inbound. |
| `listen` | string | Yes | Listen address. |
| `listen_port` | uint16 | Yes | Port to listen on. |
| `version` | uint8 | No | Protocol version: `2` or `3` (default: `3`). |
| `password` | string | No | Single shared password. |
| `users` | array | No | Multiple users (`{"name": "...", "password": "..."}`). |
| `handshake` | object | Yes | Default decoy TLS server (`{"server": "...", "server_port": 443}`). |
| `handshake_for_server_name` | object | No | Per-SNI decoy server mapping. |
| `strict_mode` | boolean | No | Drop unauthenticated connections instead of falling back (default: `false`). |
| `wildcard_sni` | boolean | No | Allow arbitrary SNI using default `handshake` server. |

## Example

```json
{
  "type": "shadowtls",
  "tag": "stls-in",
  "listen": "::",
  "listen_port": 443,
  "version": 3,
  "users": [
    {
      "name": "user1",
      "password": "shadowtls-password"
    }
  ],
  "handshake": {
    "server": "www.microsoft.com",
    "server_port": 443
  },
  "strict_mode": true
}
```
