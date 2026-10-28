# MTProto Outbound

Obfuscated MTProto proxy outbound for routing Telegram traffic through a proxy server.

## Schema

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | — | Must be `"mtproto"` |
| `tag` | string | — | Unique outbound tag |
| `server` | string | — | Proxy server address (hostname or IP) |
| `server_port` | integer | — | Proxy server port |
| `secret` | string | — | MTProto proxy secret. Hex string prefixed with `ee` for FakeTLS mode, or `dd` for obfs2 mode. May also be base64-encoded. |
| *(dial fields)* | — | — | Standard dial fields (e.g. `detour`, `bind_interface`) |

## Example

```json
{
  "type": "mtproto",
  "tag": "mtproto-out",
  "server": "proxy.example.com",
  "server_port": 443,
  "secret": "ee1234567890abcdef1234567890abcdwww.google.com"
}
```

## Notes

- Secrets prefixed with `dd` use **obfs2** obfuscation mode.
- Secrets prefixed with `ee` use **FakeTLS** mode — the connection mimics TLS traffic to a domain embedded in the secret (after the 32-byte hex key). FakeTLS is strongly recommended for bypassing DPI.
- This outbound is only useful for Telegram traffic. Configure routing rules to match Telegram IP ranges (e.g. `91.108.0.0/16`, `149.154.0.0/16`) and direct them to this outbound.
- The proxy server must be a compatible MTProto proxy implementation (e.g. MTProxy, mtg).
