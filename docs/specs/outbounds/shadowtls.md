# ShadowTLS Outbound

Wraps another proxy outbound in a fake TLS handshake camouflage layer to bypass TLS-aware DPI.

## Schema

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | — | Must be `"shadowtls"` |
| `tag` | string | — | Unique outbound identifier |
| `server` | string | — | ShadowTLS server hostname or IP address |
| `server_port` | integer | — | ShadowTLS server port |
| `version` | integer | `3` | Protocol version: `1`, `2`, or `3`. Use v3 (recommended, replay-resistant) |
| `password` | string | — | **Required** for v2/v3. Authentication password |
| `detour` | string | — | Tag of the inner proxy outbound to wrap (e.g. a Shadowsocks outbound) |
| `tls.enabled` | bool | — | **Required**, must be `true` |
| `tls.server_name` | string | — | **Required.** Must be a real domain with a valid TLS certificate to mimic |
| `tls.utls.enabled` | bool | `false` | Enable uTLS for browser TLS fingerprint emulation |
| `tls.utls.fingerprint` | string | — | uTLS fingerprint: `"chrome"`, `"firefox"`, `"safari"`, `"ios"`, `"android"`, `"edge"`, `"360"`, `"qq"`, `"random"`, `"randomized"` |

> Dial fields (`bind_interface`, `connect_timeout`, `domain_strategy`, etc.) are supported — see the common dial documentation.

## Example

```json
{
  "type": "shadowtls",
  "tag": "shadowtls-out",
  "server": "192.0.2.1",
  "server_port": 443,
  "version": 3,
  "password": "st-password",
  "tls": {
    "enabled": true,
    "server_name": "www.apple.com",
    "utls": {
      "enabled": true,
      "fingerprint": "safari"
    }
  },
  "detour": "ss-out"
}
```

The inner Shadowsocks outbound referenced by `detour`:

```json
{
  "type": "shadowsocks",
  "tag": "ss-out",
  "server": "127.0.0.1",
  "server_port": 8388,
  "method": "2022-blake3-aes-128-gcm",
  "password": "ss-password"
}
```

## Notes

- `detour` points to the tag of the inner proxy outbound (e.g. Shadowsocks). ShadowTLS only handles the TLS camouflage layer; the inner outbound handles actual data encryption.
- `tls.server_name` **must** be a real domain whose TLS handshake a real browser would produce. Using a fake or self-signed domain defeats the purpose.
- v3 is the only replay-resistant version; prefer it over v1/v2 in production deployments.
- uTLS (`tls.utls`) makes the TLS `ClientHello` match a specific browser fingerprint, significantly improving DPI bypass effectiveness.
- The inner outbound's `server`/`server_port` are typically loopback or internal; ShadowTLS establishes the outer TCP connection.
