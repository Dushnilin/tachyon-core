# Direct Outbound

Forwards traffic directly to the destination without any proxy. Supports interface binding, address override, and PROXY protocol injection.

## Schema

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | `"direct"` | — | Must be `"direct"`. |
| `tag` | string | — | Unique label for this outbound. |
| `override_address` | string | — | Replace the destination address for every connection. |
| `override_port` | integer | — | Replace the destination port for every connection. |
| `proxy_protocol` | integer | — | Emit a PROXY protocol header before data; `1` = v1 (text), `2` = v2 (binary). |
| `bind_address` | string | — | Local IP address to bind the outgoing socket to. |
| `bind_interface` | string | — | Local network interface to bind the outgoing socket to. |
| `routing_mark` | integer | — | `SO_MARK` value set on outgoing sockets (Linux only). |
| `reuse_addr` | bool | `false` | Set `SO_REUSEADDR` on the outgoing socket. |
| `connect_timeout` | duration | `"300s"` | Timeout for establishing a TCP connection. |
| `tcp_fast_open` | bool | `false` | Enable TCP Fast Open. |
| `domain_strategy` | string | `"prefer_ipv4"` | DNS resolution strategy: `"prefer_ipv4"`, `"prefer_ipv6"`, `"ipv4_only"`, `"ipv6_only"`. |
| `fallback_delay` | duration | `"300ms"` | Happy-eyeballs delay before attempting the fallback address family. |

## Example

```json
{
  "type": "direct",
  "tag": "direct",
  "bind_interface": "eth0",
  "domain_strategy": "prefer_ipv4"
}
```

## Notes

- `override_address` and `override_port` apply to **every** connection through this outbound; use with care in routing rules.
- `proxy_protocol` requires the upstream server to accept PROXY protocol headers; mismatches will cause connection errors.
- `bind_interface` and `bind_address` are mutually exclusive on most platforms.
- `routing_mark` is Linux-specific and is ignored on other operating systems.
