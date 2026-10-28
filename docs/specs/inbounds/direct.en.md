# Inbound: Direct

Transit inbound that accepts raw TCP/UDP connections and forwards them directly into the routing engine (optionally overriding the destination address/port).

## Configuration Schema

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | Yes | Must be `"direct"`. |
| `tag` | string | No | Unique identifier for this inbound. |
| `listen` | string | Yes | Listen address. |
| `listen_port` | uint16 | Yes | Port to listen on. |
| `network` | string | No | `"tcp"`, `"udp"`, or omitted for both. |
| `override_address` | string | No | Override destination IP or domain. |
| `override_port` | uint16 | No | Override destination port. |

## Example (Local DNS Forwarder)

```json
{
  "type": "direct",
  "tag": "dns-in",
  "listen": "127.0.0.1",
  "listen_port": 5353,
  "network": "udp",
  "override_address": "1.1.1.1",
  "override_port": 53
}
```
