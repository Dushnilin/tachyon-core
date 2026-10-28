# TUN Inbound

Virtual TUN network interface that captures system traffic, supporting TCP/UDP and FakeIP.

## Schema

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| type | string | - | Must be "tun" |
| tag | string | - | Unique identifier |
| interface_name | string | - | Interface name (e.g., "tun0") |
| inet4_address | string | - | IPv4 CIDR |
| inet6_address | string | - | IPv6 CIDR |
| mtu | integer | 9000 | MTU size |
| gso | boolean | false | Generic Segmentation Offload (Linux) |
| auto_route | boolean | false | Automatically configure routes |
| stack | string | "mixed" | "system", "gvisor", "mixed" |

## Example

```json
{
  "type": "tun",
  "tag": "tun-in",
  "interface_name": "tun0",
  "inet4_address": "172.19.0.1/30",
  "auto_route": true,
  "stack": "mixed",
  "sniff": true
}
```

## Notes

- Requires elevated privileges to create network interfaces.
- `stack: "mixed"` provides the best performance on modern Linux kernels.
