# TPROXY Inbound

Transparent proxy inbound using the Linux TPROXY kernel mechanism to intercept traffic redirected by nftables/iptables.

## Schema

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| type | string | - | Must be "tproxy" |
| tag | string | - | Unique identifier |
| listen | string | "0.0.0.0" | Address to bind |
| listen_port | integer | - | Required: Port to bind |
| network | string | "tcp,udp" | "tcp", "udp", or "tcp,udp" |
| tcp_fast_open | boolean | false | Enable TFO |
| udp_timeout | duration | "5m" | UDP session timeout |
| sniff | boolean | false | Enable protocol sniffing |
| sniff_override_destination | boolean | false | Override destination on sniff |
| mark | integer | - | SO_MARK for routing bypass |

## Example

```json
{
  "type": "tproxy",
  "tag": "tproxy-in",
  "listen": "0.0.0.0",
  "listen_port": 1080,
  "network": "tcp,udp",
  "sniff": true,
  "mark": 255
}
```

## Notes

- Requires `CAP_NET_ADMIN` to set `SO_MARK` and bind to TPROXY sockets.
- Designed for Linux routers; on OpenWrt, configure appropriate `nftables` rules to divert traffic to the listener port.
