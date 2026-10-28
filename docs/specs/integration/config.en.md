# Configuration JSON Specification

`tachyon-core` uses a JSON configuration schema fully compatible with `sing-box`.

## Structure

The configuration is a single JSON object.

### Top-level Sections
- `log`: Logging configuration (level, output).
- `dns`: DNS resolution rules and FakeIP.
- `inbounds`: List of inbound proxy servers.
- `outbounds`: List of outbound proxy clients.
- `endpoints`: WireGuard/AmneziaWG endpoints.
- `route`: Routing rules, sniffers, and RuleSets.
- `experimental`: Clash API and cache settings.

## Example Configuration

```json
{
  "log": {
    "level": "warn",
    "output": "/var/log/tachyon.log"
  },
  "inbounds": [
    {
      "type": "mixed",
      "tag": "in",
      "listen": "::",
      "listen_port": 7890
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "route": {
    "rules": [
      {
        "outbound": "direct",
        "domain_suffix": ["example.com"]
      }
    ]
  }
}
```

<!-- GOAL_PROGRESS: 1/60 -->
