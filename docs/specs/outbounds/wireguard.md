# WireGuard Outbound

WireGuard / AmneziaWG VPN tunnel outbound with Full Cone NAT support and optional junk-packet obfuscation.

## Schema

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | — | Must be `"wireguard"` |
| `tag` | string | — | Unique outbound identifier |
| `server` | string | — | Peer endpoint hostname or IP (single-peer mode) |
| `server_port` | integer | — | Peer endpoint port (single-peer mode) |
| `local_address` | string[] | — | **Required.** CIDR addresses assigned to the local tunnel interface (e.g. `["10.0.0.2/32", "fd00::2/128"]`) |
| `private_key` | string | — | **Required.** Base64-encoded WireGuard private key |
| `peer_public_key` | string | — | **Required** (single-peer). Base64-encoded server public key |
| `pre_shared_key` | string | — | Optional base64 pre-shared key (PSK) for additional symmetric encryption |
| `peers` | object[] | — | Multi-peer list; each entry has `server`, `server_port`, `public_key`, `pre_shared_key`, `allowed_ips` |
| `mtu` | integer | `1408` | Tunnel MTU in bytes |
| `workers` | integer | CPU count | Number of parallel packet-processing workers |
| `network` | string | `"tcp,udp"` | Supported network types: `"tcp"`, `"udp"`, or `"tcp,udp"` |
| `fake_packets` | string | — | AmneziaWG: junk packet count range, e.g. `"5-10"` |
| `fake_packets_size` | string | — | AmneziaWG: junk packet byte-size range, e.g. `"40-100"` |
| `fake_packets_delay` | string | — | AmneziaWG: delay between junk packets in ms, e.g. `"20-250"` |
| `fake_packets_mode` | string | — | AmneziaWG obfuscation mode; currently only `"m1"` |

> Dial fields (`detour`, `bind_interface`, `connect_timeout`, `domain_strategy`, etc.) are supported — see the common dial documentation.

## Example

### Standard WireGuard

```json
{
  "type": "wireguard",
  "tag": "wg-out",
  "server": "vpn.example.com",
  "server_port": 51820,
  "local_address": ["10.10.10.2/32", "fd00::2/128"],
  "private_key": "YBOnRyBsXxDG6cFi3MtSKE0E2dVoqDkqPVBRKwVPgGQ=",
  "peer_public_key": "mBpbKhQVEtmkQfb5nuY5e3RIcl0g/bVpADf1i2f+9Wk=",
  "mtu": 1280,
  "workers": 2
}
```

### AmneziaWG (junk-packet obfuscation)

```json
{
  "type": "wireguard",
  "tag": "awg-out",
  "server": "vpn.example.com",
  "server_port": 51820,
  "local_address": ["10.10.10.2/32"],
  "private_key": "YBOnRyBsXxDG6cFi3MtSKE0E2dVoqDkqPVBRKwVPgGQ=",
  "peer_public_key": "mBpbKhQVEtmkQfb5nuY5e3RIcl0g/bVpADf1i2f+9Wk=",
  "fake_packets": "5-10",
  "fake_packets_size": "40-100",
  "fake_packets_delay": "20-250",
  "fake_packets_mode": "m1"
}
```

### Multi-peer

```json
{
  "type": "wireguard",
  "tag": "wg-multi",
  "local_address": ["10.10.10.2/32"],
  "private_key": "YBOnRyBsXxDG6cFi3MtSKE0E2dVoqDkqPVBRKwVPgGQ=",
  "peers": [
    {
      "server": "peer1.example.com",
      "server_port": 51820,
      "public_key": "mBpbKhQVEtmkQfb5nuY5e3RIcl0g/bVpADf1i2f+9Wk=",
      "allowed_ips": ["0.0.0.0/0", "::/0"]
    }
  ]
}
```

## Notes

- `fake_packets_*` fields activate AmneziaWG mode; all four should be set together. They have no effect without a matching AmneziaWG server.
- Lower `mtu` values (e.g. `1280`) help avoid fragmentation over PPPoE or other encapsulating transports.
- `workers` defaults to the number of logical CPUs; reducing it on low-core routers lowers CPU contention.
- Full Cone NAT allows inbound P2P connections to the tunnel; this is the default WireGuard NAT behavior.
- In multi-peer mode, `server` / `server_port` / `peer_public_key` at the top level are ignored — all peer data must be in the `peers` array.
