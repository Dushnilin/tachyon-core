# Inbound: OpenConnect

Corporate SSL-VPN server inbound supporting Cisco AnyConnect, Palo Alto GlobalProtect, Juniper Network Connect, Pulse Secure, F5, and Fortinet flavors.

## Configuration Schema

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | Yes | Must be `"openconnect"`. |
| `tag` | string | No | Unique identifier for this inbound. |
| `listen` | string | Yes | Listen address. |
| `listen_port` | uint16 | Yes | Port to listen on. |
| `flavor` | string | Yes | `"anyconnect"`, `"gp"`, `"nc"`, `"pulse"`, `"f5"`, or `"fortinet"`. |
| `cookie` | string | No | Session authentication token/cookie. |
| `ip` | boolean | No | Carry raw IP packets inside the tunnel (default: `false`). |
| `esp` | boolean | No | Enable ESP UDP transport (requires `ip: true`). |
| `dtls` | boolean | No | Enable DTLS UDP transport (`"anyconnect"` flavor only). |
| `dtls_port` | uint16 | No | UDP port for DTLS listener (`0` for dynamic). |
| `mtu` | uint16 | No | Tunnel MTU (default: `1400`). |
| `tls` | object | No | Server TLS configuration. |

## Example

```json
{
  "type": "openconnect",
  "tag": "oc-in",
  "listen": "::",
  "listen_port": 443,
  "flavor": "anyconnect",
  "cookie": "secret-session-cookie",
  "ip": true,
  "dtls": true,
  "mtu": 1400,
  "tls": {
    "enabled": true,
    "certificate_path": "/etc/tachyon/cert.pem",
    "key_path": "/etc/tachyon/key.pem"
  }
}
```
