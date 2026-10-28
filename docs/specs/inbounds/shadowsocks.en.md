# Inbound: Shadowsocks

Shadowsocks server inbound supporting both classic AEAD ciphers and Shadowsocks-2022 (`2022-blake3-*`) over TCP and UDP.

## Configuration Schema

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | Yes | Must be `"shadowsocks"`. |
| `tag` | string | No | Unique identifier for this inbound. |
| `listen` | string | Yes | Listen address. |
| `listen_port` | uint16 | Yes | Port to listen on. |
| `method` | string | Yes | Cipher (`"2022-blake3-aes-128-gcm"`, `"2022-blake3-aes-256-gcm"`, `"2022-blake3-chacha20-poly1305"`, `"aes-128-gcm"`, `"aes-256-gcm"`, `"chacha20-ietf-poly1305"`, `"none"`). |
| `password` | string | Yes | Master password (base64 key for 2022 methods). |
| `network` | string | No | `"tcp"`, `"udp"`, or omitted for both. |
| `udp_timeout` | string | No | UDP NAT session timeout (e.g., `"5m"`). |

## Example

```json
{
  "type": "shadowsocks",
  "tag": "ss-in",
  "listen": "::",
  "listen_port": 8388,
  "method": "2022-blake3-aes-128-gcm",
  "password": "base64-encoded-16-byte-key=="
}
```
