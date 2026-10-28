# Inbound: Redirect

Transparent TCP proxy inbound using Linux netfilter `REDIRECT` (recovers original destination via `SO_ORIGINAL_DST` / `IP6T_SO_ORIGINAL_DST`). TCP only — for transparent UDP interception, use `tproxy`.

## Configuration Schema

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | Yes | Must be `"redirect"`. |
| `tag` | string | No | Unique identifier for this inbound. |
| `listen` | string | Yes | Listen address. |
| `listen_port` | uint16 | Yes | Port to listen on. |

## Example

```json
{
  "type": "redirect",
  "tag": "redir-in",
  "listen": "::",
  "listen_port": 7892
}
```
