# Clash API Specification

`tachyon-core` exposes a RESTful API compatible with the Clash control plane, used by dashboards like Yacd and Metacubexd.

## Configuration

Configured under `experimental.clash_api`.

```json
{
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "secret": "your-secret-token",
      "external_ui": "/etc/tachyon/ui",
      "external_ui_download_url": "https://github.com/MetaCubeX/Yacd-meta/archive/gh-pages.zip",
      "external_ui_download_detour": "direct",
      "access_control_allow_origin": ["*"],
      "access_control_allow_private_network": true
    }
  }
}
```

## Endpoints

### `GET /version`
Returns the core version.

### `GET /proxies`
Returns all outbounds and selector groups.

### `GET /proxies/{name}`
Returns details for a specific outbound.

### `PUT /proxies/{name}`
Switches the active outbound in a `selector` group.
Payload: `{"name": "target-outbound"}`

### `GET /proxies/{name}/delay`
Measures latency to a target URL through the specified outbound.
Query params: `url`, `timeout`.

### `GET /connections` & `DELETE /connections/{id}`
Lists and closes active connections. Supports WebSocket streaming.

### `GET /logs` & `GET /traffic`
Streams real-time logs and traffic statistics (supports HTTP chunked and WebSocket).

### `GET /rules`
Lists active routing rules.

### `GET|PATCH /configs`
Views or updates runtime configuration settings (e.g., `mode`).
