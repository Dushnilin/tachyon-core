# Спецификация Clash API

`tachyon-core` предоставляет RESTful API, совместимый с плоскостью управления Clash, используемой дашбордами вроде Yacd и Metacubexd.

## Конфигурация

Настраивается в секции `experimental.clash_api`.

```json
{
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "secret": "ваш-секретный-токен",
      "external_ui": "/etc/tachyon/ui",
      "external_ui_download_url": "https://github.com/MetaCubeX/Yacd-meta/archive/gh-pages.zip",
      "external_ui_download_detour": "direct",
      "access_control_allow_origin": ["*"],
      "access_control_allow_private_network": true
    }
  }
}
```

## Эндпоинты

### `GET /version`
Возвращает версию ядра.

### `GET /proxies`
Возвращает все аутбаунды и группы `selector`.

### `GET /proxies/{name}`
Возвращает детали конкретного аутбаунда.

### `PUT /proxies/{name}`
Переключает активный аутбаунд в группе `selector`.
Тело запроса: `{"name": "целевой-аутбаунд"}`

### `GET /proxies/{name}/delay`
Измеряет задержку до целевого URL через указанный аутбаунд.
Параметры запроса: `url`, `timeout`.

### `GET /connections` и `DELETE /connections/{id}`
Список и закрытие активных соединений. Поддерживает стриминг через WebSocket.

### `GET /logs` и `GET /traffic`
Стриминг логов и статистики трафика в реальном времени (поддерживает HTTP chunked и WebSocket).

### `GET /rules`
Список активных правил маршрутизации.

### `GET|PATCH /configs`
Просмотр или обновление настроек рантайма (например, `mode`).
