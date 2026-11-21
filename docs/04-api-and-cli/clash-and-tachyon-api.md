# Спецификация HTTP и WebSocket API (Clash API и `/tachyon/*`)

Контроллер управления `tachyon-core` (v0.6.2) объединяет Clash-совместимый REST/WebSocket API для панелей мониторинга (Yacd, Metacubexd, Zashboard и др.), метрики Prometheus (`/metrics`) и расширенный набор нативных эндпоинтов `/tachyon/*` для диагностики, управления LAN-устройствами, горячей проверки маршрутов и контроля ресурсов.

## Включение и конфигурация

Контроллер активируется в секции `experimental.clash_api` (см. [Экспериментальные параметры](../02-config/experimental.md)):

```json
{
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "secret": "replace-with-strong-token",
      "external_ui": "/usr/share/tachyon-core/ui",
      "external_ui_download_url": "https://github.com/MetaCubeX/Yacd-meta/archive/gh-pages.zip",
      "external_ui_download_detour": "proxy",
      "access_control_allow_origin": ["*"],
      "access_control_allow_private_network": false
    }
  }
}
```

- Адрес `external_controller` в сокращённой форме `:9090` автоматически нормализуется в `0.0.0.0:9090`. Если `external_controller` пуст или отсутствует, HTTP-контроллер не запускается.
- Устаревшие поля `cache_file`, `cache_id`, `store_mode`, `store_selected`, `store_fakeip` внутри `clash_api` отклоняются при старте — для персистентности используйте `experimental.cache_file`.
- Если задан `external_ui` и указанный каталог пуст, движок при старте однократно скачивает и распаковывает ZIP-архив из `external_ui_download_url` (по умолчанию Yacd-meta) через `external_ui_download_detour` (или напрямую).

---

## Транспорт, авторизация, CORS и ошибки

### Параметры HTTP/1.1 и ограничения

| Параметр | Значение |
|---|---|
| Keep-Alive | Поддерживается; таймаут простоя между запросами — `60 с` |
| Таймаут чтения заголовков и тела | `10 с` |
| Таймаут записи потоковых ответов (WS / chunked) | `15 с` |
| Максимум одновременных подключений к API | `128` |
| Максимальный размер заголовков запроса | `16 KiB` |
| Максимальный размер тела JSON-запроса | `64 KiB` (для `POST /tachyon/delay-batch` — `512 KiB`, для `PUT /configs` — `1 MiB`) |
| Максимальный размер файла конфигурации в `PUT /configs` (`path`) | `16 MiB` |
| Максимальный размер статического файла `/ui/*` | `16 MiB` (`413 Payload Too Large` при превышении) |

### Авторизация

Если в `experimental.clash_api.secret` задана непустая строка:
- Для обычных HTTP-запросов требуется заголовок:
  ```http
  Authorization: Bearer <secret>
  ```
- Для WebSocket-подключений (`Upgrade: websocket`) дополнительно допускается передача секрета в query-параметре:
  ```text
  ws://127.0.0.1:9090/traffic?token=<secret>
  ```
- Без авторизации остаются доступными только маршруты веб-интерфейса `/ui`, `/ui/*` и браузерный `GET /` (без заголовка `Content-Type: application/json`), если настроен `external_ui`.
- При отсутствии или несовпадении токена возвращается `401 Unauthorized` с телом `{"message":"Unauthorized"}`.

### CORS и Preflight

- Каждый ответ включает `Vary: Origin`, а при совпадении заголовка `Origin` со списком `access_control_allow_origin` (по умолчанию `["*"]`) добавляется `Access-Control-Allow-Origin`.
- Запросы `OPTIONS` с заголовком `Access-Control-Request-Method` перехватываются до проверки авторизации. Разрешённые методы: `GET, POST, PUT, PATCH, DELETE`; разрешённые заголовки: `Content-Type`, `Authorization`; `Access-Control-Max-Age: 300`.
- Если включён `access_control_allow_private_network: true` и клиент передал `Access-Control-Request-Private-Network: true`, возвращается `Access-Control-Allow-Private-Network: true`.

### Формат ошибок

| HTTP-статус | Тело ответа | Когда возвращается |
|---|---|---|
| `400 Bad Request` | `{"message":"Body invalid"}` или уточняющее описание | Некорректный JSON, отсутствующий обязательный параметр, невалидный режим/уровень лога или отклонение конфигурации в `PUT /configs`. |
| `401 Unauthorized` | `{"message":"Unauthorized"}` | Неверный или отсутствующий токен авторизации. |
| `404 Not Found` | `{"message":"Resource not found"}` (для сущностей) или `404 page not found\n` (`text/plain`, для неизвестного пути) | Неизвестный маршрут, прокси, соединение, провайдер или статический файл. |
| `405 Method Not Allowed` | Пустое тело + заголовки `Allow` | Неподдерживаемый HTTP-метод для существующего маршрута. |
| `413 Payload Too Large` | `asset too large\n` (`text/plain`) | Размер файла в `/ui/*` превышает `16 MiB`. |
| `502 Bad Gateway` | `{"message":"..."}` | Ошибка обращения к внешнему API (например, `/tachyon/warp/register`). |
| `503 Service Unavailable` | `{"message":"...","reason":"..."}` | Неудачная проверка задержки/доступности или сбой обновления провайдера правил. |
| `504 Gateway Timeout` | `{"message":"Timeout"}` | Превышение таймаута при тестировании задержки, exit-IP или Tailscale ping. |

---

## Сводная таблица Clash-совместимых эндпоинтов

| Метод | Путь | Протокол | Назначение |
|---|---|---|---|
| `GET` | `/` | HTTP | Приветствие `{"hello":"clash"}` или редирект `307 -> /ui/` |
| `GET` | `/ui`, `/ui/*` | HTTP | Статические файлы веб-интерфейса (`external_ui`) |
| `GET` | `/version` | HTTP | Версия движка и флаги совместимости |
| `GET` | `/configs` | HTTP | Текущие настройки контроллера, режима и уровня логов |
| `PATCH` | `/configs` | HTTP | Смена `mode` и/или `log-level` (с опциональным `ttl_sec`) |
| `PUT` | `/configs` | HTTP | Горячая перезагрузка конфигурации на месте (`path` или `payload`) |
| `GET` | `/proxies` | HTTP | Список всех аутбаундов и групп (включая синтетическую `GLOBAL`) |
| `GET` | `/proxies/{name}` | HTTP | Состояние одного аутбаунда или группы |
| `PUT` | `/proxies/{name}` | HTTP | Переключение активного узла в группе `Selector` |
| `GET` | `/proxies/{name}/delay` | HTTP | Измерение задержки узла или всех участников группы |
| `GET` | `/group/{name}/delay` | HTTP | Псевдоним `/proxies/{name}/delay` для групп |
| `GET` | `/proxies/{name}/exit` | HTTP | Определение внешнего IPv4/IPv6 и страны выхода узла |
| `GET` | `/proxies/{name}/link` | HTTP | Экспорт share-link URI для аутбаунда |
| `GET` | `/providers/proxies` | HTTP | Список провайдеров подписок |
| `GET` | `/providers/proxies/{name}` | HTTP | Информация об одном провайдере подписки |
| `PUT` | `/providers/proxies/{name}` | HTTP | Принудительное обновление провайдера подписки |
| `GET` | `/providers/proxies/{name}/links` | HTTP | Экспорт всех URI узлов провайдера (псевдоним `/link`) |
| `GET` | `/providers/rules` | HTTP | Список всех наборов правил (`rule_set`) и глобальная ревизия |
| `PUT` | `/providers/rules` | HTTP | Принудительное обновление всех удалённых наборов правил |
| `GET` | `/providers/rules/events` | HTTP | Long-poll уведомления об обновлении наборов правил |
| `GET` | `/providers/rules/{name}` | HTTP | Информация об одном наборе правил |
| `PUT` | `/providers/rules/{name}` | HTTP | Принудительное обновление одного набора правил |
| `GET` | `/rules` | HTTP | Список активных правил маршрутизации |
| `GET` | `/connections` | HTTP / WS | Снимок или поток активных соединений, трафика и RSS |
| `DELETE` | `/connections` | HTTP | Закрытие всех активных соединений |
| `GET` | `/connections/{id}` | HTTP | Детали одного активного соединения |
| `DELETE` | `/connections/{id}` | HTTP | Закрытие одного активного соединения |
| `GET` | `/traffic` | HTTP chunked / WS | Поток скоростей `up`/`down` (байт/с) раз в секунду |
| `GET` | `/logs` | HTTP chunked / WS | Буфер последних логов и поток новых событий |
| `GET` | `/tailscale` | HTTP | Состояние всех Tailscale-эндпоинтов |
| `GET` | `/tailscale/{tag}/ping` | HTTP | Проверка задержки до узла в Tailscale-сети |
| `GET` | `/metrics` | HTTP | Метрики в формате Prometheus |

> **Примечание о совместимости с другими реализациями Clash API:** маршруты `/memory`, `/dns/query` и `/cache/fakeip/flush` в `tachyon-core` не используются; вместо них предоставляются расширенные нативные маршруты `GET /tachyon/memory`, `POST /tachyon/dns-check` и `POST /tachyon/dns/flush`. Горячая перезагрузка конфигурации выполняется через `PUT /configs`.

---

## Подробное описание Clash-эндпоинтов

### `GET /` и `/ui/*`

- Если `external_ui` не задан или клиент передал `Content-Type: application/json`, `GET /` возвращает `200 OK`:
  ```json
  {"hello": "clash"}
  ```
- Если `external_ui` задан и `Content-Type` не равен `application/json`, `GET /` возвращает `307 Temporary Redirect` на `/ui/`.
- `GET /ui` возвращает `301 Moved Permanently` на `/ui/`.
- `GET /ui/<asset>` отдаёт статический файл из каталога `external_ui` (для каталогов — `index.html`). Переходы `..` отклоняются с `404`.

### `GET /version`

```bash
curl -H "Authorization: Bearer mysecret" http://127.0.0.1:9090/version
```

```json
{
  "version": "tachyon-core 0.6.2",
  "premium": true,
  "meta": true
}
```

### `GET /configs`, `PATCH /configs`, `PUT /configs`

#### `GET /configs`

Возвращает текущий режим маршрутизации, уровень логирования, признак включённого IPv6 и настройки контроллера:

```json
{
  "port": 0,
  "socks-port": 0,
  "redir-port": 0,
  "tproxy-port": 0,
  "mixed-port": 0,
  "mode": "rule",
  "log-level": "info",
  "ipv6": true,
  "allow-lan": false,
  "external-controller": "127.0.0.1:9090",
  "external-ui": "/usr/share/tachyon-core/ui",
  "external-ui-download-url": null
}
```

#### `PATCH /configs`

Принимает JSON с полями `mode` и/или `log-level` (требуется хотя бы одно поле). Возвращает `204 No Content`.

| Поле | Допустимые значения | Описание |
|---|---|---|
| `mode` | `rule`, `global`, `direct` (пустая строка сбрасывает в `rule`) | Переключает Clash-режим (сохраняется в `cache.db`, если он включён). |
| `log-level` | `trace`, `debug`, `info`, `warn`, `warning`, `error`, `fatal` | Меняет уровень логирования на лету и вновь включает отключённый логгер. |
| `ttl_sec` | Целое число (ограничивается `5..=300`) | Необязательный срок действия нового `log-level` в секундах, после которого восстанавливается предыдущий уровень. |

```bash
curl -X PATCH http://127.0.0.1:9090/configs \
  -H "Authorization: Bearer mysecret" \
  -H "Content-Type: application/json" \
  -d '{"mode":"rule","log-level":"debug","ttl_sec":60}'
```

#### `PUT /configs`

Выполняет горячую перезагрузку конфигурации на месте (`reload_in_place`) без остановки входящих слушателей и обрыва активных соединений.

| Поле тела | Описание |
|---|---|
| `path` | Путь к JSON-файлу конфигурации на диске (до `16 MiB`). |
| `payload` | Текст JSON-конфигурации строкой (имеет приоритет над `path`; тело запроса до `1 MiB`). |

Перед применением выполняется полная валидация `check_str`. При успехе возвращается `204 No Content`. Если конфигурация невалидна или затронуты секции, требующие перезапуска слушателей (`inbounds`, `clash_api`, `cache_file`, `ntp`, `network_namespaces`), возвращается `400 Bad Request` с описанием причины в `{"message": "..."}`.

```bash
curl -X PUT http://127.0.0.1:9090/configs \
  -H "Authorization: Bearer mysecret" \
  -H "Content-Type: application/json" \
  -d '{"path":"/etc/tachyon-core/config.json"}'
```

### `GET /proxies`, `GET /proxies/{name}`, `PUT /proxies/{name}`

- `GET /proxies` возвращает JSON-объект `{"proxies": {...}}` (`Content-Type: text/plain; charset=utf-8` для совместимости с клиентами Clash). Включает синтетическую запись `GLOBAL` (типа `Fallback`, содержащую все непрямые и неблокирующие аутбаунды) и запись для каждого аутбаунда.
- `GET /proxies/{name}` возвращает карточку одного аутбаунда (`404`, если тег не найден). Для групп `Selector` и `URLTest` добавляются поля `now`, `all`; для `URLTest` дополнительно выводятся `mode` и `telemetry`.

```json
{
  "type": "URLTest",
  "name": "auto",
  "udp": true,
  "history": [
    {
      "time": "2026-11-21T15:30:01.123456Z",
      "delay": 42
    }
  ],
  "now": "de-vless",
  "all": ["de-vless", "nl-hy2"],
  "mode": "urltest",
  "telemetry": {}
}
```

- `PUT /proxies/{name}` переключает активного участника группы `Selector`:

```bash
curl -X PUT http://127.0.0.1:9090/proxies/proxy \
  -H "Authorization: Bearer mysecret" \
  -H "Content-Type: application/json" \
  -d '{"name":"de-vless"}'
```

Возвращает `204 No Content`, либо `400 Bad Request` (`"Must be a Selector"` / `"Selector update error: not found"`).

### `GET /proxies/{name}/delay` и `GET /group/{name}/delay`

Измеряет задержку через HTTP `HEAD`-запрос (для `FPTN` используется встроенный зонд протокола).

| Query-параметр | Обязательный | По умолчанию | Описание |
|---|---|---|---|
| `timeout` | Да | — | Таймаут пробы в миллисекундах (целое `i16`; значения `<= 0` возвращают `504`). |
| `url` | Нет | `https://www.gstatic.com/generate_204` | Целевой HTTP/HTTPS URL для проверки. |

Поведение:
- Для одиночного аутбаунда возвращает `{"delay": 45}`.
- Для группы `Selector` или `URLTest` параллельно проверяет все конечные узлы группы (до `32` одновременных проб), обновляет историю задержек и выбор `URLTest`, и возвращает карту задержек по тегам плюс итоговое поле `"delay"`.
- При таймауте — `504 Gateway Timeout`, при ошибке подключения/TLS — `503 Service Unavailable` с полями `message` и `reason`.

```bash
curl -H "Authorization: Bearer mysecret" \
  "http://127.0.0.1:9090/proxies/de-vless/delay?timeout=5000&url=https://www.gstatic.com/generate_204"
```

### `GET /proxies/{name}/exit`

Определяет внешний IPv4/IPv6-адрес и двухбуквенный код страны (`loc`) выхода через указанный аутбаунд (группы `Selector`/`URLTest` рекурсивно разрешаются до активного конечного узла). Всегда выставляет `Cache-Control: no-store`.

| Query-параметр | Обязательный | Описание |
|---|---|---|
| `timeout` | Да | Таймаут в миллисекундах (`> 0`). |

```bash
curl -H "Authorization: Bearer mysecret" \
  "http://127.0.0.1:9090/proxies/proxy/exit?timeout=5000"
```

```json
{
  "outbound": "de-vless",
  "ipv4": {
    "address": "203.0.113.10",
    "country": "DE"
  },
  "ipv6": {
    "error": "Timeout"
  }
}
```

Если оба семейства адресов завершились ошибкой, возвращается `504` (при таймауте IPv4) или `503` (с текстом ошибки).

### `GET /proxies/{name}/link`

Экспортирует share-link URI для указанного аутбаунда.

| Query-параметр / заголовок | По умолчанию | Описание |
|---|---|---|
| `resolve` | `true` | Разрешать группы `Selector`/`URLTest` в активный узел (`resolve=false` / `0` / `no` отключает). |
| `format=raw` / `raw=1` / `Accept: text/plain` | JSON | Вернуть чистую строку URI с `Content-Type: text/plain; charset=utf-8`. |

JSON-ответ:

```json
{
  "name": "de-vless",
  "type": "vless",
  "link": "vless://..."
}
```

### Провайдеры подписок (`/providers/proxies*`)

- `GET /providers/proxies` — возвращает `{"providers": {"<tag>": {...}}}`. Каждый провайдер содержит `name`, `type: "Proxy"`, `vehicleType`, `proxies` (массив объектов в формате `/proxies/{name}`), `updatedAt` и опциональный `subscriptionInfo` (`upload`, `download`, `total`, `expire`).
- `GET /providers/proxies/{name}` — возвращает карточку одного провайдера (`404`, если не найден).
- `PUT /providers/proxies/{name}` — принудительно загружает удалённую подписку и применяет обновление на лету (`204 No Content` при успехе, `404` при отсутствии провайдера или сбое).
- `GET /providers/proxies/{name}/links` (псевдоним `/providers/proxies/{name}/link`) — экспортирует все узлы провайдера. Поддерживает `?format=raw` / `?raw=1` / `Accept: text/plain`, иначе возвращает JSON:
  ```json
  {
    "name": "my-sub",
    "count": 3,
    "links": ["vless://...", "hy2://..."],
    "base64": "dmxlc3M6Ly8uLi4="
  }
  ```

### Провайдеры наборов правил (`/providers/rules*`)

- `GET /providers/rules` — возвращает карту всех подключённых `rule_set` и общую монотонно растущую ревизию:
  ```json
  {
    "providers": {
      "geo-domains": {
        "type": "Rule",
        "vehicleType": "HTTP",
        "name": "geo-domains",
        "format": "binary",
        "updatedAt": "2026-11-21T15:00:00Z",
        "revision": 2,
        "ip_cidr": []
      }
    },
    "revision": 2
  }
  ```
- `PUT /providers/rules` — обновляет все удалённые наборы правил (`204 No Content` или `503 Service Unavailable`).
- `GET /providers/rules/{name}` — сведения об одном наборе правил (`404`, если не найден).
- `PUT /providers/rules/{name}` — принудительное обновление одного набора правил (`204`, `404` или `503`).
- `GET /providers/rules/events?since=<revision>` — long-poll ожидание обновления наборов правил. Если текущая ревизия уже отличается от `since`, отвечает немедленно `{"revision": N}`; иначе удерживает запрос до следующего обновления и возвращает `{"name": "<tag>", "revision": N}`.

### `GET /rules`

Возвращает список активных правил маршрутизации:

```json
{
  "rules": [
    {
      "type": "RuleSet",
      "payload": "rule_set=geo-direct",
      "proxy": "direct"
    }
  ]
}
```

### Потоковые эндпоинты: `/connections`, `/traffic`, `/logs`

Все три маршрута поддерживают стандартное обновление до WebSocket (`Upgrade: websocket`, RFC 6455). Без заголовка `Upgrade`:
- `GET /connections` возвращает разовый JSON-снимок;
- `GET /traffic` и `GET /logs` возвращают потоковый HTTP-ответ (`Transfer-Encoding: chunked`, один JSON-объект на строку).

#### `GET|DELETE /connections` и `GET|DELETE /connections/{id}`

- `GET /connections` (для WebSocket доступен параметр `?interval=<ms>`, по умолчанию `1000`, минимум `1`):
  ```json
  {
    "downloadTotal": 104857600,
    "uploadTotal": 12582912,
    "connections": [
      {
        "id": "42",
        "metadata": {
          "network": "tcp",
          "type": "tproxy/tproxy-in",
          "sourceIP": "192.168.1.50",
          "sourcePort": "54321",
          "destinationIP": "93.184.216.34",
          "destinationPort": "443",
          "host": "example.com",
          "dnsMode": "normal",
          "processPath": ""
        },
        "upload": 4096,
        "download": 65536,
        "start": "2026-11-21T15:25:10Z",
        "chains": ["proxy", "de-vless"],
        "rule": "domain_suffix=example.com => proxy",
        "rulePayload": "example.com"
      }
    ],
    "memory": 18874368,
    "reverseDns": {}
  }
  ```
- `DELETE /connections` — закрывает все активные соединения (`204 No Content`).
- `GET /connections/{id}` — карточка одного соединения по числовому `id` (`200` или `404`).
- `DELETE /connections/{id}` — разрывает указанное соединение (`204` или `404`).

#### `GET /traffic`

Каждую секунду отправляет дельту трафика в байтах за последнюю секунду:

```json
{"up": 14336, "down": 1048576}
```

#### `GET /logs`

Query-параметр `?level=` принимает `trace`, `debug`, `info`, `warn`/`warning`, `error`/`fatal` (по умолчанию `trace`; при невалидном значении возвращается `400 Bad Request` до выполнения WebSocket handshake). Сначала отправляются буферизованные записи из кольцевого буфера, затем новые сообщения в реальном времени:

```json
{"type": "info", "payload": "clash-api: restful api listening at 127.0.0.1:9090"}
```

### Tailscale (`/tailscale*`)

- `GET /tailscale` — возвращает `{"endpoints": [...]}` со статусом каждого настроенного Tailscale-эндпоинта.
- `GET /tailscale/{tag}/ping?address=<ip>&timeout=<ms>` — пингует узел Tailscale (`200 {"latency": ...}`, `400`, `404`, `503`, `504`; `Cache-Control: no-store`).

### `GET /metrics` (Prometheus)

Возвращает метрики в формате `text/plain; version=0.0.4; charset=utf-8`:

| Метрика | Тип | Описание |
|---|---|---|
| `tachyon_connections_active` | gauge | Текущее число активных соединений |
| `tachyon_traffic_upload_bytes_total` | counter | Суммарный исходящий трафик (байты) |
| `tachyon_traffic_download_bytes_total` | counter | Суммарный входящий трафик (байты) |
| `tachyon_memory_rss_bytes` | gauge | Резидентная память процесса (RSS, байты) |
| `tachyon_outbound_connections_active{outbound}` | gauge | Активные соединения по тегу аутбаунда |
| `tachyon_outbound_traffic_upload_bytes{outbound}` | gauge | Исходящие байты активных соединений по аутбаунду |
| `tachyon_outbound_traffic_download_bytes{outbound}` | gauge | Входящие байты активных соединений по аутбаунду |
| `tachyon_process_open_fds` / `tachyon_process_max_fds` | gauge | Открытые файловые дескрипторы и мягкий лимит |
| `tachyon_udp_nat_active` / `tachyon_udp_nat_evictions_total` | gauge / counter | Активные сессии UDP NAT и вытеснения по ёмкости |
| `tachyon_fakeip_v4_used` / `tachyon_fakeip_v4_capacity` / `tachyon_fakeip_evictions_total` | gauge / counter | Состояние пула FakeIP IPv4 |
| `tachyon_dns_cache_hits_total` / `tachyon_dns_cache_misses_total` | counter | Попадания и промахи DNS-кэша |
| `tachyon_inbound_cap_drops_total` | counter | Отклонённые соединения при достижении лимита инбаунда |
| `tachyon_reloads_total` | counter | Общее число загрузок/перезагрузок конфигурации |
| `tachyon_pool_purges_total` | counter | Число очисток буферных пулов при давлении памяти |
| `tachyon_outbound_dial_errors_total{outbound,class}` | counter | Ошибки установки соединений по тегу и классу ошибки |
| `tachyon_dns_upstream_errors_total{server}` | counter | Ошибки и `SERVFAIL` по upstream DNS-серверам |

---

## Нативные эндпоинты `/tachyon/*`

Все нативные маршруты принимают завершающий `/` опционально (например, `/tachyon/health` и `/tachyon/health/` эквивалентны) и защищены общей Bearer-авторизацией.

### Сводная таблица `/tachyon/*`

| Метод | Путь | Назначение |
|---|---|---|
| `GET` | `/tachyon/config-state` | PID, ревизия и SHA-256 применённой конфигурации |
| `POST` | `/tachyon/route-recheck` | Перепроверка маршрутов всех активных соединений |
| `POST` | `/tachyon/delay-batch` | Пакетное измерение задержки до 64 узлов одновременно |
| `GET`, `POST` | `/tachyon/stats` | Счётчики трафика по инбаундам, пользователям и IP (с опцией `?reset=1`) |
| `POST` | `/tachyon/kick` | Принудительное закрытие соединений по фильтру |
| `GET` | `/tachyon/neighbors` | Обнаруженные LAN-устройства (ARP/NDP + DHCP-лизы) |
| `GET` | `/tachyon/devices` | Учёт трафика по LAN-устройствам, скорости и 60-секундная история |
| `POST` | `/tachyon/devices/limit` | Ограничение скорости upload/download для конкретного LAN IP |
| `POST` | `/tachyon/wol` | Отправка Wake-on-LAN Magic Packet в локальную сеть |
| `POST` | `/tachyon/route-check` | Трассировка правила маршрутизации + двойная проверка доступности |
| `POST` | `/tachyon/connection-test` | 8-этапная диагностика соединения (псевдоним `POST /connections/test`) |
| `POST` | `/tachyon/warp/register` | Авторегистрация учётных данных Cloudflare WARP / MASQUE |
| `POST` | `/tachyon/dns-check` | Сравнение DNS движка с прямым UDP/53 и диагностика перехвата |
| `GET`, `POST` | `/tachyon/failover` | Статус и возврат primary/backup групп (`POST /tachyon/failover/restore`) |
| `GET` | `/tachyon/memory` | RSS, VM, доступная ОЗУ системы, уровень давления памяти и размеры кэшей |
| `POST` | `/tachyon/memory/trim` | Принудительная очистка кэшей и пулов буферов |
| `GET`, `DELETE` | `/tachyon/flight` | Кольцевой журнал последних 128 завершённых/ошибочных соединений |
| `GET`, `POST` | `/tachyon/leak` | Аудит маршрутов IPv4, IPv6, WebRTC STUN и DNS на утечки в `direct` |
| `GET` | `/tachyon/health` | Консолидированный срез здоровья и телеметрии ядра |
| `GET` | `/tachyon/anomalies` | Хосты с аномально высокой долей ошибок за последние 5 минут |
| `POST` | `/tachyon/dns/flush` | Сброс DNS-кэша и/или кэша адресов upstream-серверов |
| `POST` | `/tachyon/outbound/reset` | Сброс сокетов/сессий аутбаунда (rebind WireGuard, re-probe URLTest) |
| `GET` | `/tachyon/logs/recent` | Последние структурированные записи лога без потокового подключения |

---

### `GET /tachyon/config-state`

Позволяет внешнему контроллеру проверить, применилась ли конфигурация после `SIGHUP` или `PUT /configs`.

```bash
curl -H "Authorization: Bearer mysecret" http://127.0.0.1:9090/tachyon/config-state
```

```json
{
  "pid": 1482,
  "revision": 3,
  "digest": "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4",
  "ready": true
}
```

### `POST /tachyon/route-recheck`

Повторно прогоняет все активные маршрутизированные соединения через текущую таблицу правил (волнами по 16 задач) и закрывает соединения, у которых сменился целевой аутбаунд, правило стало блокирующим или деградировало в `final`. Если во время обхода произошла новая перезагрузка конфигурации, результаты отбрасываются (`"stale": true`) и соединения не закрываются.

```bash
curl -X POST -H "Authorization: Bearer mysecret" http://127.0.0.1:9090/tachyon/route-recheck
```

```json
{
  "checked": 124,
  "closed": 5,
  "failed": 0,
  "stale": false
}
```

### `POST /tachyon/delay-batch`

Проверяет задержку списка аутбаундов параллельно (до `64` одновременных проб). Лимит тела запроса — `512 KiB`.

| Поле тела | Обязательный | По умолчанию | Описание |
|---|---|---|---|
| `names` | Да | — | Массив тегов аутбаундов или групп. |
| `url` | Нет | `https://www.gstatic.com/generate_204` | Целевой HTTP/HTTPS URL. |
| `timeout` | Нет | `5000` | Таймаут в мс (ограничивается `100..=30000`). |

```bash
curl -X POST http://127.0.0.1:9090/tachyon/delay-batch \
  -H "Authorization: Bearer mysecret" \
  -H "Content-Type: application/json" \
  -d '{"names":["de-vless","nl-hy2","auto"],"timeout":4000}'
```

```json
{
  "results": {
    "de-vless": { "delay": 38 },
    "nl-hy2": { "message": "Timeout" },
    "auto": { "delay": 38 }
  }
}
```

### `GET|POST /tachyon/stats`

Возвращает статистику трафика в разрезе инбаундов и аутентифицированных пользователей (полезно для серверного учёта и панелей). Query-параметр `?reset=1` (или `true`/`yes`) атомарно обнуляет накопленные счётчики инбаундов и пользователей, возвращая дельту с предыдущего сброса.

```bash
curl -H "Authorization: Bearer mysecret" "http://127.0.0.1:9090/tachyon/stats?reset=1"
```

```json
{
  "total": { "up": 5242880, "down": 83886080, "active": 14 },
  "inbounds": {
    "vless-in": { "up": 5242880, "down": 83886080, "active": 14 }
  },
  "users": {
    "alice": { "up": 1048576, "down": 20971520, "active": 4, "ips": ["198.51.100.7"] }
  },
  "inbound_users": [
    {
      "inbound": "vless-in",
      "user": "alice",
      "up": 1048576,
      "down": 20971520,
      "active": 4,
      "ips": ["198.51.100.7"]
    }
  ]
}
```

### `POST /tachyon/kick`

Принудительно закрывает активные соединения, соответствующие переданному фильтру (необходимо указать хотя бы одно поле).

| Поле тела | Тип | Описание |
|---|---|---|
| `user` | `string` | Имя аутентифицированного пользователя. |
| `inbound` | `string` | Тег инбаунда. |
| `outbound` | `string` | Тег аутбаунда. |
| `only_stalled_ms` | `u64` | Закрывать только соединения без активности дольше указанного числа миллисекунд. |

```bash
curl -X POST http://127.0.0.1:9090/tachyon/kick \
  -H "Authorization: Bearer mysecret" \
  -H "Content-Type: application/json" \
  -d '{"user":"alice","inbound":"vless-in"}'
```

Ответ: `{"closed": 4}`.

### `GET /tachyon/neighbors`

Возвращает список LAN-устройств, обнаруженных из таблицы соседей ядра (`/proc/net/arp` и RTNETLINK `RTM_GETNEIGH` / подписки `RTM_NEWNEIGH`) и файлов DHCP-лизов (`/tmp/dhcp.leases`, `/tmp/hosts/odhcpd`, ISC DHCP, Kea), объединённый со счётчиками трафика.

```bash
curl -H "Authorization: Bearer mysecret" http://127.0.0.1:9090/tachyon/neighbors
```

```json
{
  "neighbors": [
    {
      "mac": "aa:bb:cc:11:22:33",
      "ips": ["192.168.1.50"],
      "hostname": "workstation",
      "active_connections": 6,
      "upload": 1048576,
      "download": 16777216,
      "proxied_upload": 524288,
      "proxied_download": 12582912,
      "direct_upload": 524288,
      "direct_download": 4194304,
      "upload_bps": 8192,
      "download_bps": 262144,
      "last_seen_ago_ms": 120
    }
  ]
}
```

### `GET /tachyon/devices` и `POST /tachyon/devices/limit`

#### `GET /tachyon/devices`

Объединяет таблицу LAN-соседей со всеми активными и сохранёнными в `cache.db` IP-бакетами трафика (до `512` устройств). Query-параметр `?history=0` (или `false`/`no`) исключает 60-секундный массив `[upload_bytes, download_bytes]` из ответа.

```json
{
  "devices": [
    {
      "mac": "aa:bb:cc:11:22:33",
      "ips": ["192.168.1.50"],
      "hostname": "workstation",
      "active_connections": 6,
      "upload": 1048576,
      "download": 16777216,
      "proxied_upload": 524288,
      "proxied_download": 12582912,
      "direct_upload": 524288,
      "direct_download": 4194304,
      "upload_bps": 8192,
      "download_bps": 262144,
      "limit_up_bps": 0,
      "limit_down_bps": 2500000,
      "last_seen_ago_ms": 120,
      "history": [[0, 0], [8192, 262144]]
    }
  ],
  "summary": {
    "total_devices": 1,
    "active_connections": 6,
    "upload": 1048576,
    "download": 16777216,
    "proxied_upload": 524288,
    "proxied_download": 12582912,
    "direct_upload": 524288,
    "direct_download": 4194304,
    "upload_bps": 8192,
    "download_bps": 262144
  }
}
```

#### `POST /tachyon/devices/limit`

Задаёт ограничение скорости для конкретного IP-адреса в локальной сети (значение `0` снимает ограничение). Лимиты сохраняются в `cache.db` (если кэш включён).

| Поле тела | Описание |
|---|---|
| `ip` | Обязательный IPv4- или IPv6-адрес устройства. |
| `limit_up_bps` / `limit_down_bps` | Лимит в байтах/с (`u64`). |
| `upload_mbps` / `download_mbps` | Альтернатива в Mbit/s (`f64`, пересчитывается как `mbps * 125_000` байт/с, если не заданы `*_bps`). |

```bash
curl -X POST http://127.0.0.1:9090/tachyon/devices/limit \
  -H "Authorization: Bearer mysecret" \
  -H "Content-Type: application/json" \
  -d '{"ip":"192.168.1.50","upload_mbps":10,"download_mbps":20}'
```

```json
{
  "ok": true,
  "ip": "192.168.1.50",
  "limit_up_bps": 1250000,
  "limit_down_bps": 2500000
}
```

### `POST /tachyon/wol`

Отправляет Wake-on-LAN Magic Packet (`6 x 0xFF` + `16 x MAC` + опциональный SecureOn-пароль, по 3 UDP-пакета на каждую целевую комбинацию broadcast/порт).

| Поле тела | Обязательный | По умолчанию | Описание |
|---|---|---|---|
| `mac` | Да | — | MAC-адрес устройства (`aa:bb:cc:dd:ee:ff` или с `-`). |
| `interface` | Нет | Все не-loopback | Имя интерфейса (например, `br-lan`); на Linux привязывает сокет через `SO_BINDTODEVICE`. |
| `address` (или `broadcast`) | Нет | Широковещательные адреса подсетей + `255.255.255.255` | Целевой IPv4 broadcast-адрес. |
| `port` | Нет | Порты `9` и `7` | Целевой UDP-порт (`1..=65535`). |
| `password` | Нет | Нет | Пароль SecureOn: 4 байта (IPv4 или 8 hex-символов) либо 6 байт (MAC или 12 hex-символов). |

```bash
curl -X POST http://127.0.0.1:9090/tachyon/wol \
  -H "Authorization: Bearer mysecret" \
  -H "Content-Type: application/json" \
  -d '{"mac":"aa:bb:cc:11:22:33","interface":"br-lan","port":9}'
```

```json
{
  "ok": true,
  "mac": "aa:bb:cc:11:22:33",
  "sent_packets": 6,
  "targets": ["192.168.1.255:9", "255.255.255.255:9"]
}
```

### `POST /tachyon/route-check`

Трассирует цель через таблицу маршрутизации и (по умолчанию для TCP) параллельно проверяет доступность через выбранный аутбаунд и альтернативный путь (`direct` либо `proxy`), формируя рекомендацию `probe.advice`.

| Поле тела | Обязательный | По умолчанию | Описание |
|---|---|---|---|
| `target` / `url` / `domain` / `host` | Да (любое из 4) | — | URL (`https://...`), `host:port`, домен или IP. |
| `port` | Нет | Из URL или `443` | Целевой порт (`1..=65535`). |
| `network` | Нет | `tcp` | `tcp` или `udp`. |
| `source_ip`, `source_mac`, `source_hostname` | Нет | — | Симуляция атрибутов клиента LAN для правил `source_*`. |
| `inbound`, `protocol` | Нет | — | Симуляция тега инбаунда и распознанного протокола. |
| `probe` | Нет | `true` для TCP | Запускать ли параллельную HTTP-пробу. |
| `timeout` | Нет | `5000` | Таймаут пробы в мс (`200..=15000`). |

Возможные значения `probe.advice`: `ok`, `ok_also_direct`, `route_via_proxy`, `route_direct`, `target_unreachable`, `blocked_by_rule`.

```bash
curl -X POST http://127.0.0.1:9090/tachyon/route-check \
  -H "Authorization: Bearer mysecret" \
  -H "Content-Type: application/json" \
  -d '{"target":"https://example.com","source_ip":"192.168.1.50","probe":true}'
```

```json
{
  "target": "example.com:443",
  "host": "example.com",
  "port": 443,
  "network": "tcp",
  "source": { "ip": "192.168.1.50", "mac": null, "hostname": null },
  "action": "route",
  "matched_rule": "rule_set=proxy-list => proxy",
  "rule_evidence": "proxy-list",
  "outbound": "proxy",
  "effective_outbound": "de-vless",
  "outbound_type": "VLESS",
  "is_direct": false,
  "fakeip": false,
  "origin_destination": null,
  "fakeip_domain": null,
  "destination_addresses": ["93.184.216.34"],
  "probe": {
    "routed": { "outbound": "de-vless", "ok": true, "delay": 47 },
    "direct": { "outbound": "direct", "ok": true, "delay": 18 },
    "advice": "ok_also_direct"
  }
}
```

### `POST /tachyon/connection-test` (псевдоним `POST /connections/test`)

Выполняет пошаговую диагностику соединения по 8 этапам: `dns -> rule -> outbound -> detour -> resolve -> tcp -> tls -> http` — с точным кодом отказа, длительностью и деталями на каждом шаге.

| Поле тела | Обязательный | По умолчанию | Описание |
|---|---|---|---|
| `url` / `target` / `host` / `domain` | Да (любое из 4) | — | Проверяемый ресурс. |
| `port`, `tls`, `path` | Нет | Из URL (`443`/`true`/`/` либо `80`/`false`) | Явное переопределение порта, TLS и пути. |
| `method` | Нет | `HEAD` | HTTP-метод (только ASCII-буквы, до 16 символов). |
| `skip_http` | Нет | `false` | Остановиться после TCP/TLS без HTTP-запроса. |
| `outbound` | Нет | Из правил | Принудительно тестировать конкретный аутбаунд в обход правил. |
| `inbound`, `protocol`, `source_ip`, `source_mac`, `source_hostname` | Нет | — | Контекст для этапа `rule`. |
| `timeout_ms` (или `timeout`) | Нет | `5000` | Общий бюджет времени в мс (`100..=30000`). |

```bash
curl -X POST http://127.0.0.1:9090/tachyon/connection-test \
  -H "Authorization: Bearer mysecret" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com","timeout_ms":6000}'
```

Ответ содержит верхнеуровневые поля `ok`, `target`, `host`, `port`, `scheme`, `network`, `failed_stage`, `code`, `summary`, `duration_ms`, `timeout_ms`, объект каждого этапа по имени (`dns`, `rule`, ..., `http`) и упорядоченный массив `stages` (`{stage, status, ok, code, duration_ms, detail}`).

### `POST /tachyon/warp/register`

Генерирует свежие ключи Curve25519 (WireGuard) и P-256 (MASQUE), регистрирует устройство в API Cloudflare WARP и возвращает готовые JSON-фрагменты аутбаундов `wireguard` (с `reserved`, параметрами `jc`/`jmin`/`jmax` и ротацией портов `server_ports`) и `masque`.

| Поле тела | По умолчанию | Описание |
|---|---|---|
| `tag` | `warp-out` | Тег для WireGuard (MASQUE получит `<tag>-masque`). |
| `device_model` (или `model`) | `Pixel 9 Pro` | Модель устройства для регистрации. |
| `locale` | `en_US` | Локаль устройства. |
| `offline` | `false` | Не обращаться к сети, сгенерировать локальные ключи и шаблон. |
| `fallback_offline` | `false` | Вернуть офлайн-шаблон при сетевой ошибке вместо `502`. |
| `api_url` | `https://api.cloudflareclient.com/v0a5641/reg` | Пользовательский URL регистрации. |

Ответ: `{"account": {...}, "wireguard_outbound": {...}, "masque_outbound": {...}}`.

### `POST /tachyon/dns-check`

Параллельно разрешает домен через встроенный DNS-движок и прямым UDP-запросом на порт 53, выявляя подмену на частные/bogon-адреса или блокировку UDP/53.

| Поле тела | По умолчанию | Описание |
|---|---|---|
| `domain` (или `host`) | `example.com` | Проверяемый домен. |
| `udp_server` (или `server`) | `1.1.1.1:53` | Прямой UDP DNS-сервер (порт 53 подставляется по умолчанию). |
| `timeout` | `2500` | Таймаут в мс (`200..=10000`). |

```bash
curl -X POST http://127.0.0.1:9090/tachyon/dns-check \
  -H "Authorization: Bearer mysecret" \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com","udp_server":"1.1.1.1:53"}'
```

Возможные пары `(status, advice)`:
- `("ok", "ok")` — оба пути работают корректно;
- `("udp53_intercepted", "enable_encrypted_dns_and_hijack")` — прямой UDP/53 вернул bogon/sinkhole-адрес;
- `("udp53_blocked_engine_ok", "hijack_lan_udp53_to_engine")` — прямой UDP/53 недоступен, но движок разрешает домен;
- `("engine_dns_failed", "check_upstream_dns_servers")` — сбой настроенного DNS-движка при рабочем UDP/53;
- `("dns_unreachable", "check_wan_and_dns_servers")` — оба пути недоступны.

### `GET|POST /tachyon/failover` и `POST /tachyon/failover/restore`

- `GET /tachyon/failover` — возвращает статус всех групп `URLTest` и `Selector`: `any_on_backup` и массив `groups` (`tag`, `type`, `mode`, `primary`, `current`, `on_backup`, `primary_healthy`, `members`).
- `POST /tachyon/failover` (или `POST /tachyon/failover/restore`) — возвращает выбранную группу (или все группы) на первичный узел `primary`. Опциональное тело: `{"group": "auto", "probe": true}` (также принимается ключ `tag`). Возвращает `restored_groups`, `any_on_backup` и обновлённый список `groups`.

### `GET /tachyon/memory` и `POST /tachyon/memory/trim`

- `GET /tachyon/memory` — текущий срез памяти и кэшей:
  ```json
  {
    "rss_bytes": 16777216,
    "vm_bytes": 134217728,
    "system_available_bytes": 104857600,
    "total_ram_mb": 256,
    "pressure_level": "normal",
    "under_pressure": false,
    "connections": {
      "active_connections": 12,
      "device_buckets": 4,
      "inbound_buckets": 2,
      "user_buckets": 0
    },
    "dns": {
      "cache_entries": 180,
      "reverse_entries": 64,
      "fakeip_entries": 0
    }
  }
  ```
  Значения `pressure_level`: `normal`, `elevated`, `critical`.
- `POST /tachyon/memory/trim` — вытесняет неактивные бакеты устройств, усекает кэши DNS и очищает глобальные пулы буферов. Возвращает `{"trimmed": true, "evicted": {...}, "remaining": {...}, "rss_bytes": ..., "pressure_level": ..., "under_pressure": ...}`.

### `GET|DELETE /tachyon/flight`

Кольцевой журнал последних `128` закрытых или завершившихся ошибкой соединений (flight recorder).

- `GET /tachyon/flight` поддерживает query-параметры:
  - `only_failed=1|true|yes` — только ошибочные соединения;
  - `outbound=<tag>` — фильтр по тегу аутбаунда;
  - `limit=<1..128>` — максимум возвращаемых записей (по умолчанию `128`).
  Каждая запись содержит `id`, `timestamp_ms`, `network`, `inbound`, `source`, `host`, `destination`, `outbound`, `rule`, `upload`, `download`, `duration_ms`, `status`, `error_kind`, `error_detail`, `dial_ms`, `ttfb_ms`.
- `DELETE /tachyon/flight` — очищает журнал и возвращает `{"cleared": N}`.

### `GET|POST /tachyon/leak`

Проводит трассировку контрольных направлений (`1.1.1.1:443/tcp`, `[2606:4700:4700::1111]:443/tcp`, `stun.l.google.com:19302/udp`) и проверяет активность DNS-движка. Если IPv4 идёт через прокси, а IPv6 или WebRTC STUN попадают в `direct`, выставляется соответствующий флаг `leak_risk: true`.

Возможные значения `status`: `ok`, `ipv6_direct_leak`, `webrtc_udp_direct_leak`, `dns_engine_disabled`.

### `GET /tachyon/health`

Единый срез состояния для систем мониторинга и панелей управления:
- `uptime_secs`, `last_reload_unix`, `last_reload_mode`, `reload_count`, `reload_in_place_total`, `reload_cold_total`;
- `config_state` (как в `/tachyon/config-state`);
- `memory` (`rss_bytes`, `vm_bytes`, `system_available_bytes`, `total_ram_mb`, `pressure_level`, `under_pressure`, `pool_purges_total`);
- `fds` (`open`, `soft_limit`, `usage_pct`);
- `connections` (`active`, `inbound_cap_drops`, `upload_total`, `download_total`);
- `udp_nat` (`active`, `evictions_total`);
- `dns` (`cache_entries`, `cache_hits`, `cache_stale_hits`, `cache_misses`, `reverse_entries`, `fakeip`, `servers`);
- `outbounds` (счётчики `dial_ok`, `dial_fail`, `ewma_handshake_ms`, `last_err_class`, `errors_by_class`; для WireGuard дополнительно `wg_up`, `wg_last_handshake_age_secs`, `wg_rx_bytes`, `wg_tx_bytes`; для `Selector`/`URLTest` — `selected`).

### `GET /tachyon/anomalies`

Возвращает до 32 хостов с высокой долей сбоев подключения за скользящее 5-минутное окно (`window_secs`).

| Query-параметр | По умолчанию | Описание |
|---|---|---|
| `min_failures` | `3` (минимум `1`) | Минимальное число ошибок по хосту. |
| `min_rate_pct` | `50` (`1..=100`) | Минимальный процент ошибок от общего числа попыток. |

```json
{
  "window_secs": 300,
  "count": 1,
  "hosts": [
    {
      "host": "unreachable.example",
      "ok_count": 0,
      "fail_count": 5,
      "fail_rate_pct": 100,
      "last_outbound": "de-vless",
      "last_err_class": "timeout",
      "last_seen_unix": 1795275000
    }
  ]
}
```

### `POST /tachyon/dns/flush`

Очищает кэши DNS-подсистемы.

| Поле тела | Значения | По умолчанию | Описание |
|---|---|---|---|
| `scope` | `cache`, `upstream`, `all` | `all` | `cache` — кэш ответов и reverse DNS; `upstream` — кэш разрешённых адресов upstream-серверов; `all` — оба кэша. |

```bash
curl -X POST http://127.0.0.1:9090/tachyon/dns/flush \
  -H "Authorization: Bearer mysecret" \
  -H "Content-Type: application/json" \
  -d '{"scope":"all"}'
```

### `POST /tachyon/outbound/reset`

Сбрасывает состояние указанного аутбаунда без перезагрузки конфигурации: перепривязывает UDP-сокет у WireGuard (`rebound: true`), запускает немедленную пробу у `URLTest` (`probed: true`) и опционально закрывает активные сессии на этом теге.

| Поле тела | Обязательный | По умолчанию | Описание |
|---|---|---|---|
| `tag` | Да | — | Тег сбрасываемого аутбаунда (`404`, если не найден). |
| `close_sessions` | Нет | `true` | Закрывать ли активные соединения, использующие этот тег. |
| `stalled_only_ms` | Нет | `null` | Если указано, закрываются только простаивающие дольше порога сессии. |

```bash
curl -X POST http://127.0.0.1:9090/tachyon/outbound/reset \
  -H "Authorization: Bearer mysecret" \
  -H "Content-Type: application/json" \
  -d '{"tag":"wg-main","close_sessions":true}'
```

```json
{
  "ok": true,
  "tag": "wg-main",
  "rebound": true,
  "probed": false,
  "closed_sessions": 3
}
```

### `GET /tachyon/logs/recent`

Возвращает срез последних записей из кольцевого буфера логов одним JSON-ответом (удобно для периодического опроса из UI или CLI-скриптов).

| Query-параметр | По умолчанию | Описание |
|---|---|---|
| `level` | `warn` | Минимальный уровень (`trace`, `debug`, `info`, `warn`/`warning`, `error`/`fatal`). |
| `limit` | `50` (`1..=256`) | Максимальное число возвращаемых строк (новейшие в конце). |

```bash
curl -H "Authorization: Bearer mysecret" \
  "http://127.0.0.1:9090/tachyon/logs/recent?level=warn&limit=20"
```

```json
{
  "level": "warning",
  "current_level": "info",
  "count": 1,
  "entries": [
    {
      "level": "WARN",
      "message": "inbound tun[tun-in]: IPv6 requires MTU >= 1280 (RFC 8200), clamping 1200 -> 1280"
    }
  ]
}
```
