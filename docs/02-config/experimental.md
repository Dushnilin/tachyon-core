# Секция `experimental`

Секция `experimental` управляет локальным хранилищем состояния (`cache_file`) и HTTP/WebSocket-контроллером управления (`clash_api`).

Валидатор принимает в `experimental` строго два ключа:

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `cache_file` | `object` | — | Параметры локального bbolt-хранилища кэша, FakeIP и состояния переключателей. |
| `clash_api` | `object` | — | Параметры встроенного Clash-совместимого REST и WebSocket API. |

Ключ `v2ray_api` **не поддерживается** и отсутствует в схеме `experimental`: его указание приводит к ошибке валидации `experimental.v2ray_api: unknown field "v2ray_api"`.

---

## `experimental.cache_file`

Постоянное хранилище в формате bbolt, совместимом с sing-box. Сохраняет выбор в группах `selector`, состояние раскрытия групп, текущий `clash_mode`, метаданные удалённых `rule_set`, отображения FakeIP, адаптивное состояние и кэш DNS.

### Поля `experimental.cache_file`

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `enabled` | `bool` | `false` | Включает файловое хранилище. Для активации на диске также требуется непустой `path`. |
| `path` | `string` | `""` | Путь к основному файлу базы (например, `"/etc/tachyon-core/cache.db"` или `"/var/lib/tachyon-core/cache.db"`). Родительские каталоги создаются автоматически. При пустом `path` хранилище не открывается. |
| `cache_id` | `string` | `""` | Идентификатор профиля кэша. Хранится в служебном бакете `_id`. Если задан непустой `cache_id` и он отличается от сохранённого в файле, существующие данные очищаются, а файлы `.volatile` и `.ephemeral` удаляются. |
| `store_fakeip` | `bool` | `false` | Сохраняет таблицу соответствий `FakeIP <-> домен` между перезапусками ядра. |
| `store_rdrc` | `bool` | `false` | Включает сохранение кэша отклонённых DNS-ответов (RDRC) в эфемерном сайдкаре. |
| `rdrc_timeout` | `Duration` | — | Срок хранения записей RDRC (строка `Duration`, например `"7d"`). |
| `store_dns` | `bool` | `false` | Сохраняет записи кэша DNS между перезапусками в эфемерном сайдкаре. |
| `buffer_size` | `int \| string` | `0` | Порог накопленных изменений для немедленного сброса на диск: неотрицательное целое число байт либо строка с единицей `b`, `k`, `kb`, `m`, `mb`, `g`, `gb` (регистронезависимо, например `"64k"` или `"1mb"`). Значение `0` означает сброс только по таймеру `flush_interval`. |
| `flush_interval` | `Duration` | `"60s"` | Максимальный интервал между атомарными сбросами изменённых бакетов на диск. |

### Трёхуровневое разделение файлов (защита flash-памяти)

Для снижения числа перезаписей на встроенных маршрутизаторах (NAND/NOR SPI flash) `tachyon-core` автоматически разделяет бакеты по частоте обновлений и переписывает файлы атомарно только при фактическом изменении значений:

| Файл | Расположение | Содержимое (бакеты) | Назначение |
|---|---|---|---|
| Основной (`<path>`) | Задано в `path` | `_id`, `selected`, `group_expand`, `clash_mode`, `rule_set`, `chain_disabled_lx` | Редко изменяемое постоянное состояние (выбор пользователя, метаданные наборов правил). |
| Сайдкар `.volatile` (`<path>.volatile`) | Рядом с `<path>` | `fakeip`, `fakeip_address`, `fakeip_domain4`, `fakeip_domain6`, `desync_adaptive` | Среднечастотное состояние, которое важно перенести через перезапуск, не переписывая основной `cache.db`. |
| Сайдкар `.ephemeral` | На Linux при `<path>` внутри `/etc/` или `/usr/`: `/tmp/tachyon-core/<имя_файла>.ephemeral`; иначе `<path>.ephemeral` | `dns_cache`, `rdrc2`, `tachyon_devices`, `tachyon_delays` | Высокочастотные кэши и замеры задержек. Вынос в `/tmp/tachyon-core/` (tmpfs в ОЗУ) полностью исключает их запись на flash-накопитель. |
| Файл блокировки `.lock` | На Linux при `<path>` внутри `/etc/` или `/usr/`: `/tmp/tachyon-core/<хеш>-<имя_файла>.lock`; иначе `<path>.lock` | Файловая блокировка ОС | Предотвращает одновременную запись в один `cache.db` двумя разными процессами. |

При удалении основного файла `<path>` устаревшие сайдкары `.volatile` и `.ephemeral` автоматически очищаются при следующем открытии.

---

## `experimental.clash_api`

Встроенный HTTP/WebSocket-сервер, совместимый с панелями управления Clash / Yacd / MetaCubeX. Сервер запускается только при заданном непустом `external_controller`.

### Поля `experimental.clash_api`

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `external_controller` | `string` | `""` (отключён) | Адрес и порт прослушивания API (например, `"127.0.0.1:9090"` или `":9090"`). Если пусто — контроллер не запускается. |
| `external_ui` | `string` | — | Локальный каталог со статическими файлами веб-интерфейса (монтируется по пути `/ui/`). Если каталог отсутствует или пуст, ядро создаёт его и однократно распаковывает архив из `external_ui_download_url`. |
| `external_ui_download_url` | `string` | `"https://github.com/MetaCubeX/Yacd-meta/archive/gh-pages.zip"` | URL ZIP-архива веб-интерфейса для автоматической загрузки при пустом каталоге `external_ui`. |
| `external_ui_download_detour` | `string` | — | Тег исходящего подключения, через которое загружается архив `external_ui_download_url`. |
| `secret` | `string` | `""` | Секретный ключ авторизации запросов (передаётся в заголовке `Authorization: Bearer <secret>` или в query-параметре `?token=<secret>` для WebSocket). Если не задан, аутентификация не требуется. |
| `default_mode` | `string` | `"rule"` | Начальный режим маршрутизации (валидируется как строка). Допустимые режимы во время выполнения: `"rule"`, `"global"`, `"direct"`. Если в `experimental.cache_file` сохранён ранее выбранный режим, при старте восстанавливается он; переключение в реальном времени выполняется через `PATCH /configs {"mode": "..."}`. |
| `access_control_allow_origin` | `Listable<string>` | `["*"]` | Разрешённые источники CORS (`Access-Control-Allow-Origin`). Можно указать одну строку или массив URL. |
| `access_control_allow_private_network` | `bool` | `false` | Добавляет заголовок `Access-Control-Allow-Private-Network: true` для CORS preflight-запросов из браузеров к локальным адресам. |

### Устаревшие поля `experimental.clash_api` (запрещены)

Следующие поля распознаются декодером только для диагностики — передача `true` для булевых флагов или непустой строки для строковых полей завершает `check` и `run` ошибкой `create clash-server: cache_file and related fields in Clash API is deprecated in tachyon-core, use experimental.cache_file instead.`:

- `store_mode`
- `store_selected`
- `store_fakeip`
- `cache_file`
- `cache_id`

Все функции сохранения состояния перенесены в `experimental.cache_file`.

### Поддерживаемые эндпоинты контроллера

При активном `external_controller` обслуживаются:
- `GET /version` — версия ядра (`tachyon-core`).
- `GET /proxies`, `GET /proxies/{name}`, `PUT /proxies/{name}`, `GET /proxies/{name}/delay` — просмотр узлов/групп, переключение `selector` и измерение задержки.
- `GET /logs`, `GET /traffic`, `GET /connections` (HTTP chunked или WebSocket по `Upgrade: websocket`), `DELETE /connections/{id}`.
- `GET /rules`, `GET /configs`, `PATCH /configs` (включая переключение `mode` и `log-level`).
- `GET /ui/` — раздача статических файлов из `external_ui` (максимальный размер одного файла 16 MiB, лимит одновременных API-соединений 128).

---

## Пример конфигурации секции `experimental`

```json
{
  "experimental": {
    "cache_file": {
      "enabled": true,
      "path": "/etc/tachyon-core/cache.db",
      "cache_id": "router-main",
      "store_fakeip": true,
      "store_rdrc": true,
      "rdrc_timeout": "7d",
      "store_dns": true,
      "buffer_size": "64k",
      "flush_interval": "60s"
    },
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "external_ui": "/var/lib/tachyon-core/ui",
      "external_ui_download_url": "https://github.com/MetaCubeX/Yacd-meta/archive/gh-pages.zip",
      "external_ui_download_detour": "proxy-out",
      "secret": "change-me-secret",
      "default_mode": "rule",
      "access_control_allow_origin": [
        "http://127.0.0.1:9090",
        "https://yacd.metacubex.one"
      ],
      "access_control_allow_private_network": true
    }
  }
}
```
