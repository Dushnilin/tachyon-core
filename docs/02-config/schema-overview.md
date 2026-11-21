# Обзор схемы конфигурации `tachyon-core`

Конфигурация `tachyon-core` (v0.6.2) задаётся в формате стандартного JSON (UTF-8, без комментариев и завершающих запятых). Схема совместима с форматом sing-box и проверяется командой `tachyon-core check -c config.json` до запуска ядра.

## Корневые секции конфигурации

Корневой элемент должен быть JSON-объектом. Валидатор допускает строго фиксированный набор ключей верхнего уровня:

| Ключ | Тип | Назначение | Подробная документация |
|---|---|---|---|
| `log` | `object` | Параметры журналирования (`disabled`, `level`, `output`, `timestamp`, `time`). | Раздел [Секция `log`](#секция-log) |
| `dns` | `object` | Настройка DNS-серверов, правил разрешения имён, кэширования и FakeIP. | [dns.md](dns.md) |
| `ntp` | `object` | Периодическая синхронизация времени по SNTP (RFC 5905). | Раздел [Секция `ntp`](#секция-ntp) |
| `certificate` | `object` | Дополнительные корневые сертификаты CA для HTTPS-проверок (например, `urltest`). | Раздел [Секция `certificate`](#секция-certificate) |
| `endpoints` | `array<object>` | Сетевые конечные точки туннельного уровня (`wireguard`, `tailscale`, `openvpn-client`, `openvpn-server`, `openconnect`). | [endpoints.md](endpoints.md) |
| `inbounds` | `array<object>` | Входящие обработчики трафика (`tun`, `tproxy`, `redirect`, `mixed`, `socks`, `http`, `direct`, прокси- и туннельные серверы). | [inbounds/README.md](inbounds/README.md) |
| `outbounds` | `array<object>` | Исходящие подключения и группы балансировки (`direct`, `block`, `selector`, `urltest`, прокси-протоколы и туннели). | [outbounds/README.md](outbounds/README.md) |
| `route` | `object` | Таблица маршрутизации, наборы правил (`rule_set`), параметры по умолчанию и FullCone NAT. | [route-and-rulesets.md](route-and-rulesets.md) |
| `services` | `array<object>` | Зарезервированный ключ верхнего уровня для совместимости схемы (в v0.6.2 принимается валидатором, отдельная подсистема сервисов не запускается). | Раздел [Секция `services`](#секция-services) |
| `experimental` | `object` | Файл кэша (`cache_file`) и REST-контроллер (`clash_api`). | [experimental.md](experimental.md) |
| `http_clients` | `array<object>` | Именованный реестр HTTP-клиентов для загрузок (удалённые `rule_set` и служебные запросы). | Раздел [Секция `http_clients`](#секция-http_clients) |
| `network_namespaces` | `array<object>` | Сетевые пространства имён Linux (`default`, `unshare`), на которые ссылается `netns`. | Раздел [Секция `network_namespaces`](#секция-network_namespaces) |
| `lx` | `object` | Расширенные параметры управления жизненным циклом туннелей и пакетами (`wg`, `masque`, `sniff_guard`, `mtu_align`). | Раздел [Секция `lx`](#секция-lx) |

Дополнительно на этапе предварительного разворачивания (до основной валидации схемы) поддерживаются корневые ключи `subscriptions` и `outbound_providers` (массивы описаний подписок): их узлы и группы автоматически раскрываются в секцию `outbounds`, после чего сами ключи удаляются из результирующего документа.

## Политика строгой валидации

Валидация конфигурации выполняется в два прохода — синтаксический/структурный разбор и семантическая проверка связей:

1. **Отклонение неизвестных полей.** Любой ключ, отсутствующий в списке допустимых полей данной секции или объекта, немедленно вызывает ошибку вида:
   ```text
   <путь>: unknown field "<имя_поля>"
   ```
   Например, передача неподдерживаемой корневой секции `futureSection` или опечатка в имени параметра прерывает `tachyon-core check` и `tachyon-core run` с ненулевым кодом выхода.
2. **Удаление пустых контейнеров (pruning).** В записях `inbounds[]`, `outbounds[]`, `endpoints[]` и вложенных контейнерах (например, `tls`) пустые объекты `{}` и пустые массивы `[]` (включая вложенные пустые структуры) рекурсивно трактуются как отсутствующее поле; значения `null` и скаляры сохраняются.
3. **Запрет устаревших форматов.** Удалённые конструкции не игнорируются молча, а отклоняются с диагностическим сообщением:
   - устаревшие поля входящих подключений (`sniff`, `sniff_override_destination`, `sniff_timeout`, `domain_strategy`, `udp_disable_domain_unmapping` с ненулевыми значениями):
     `legacy inbound fields are deprecated and removed in tachyon-core, use route rule actions instead`;
   - устаревшие адресные поля `tun` (`inet4_address`, `inet6_address`, `inet4_route_address`, `inet6_route_address`, `inet4_route_exclude_address`, `inet6_route_exclude_address`):
     `legacy tun address fields are deprecated and removed in tachyon-core, use \`address\` array instead`;
   - устаревшие DNS-серверы без поля `type`:
     `legacy DNS server formats are deprecated and removed in tachyon-core, use typed DNS server objects instead`;
   - устаревшие поля кэширования внутри `experimental.clash_api` (`store_mode`, `store_selected`, `store_fakeip`, `cache_file`, `cache_id`):
     `create clash-server: cache_file and related fields in Clash API is deprecated in tachyon-core, use experimental.cache_file instead.`;
   - отсутствие `route.default_domain_resolver` или `domain_resolver` на исходящих подключениях при наличии двух и более DNS-серверов:
     `missing \`route.default_domain_resolver\` or \`domain_resolver\` in dial fields is deprecated and removed in tachyon-core, specify \`route.default_domain_resolver\` or outbound \`domain_resolver\``.
4. **Формат сообщений об ошибках.** `tachyon-core` формирует собственные сообщения об ошибках с указанием JSON-пути, ожидаемого типа и фактически полученного значения, без Go-формулировок:
   ```text
   outbounds[0].server_port: expected port/integer (0..65535), got string
   route.rules[2].time_window: expected string or array of strings, got number
   ```
5. **Уникальность тегов.** Повторяющиеся непустые `tag` запрещены в пределах `inbounds`, в общем пространстве имён `outbounds` + `endpoints`, в `dns.servers` и в `http_clients`.
6. **Предупреждения без остановки.** Устаревшие псевдонимы (например, `route.lx_idle_suspend` вместо `lx.wg.idle_suspend`) не прерывают запуск, но выводят предупреждение, если не конфликтуют с каноническим полем. Поля, принимаемые валидатором для совместимости схемы, но не применяемые на текущей платформе (например, `netns` вне Linux), логируются предупреждением при старте.

## Базовые типы данных

В справочнике конфигурации используются следующие составные типы:

### `Duration` (длительность)

Строка в синтаксисе `[-+]?(<число><единица>)+`, допускающая комбинации единиц и дробные значения (например, `"5s"`, `"300ms"`, `"1h30m"`, `"0.5s"`, `"7d"`), либо строка `"0"` / `"+0"` / `"-0"`.

| Единица | Значение |
|---|---|
| `ns` | наносекунды |
| `us`, `µs`, `μs` | микросекунды |
| `ms` | миллисекунды |
| `s` | секунды |
| `m` | минуты |
| `h` | часы |
| `d` | сутки (24 часа) |

Для большинства полей `null` в поле длительности отклоняется как невалидная пустая длительность, если в таблице конкретного поля не указано иное. В некоторых полях (например, `udp_timeout`) дополнительно допускается число секунд.

### Размеры памяти (`MemoryBytes`) и полосы (`NetworkBytes`)

- **`MemoryBytes`** (например, `stream_receive_window`, `connection_receive_window`): неотрицательное целое число байт либо строка `<цифры><единица>` (регистронезависимо): `b`, `k`, `kb`, `mb`, `gb`, `tb`.
- **`experimental.cache_file.buffer_size`**: неотрицательное целое число байт или строка с числом (допускается десятичная точка) и единицей (регистронезависимо): `b`, `k`, `kb`, `m`, `mb`, `g`, `gb`.
- **`NetworkBytes`** (например, скорость канала в QUIC-протоколах): целое число байт/с либо строка `<цифры><единица>` (**с учётом регистра**): `Bps`, `Kbps`, `KBps`, `Mbps`, `MBps`, `Gbps`, `GBps`, `Tbps`, `TBps`, `Pbps`, `PBps`, `Ebps`, `EBps`.

### `Listable<T>`

Поле, принимающее либо одиночное значение типа `T`, либо JSON-массив `array<T>` (или `null` для сброса). Например, `"domain_suffix": "example.com"` и `"domain_suffix": ["example.com", "example.org"]` эквивалентны.

### IP-адреса и CIDR-префиксы (`IP`, `CIDR`)

- **`IP`**: строковое представление IPv4 (`"127.0.0.1"`, `"0.0.0.0"`) или IPv6 (`"::1"`, `"::"`, `"2001:db8::1"`). Для полей `listen` допускаются IPv6-адреса в квадратных скобках (`"[::1]"`).
- **`CIDR`**: строка `<ip>/<prefix_len>` (`"192.168.1.0/24"`, `"10.0.0.1/32"`, `"fc00::/18"`). Длина префикса: `0..32` для IPv4, `0..128` для IPv6 (для пулов FakeIP — не длиннее `/30` для IPv4 и `/125` для IPv6).

### Диапазоны портов (`port_range`)

Строка формата `"<start>:<end>"`, где `<start>` и `<end>` — целые числа в диапазоне `0..65535` либо пустая граница (`":1024"` трактуется как `0..1024`, `"10000:"` — от 10000). В полях ротации портов (`server_ports` для WireGuard и др.) дополнительно допускается дефис (`"20000-30000"`, `"20000:30000"`) и одиночный порт (`"51820"`).

### Метка маршрутизации (`FwMark` / `routing_mark`)

Неотрицательное 32-битное целое (`0..4294967295`) либо строка с числом в десятичной (`"255"`), шестнадцатеричной (`"0xff"`), восьмеричной (`"0o377"`, `"0377"`) или двоичной (`"0b11111111"`) записи. Поддерживается только на Linux и Android.

---

## Секция `log`

Управляет уровнем детализации и направлением вывода логов. Переменные окружения вроде `RUST_LOG` не используются — всё журналирование задаётся исключительно секцией `log`.

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `disabled` | `bool` | `false` | Полностью отключает запись и вывод логов всех уровней. |
| `level` | `string` | `"info"` | Минимальный уровень сообщений: `"trace"`, `"debug"`, `"info"`, `"warn"`, `"error"`, `"fatal"` (внутри ядра `fatal` соответствует `error`; через Clash API также принимается псевдоним `"warning"`). |
| `output` | `string` | `""` (`stderr`) | Приёмник вывода: `""` или `"stderr"` — стандартный поток ошибок; `"stdout"` — стандартный вывод; любой иной путь — запись в файл (в режиме добавления с автоматическим усечением при превышении 2 MiB; при использовании файла вывод в консоль не дублируется). На OpenWrt стандартный путь лога — `/tmp/tachyon-core/tachyon-core.log`. |
| `timestamp` | `bool` | `false` | Добавляет локальную метку времени формата `YYYY-MM-DD HH:MM:SS ` в начало каждой строки. |
| `time` | `any` | — | Принимается валидатором для совместимости схемы; для включения меток времени следует использовать `timestamp`. |

### Пример `log`

```json
{
  "log": {
    "disabled": false,
    "level": "info",
    "output": "/tmp/tachyon-core/tachyon-core.log",
    "timestamp": true
  }
}
```

---

## Секция `ntp`

Встроенный SNTP-клиент (RFC 5905, 48-байтный UDP-запрос). При включении выполняет немедленную синхронизацию при старте, а затем повторяет её с заданным интервалом. Вычисленное смещение передаётся в подсистему проверки срока действия TLS-сертификатов (полезно для маршрутизаторов без батарейных часов RTC).

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `enabled` | `bool` | `false` | Включает службу синхронизации времени. При `false` секция не активируется. |
| `server` | `string` | — | Адрес или доменное имя NTP-сервера (обязательно при `enabled: true`). |
| `server_port` | `uint16` | `123` | UDP-порт NTP-сервера. |
| `interval` | `Duration` | `"30m"` | Интервал периодического опроса. Нулевое значение заменяется на `30m`. Таймаут одного SNTP-запроса фиксирован (5 секунд). |
| `write_to_system` | `bool` | `false` | Пытается применить смещение к системным часам (`CLOCK_REALTIME`, требует `CAP_SYS_TIME` на Unix; не поддерживается на Windows и iOS). При ошибке или `false` смещение используется только внутри TLS-стека `tachyon-core`. |
| *(поля dialer)* | — | — | Схема валидации принимает все поля объекта [dialer](common-objects.md#объект-dialer-параметры-исходящего-подключения) (`detour`, `bind_interface`, `inet4_bind_address`, `inet6_bind_address`, `bind_address_no_port`, `protect_path`, `routing_mark`, `reuse_addr`, `netns`, `connect_timeout`, `tcp_fast_open`, `tcp_multi_path`, `disable_tcp_keep_alive`, `tcp_keep_alive`, `tcp_keep_alive_interval`, `udp_fragment`, `domain_resolver`, `network_strategy`, `network_type`, `fallback_network_type`, `fallback_delay`, `domain_strategy`, `tcp_profile`, `ip_ttl`, `tcp_mss`, `tcp_rcvbuf`, `preconnect`, `warm_pool`, `fragment`, `tcp_fragment`, `finalmask`). |

### Пример `ntp`

```json
{
  "ntp": {
    "enabled": true,
    "server": "time.cloudflare.com",
    "server_port": 123,
    "interval": "30m",
    "write_to_system": false
  }
}
```

---

## Секция `certificate`

Добавляет пользовательские корневые PEM-сертификаты к встроенному хранилищу доверенных центров сертификации Mozilla (используемому, например, при HTTPS-проверках `urltest`, чтобы проверки работали на OpenWrt без системного пакета `ca-certificates`).

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `certificate` | `Listable<string>` | — | Встроенный PEM-блок сертификата(ов) либо массив строк PEM (соединяются через `\n`). |
| `certificate_path` | `Listable<string>` | — | Путь или массив путей к PEM-файлам с корневыми сертификатами. |

### Пример `certificate`

```json
{
  "certificate": {
    "certificate_path": [
      "/etc/ssl/certs/corp-root-ca.pem"
    ]
  }
}
```

---

## Секция `http_clients`

Массив именованных HTTP-клиентов. На теги из этой секции можно ссылаться в `route.default_http_client`, в поле `http_client` удалённых `rule_set` и в параметрах служебных клиентов.

Каждый элемент массива — JSON-объект со строгой проверкой полей в зависимости от версии HTTP (`version`):

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `tag` | `string` | *(обязательно)* | Уникальный непустой идентификатор HTTP-клиента. |
| `engine` | `string` | `""` | Идентификатор движка HTTP-клиента (поле схемы совместимости). |
| `version` | `int` | `0` (авто / HTTP/2) | Версия HTTP: `0` (по умолчанию), `1` (HTTP/1.1), `2` (HTTP/2), `3` (HTTP/3 / QUIC). Другие значения отклоняются с ошибкой `unknown HTTP version`. |
| `disable_version_fallback` | `bool` | `false` | Запрещает автоматический откат версии протокола. |
| `headers` | `object \| array` | `{}` | Дополнительные HTTP-заголовки: объект `{"Header": "Value"}` или массив `[{"key": "...", "value": "..."}]`. |
| `tls` | `object` | — | Параметры клиентского TLS ([common-objects.md](common-objects.md#объект-tls-клиент)). |
| `idle_timeout` | `Duration` | — | Таймаут простоя соединения (доступно при `version` `0`, `2`, `3`). |
| `keep_alive_period` | `Duration` | — | Период отправки ping/keep-alive (доступно при `version` `0`, `2`, `3`). |
| `stream_receive_window` | `MemoryBytes` | — | Размер окна приёма на поток (доступно при `version` `0`, `2`, `3`). |
| `connection_receive_window` | `MemoryBytes` | — | Размер окна приёма на соединение (доступно при `version` `0`, `2`, `3`). |
| `max_concurrent_streams` | `int` | — | Максимум одновременных потоков на соединение (доступно при `version` `0`, `2`, `3`). |
| `initial_packet_size` | `int` | — | Начальный размер пакета QUIC (только при `version: 3`). |
| `disable_path_mtu_discovery` | `bool` | `false` | Отключение PMTUD для QUIC (только при `version: 3`). |
| *(поля dialer)* | — | — | Все поля объекта [dialer](common-objects.md#объект-dialer-параметры-исходящего-подключения), включая `detour` для маршрутизации HTTP-загрузки через конкретный outbound. |

Примечание о выполнении: встроенный клиент служебных загрузок (`rule_set`, UI Clash API) использует `detour`, `tls` и `headers`, выполняет HTTP/1.1 с поддержкой до 10 перенаправлений (запрещая понижение `https` -> `http`), таймаутом подключения 30 с, таймаутом ввода-вывода 60 с и ограничением тела ответа 64 MiB.

### Пример `http_clients`

```json
{
  "http_clients": [
    {
      "tag": "proxy-fetch",
      "version": 2,
      "detour": "proxy-out",
      "headers": {
        "User-Agent": "tachyon-core/0.6.2"
      },
      "idle_timeout": "30s"
    }
  ]
}
```

---

## Секция `network_namespaces`

Массив описаний сетевых пространств имён (Linux-only). При непустом списке на платформах, отличных от Linux, валидатор возвращает ошибку `network namespaces are only supported on Linux`. На тег `tag` затем ссылаются поля `netns` в `listen` и `dialer`.

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `tag` | `string` | *(обязательно)* | Непустой тег пространства имён. |
| `type` | `string` | `"default"` | Режим: `""` / `"default"` (подключение к существующему netns по пути) или `"unshare"` (создание нового изолированного пространства имён). |
| `path` | `string` | — | Путь к файлу сетевого пространства имён (например, `"/run/netns/wan2"`). Обязателен для `type: "default"`, запрещён для `type: "unshare"`. |
| `pid_file` | `string` | — | Непустой путь к PID-файлу (допустим только для `type: "unshare"`, запрещён для `type: "default"`). |

### Пример `network_namespaces`

```json
{
  "network_namespaces": [
    {
      "tag": "wan-ns",
      "type": "default",
      "path": "/run/netns/wan2"
    }
  ]
}
```

---

## Секция `services`

Ключ верхнего уровня `services` включён в список допустимых корневых ключей для совместимости с конфигурациями sing-box 1.12+. В версии `tachyon-core` v0.6.2 валидатор принимает наличие этой секции без ошибки, однако отдельная подсистема сервисов (таких как `resolved` / `derp` / `ssm-api` внутри `services`) во время выполнения не запускается.

---

## Секция `lx`

Расширенная секция управления поведением туннелей, выравниванием MTU и адаптивной фрагментацией начальных пакетов. Все подразделы опциональны.

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `wg` | `object` | — | Управление простоем и ленивым поднятием WireGuard-туннелей. |
| `masque` | `object` | — | Параметры простоя туннелей MASQUE. |
| `sniff_guard` | `bool \| object` | `false` | Политика фрагментации начальных пакетов TLS/QUIC для исходящих соединений. |
| `mtu_align` | `bool \| string \| object` | — | Автоматическое согласование MTU для вложенных (`detour`) туннелей. |

### `lx.wg`

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `idle_suspend` | `Duration` | `"0s"` | Время простоя до приостановки туннеля (`>= 0`). Обязательно, если заданы `idle_suspend_reachable`, `idle_teardown` или `lazy_build: true`. |
| `idle_suspend_reachable` | `Duration` | `"0s"` | Время простоя до приостановки, когда узел остаётся достижимым (`>= idle_suspend`). |
| `idle_teardown` | `Duration` | — | Время простоя до полного разрыва сессии (`>= 0`, требует `idle_suspend`). |
| `lazy_build` | `bool` | `false` | Откладывает инициализацию туннеля до первого соединения (требует `idle_suspend`). |
| `build_max` | `int` | `0` | Максимальное число одновременно поднимаемых туннелей (`>= 0`). |
| `build_overflow` | `string` | `""` | Поведение при превышении `build_max`: `""`, `"wait"` или `"build"`. |

Устаревшие поля `route.lx_idle_suspend`, `route.lx_idle_suspend_reachable` и `route.lx_idle_teardown` сворачиваются в `lx.wg.*` с выводом предупреждения (при конфликте значений с `lx.wg.*` возникает ошибка).

### `lx.masque`

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `idle_timeout` | `Duration` | — | Таймаут простоя MASQUE-сессии (`>= 0`). |

### `lx.sniff_guard`

Принимает `bool` или объект:

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `enabled` | `bool` | `false` | Включает механизм. |
| `mode` | `string` | `""` | Режим работы: `"off"`, `"disabled"`, `"never"`, `"auto"`, `"on"`, `"force"`, `"clean"`, `"suspect"`. |
| `persist` | `bool` | `false` | Сохранение состояния между сессиями. |
| `detour_type` | `Listable<string>` | — | Типы исходящих протоколов, к которым применяется правило. |
| `nodes` | `Listable<string> \| object` | — | Фильтр узлов: список тегов или объект `{ "sni_mismatch": bool, "outbound_type": Listable<string>, "detour_type": Listable<string>, "except": Listable<string>, "include": Listable<string>, "exclude": Listable<string> }`. |
| `tls` | `object` | — | Настройки для TLS: `enabled`, `mode`, `method` (`"auto"`, `"none"`, `"tls_record"`, `"record"`, `"record_fragment"`, `"tcp_fragment"`, `"fragment"`, `"tls_fragment"`, `"both"`, `"split"`, `"delay"`, `"desync"`), `record_fragment` (`bool`), `fragment` (`bool \| object`), `lengths` / `length` (`int \| "min-max" \| [min, max]`, `>= 1`), `record_size` (`1..=16384`), `delays` / `delay` / `fallback_delay` (`int \| Duration \| "min-max"`), `persist`, `detour_type`, `nodes`. |
| `quic` | `object` | — | Настройки для QUIC: `enabled`, `mode`, `method` (`"auto"`, `"none"`, `"decoy_first_byte"`, `"decoy"`, `"delay"`), `decoy_first_byte` (`bool`), `delays` / `delay` / `fallback_delay`, `persist`, `detour_type`, `nodes`. |

### `lx.mtu_align`

Принимает `bool`, строку режима (`"clamp"`, `"fill"`, `"off"`) или объект `{ "mode": "clamp" | "fill" | "off", "except": Listable<string> }`. Автоматически вычисляет и подстраивает MTU для цепочек туннелей (например, WireGuard поверх другого туннеля), исключая теги из `except`.

### Пример `lx`

```json
{
  "lx": {
    "wg": {
      "idle_suspend": "30s",
      "idle_teardown": "5m",
      "lazy_build": true
    },
    "mtu_align": {
      "mode": "clamp",
      "except": ["tun-in"]
    }
  }
}
```

---

## Минимальная валидная конфигурация

```json
{
  "log": {
    "level": "warn",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "127.0.0.1",
      "listen_port": 1080
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "route": {
    "final": "direct"
  }
}
```
