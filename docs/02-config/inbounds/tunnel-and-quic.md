# QUIC и туннельные инбаунды

В этом разделе описаны QUIC-инбаунды и специализированные туннельные обработчики `tachyon-core` v0.6.2:

- [`hysteria2`](#hysteria2) — QUIC/HTTP/3 прокси с контролем полосы, Salamander и Gecko
- [`tuic`](#tuic) — QUIC прокси TUIC v5
- [`masque`](#masque) — RFC 9484 CONNECT-IP over HTTP/3 QUIC
- [`mieru`](#mieru) — мультипортовый TCP/UDP сервер Mieru v3
- [`tewfai`](#tewfai) — мультиплексируемый TCP/QUIC сервер с handover, шейпером и FEC
- [`fptn`](#fptn) — сервер FPTN (WebSocket, YaFF/Protobuf, RealityMode2)
- [`mtproto`](#mtproto) — сервер MTProto
- [`openconnect`](#openconnect) — мультипротокольный SSL-VPN сервер OpenConnect
- [`trusttunnel`](#trusttunnel) — сервер TrustTunnel (HTTP/2 и HTTP/3 CONNECT)
- [`wdtt`](#wdtt) — нативный UDP-сервер WDTT / qWDTT / CSQTT
- [Типы, присутствующие только в схеме валидации (`hysteria`, `cloudflared`, `sudoku`)](#типы-присутствующие-только-в-схеме-валидации)

Все сетевые типы ниже (кроме `cloudflared`) наследуют общие поля прослушивания из [common-objects.md](../common-objects.md).

---

## `hysteria2`

Серверный инбаунд Hysteria2 поверх QUIC (ALPN `h3`) с HTTP/3 аутентификацией (код ответа `233`), управлением полосой пропускания, пробросом TCP-потоков (`FRAME_TCP_REQUEST 0x401`) и UDP-датаграмм с дефрагментацией (до 1024 UDP-сессий на соединение, таймаут неактивности 120 с).

### Поведение рантайма

- **TLS обязателен**: требуется `"tls": {"enabled": true, ...}` с сертификатом и приватным ключом.
- **Обфускация UDP (`obfs`)**: на серверном инбаунде поддерживаются два типа в объекте `obfs`:
  - `"salamander"` — обфускация UDP-пакетов Salamander по паролю `obfs.password`;
  - `"gecko"` — расширенная обфускация с выравниванием размера пакетов в диапазоне `[min_packet_size, max_packet_size]` (по умолчанию `512..=1200`, допустимые границы `1..=2048`).
  > Поле `finalmask` относится к исходящему dialer (`outbounds[]`); на входящем инбаунде `hysteria2` обфускация Salamander и Gecko настраивается через объект `obfs`.
  > При задании `obfs` валидатор также требует наличие непустого пароля в `users[]`.
- **Полоса пропускания и BBR**: `up_mbps` ограничивает исходящую скорость сервера (в сторону клиента), `down_mbps` объявляется клиенту в заголовке аутентификации; `ignore_client_bandwidth: true` отключает учёт заявленной клиентом скорости и использует стандартный контроль перегрузки с профилем `bbr_profile` (`standard`, `conservative`, `aggressive`).
- **Горячее обновление пользователей**: список `users` обновляется при `reload_in_place`.
- **Маскировка (`masquerade`) и `realm`**: валидатор проверяет все форматы `masquerade` и `realm`; в рантайме v0.6.2 поля `masquerade`, `realm` и `brutal_debug` принимаются схемой совместимости.

### Поля конфигурации `hysteria2`

Помимо общих полей прослушивания, `hysteria2` принимает поля QUIC (`idle_timeout`, `keep_alive_period`, `stream_receive_window`, `connection_receive_window`, `max_concurrent_streams`, `initial_packet_size`, `disable_path_mtu_discovery`, `quic_migration`, `quic_rebind_interval`):

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | обязательное | `"hysteria2"`. |
| `tag` | `string` | `""` | Идентификатор инбаунда. |
| `listen` | `string` | `"127.0.0.1"` | IP-адрес прослушивания UDP (`"::"` для dual-stack). |
| `listen_port` | `uint16` | обязательное | UDP-порт прослушивания QUIC. |
| `users` | `object[]` | обязательное | Массив пользователей `{"name": "...", "password": "..."}`. |
| `up_mbps` | `int` | `0` | Ограничение скорости передачи от сервера к клиенту (Мбит/с; `0` — без явного лимита). |
| `down_mbps` | `int` | `0` | Ограничение скорости приёма сервером от клиента (Мбит/с; `0` — без явного лимита). |
| `ignore_client_bandwidth` | `bool` | `false` | Игнорировать скорость, запрошенную клиентом, и работать в режиме BBR. |
| `obfs` | `object` | — | Объект обфускации: `{"type": "salamander", "password": "..."}` или `{"type": "gecko", "password": "...", "min_packet_size": 512, "max_packet_size": 1200}`. |
| `bbr_profile` | `string` | `"standard"` | Профиль BBR: `"standard"`, `"conservative"` или `"aggressive"`. |
| `brutal_debug` | `bool` | `false` | Отладочный флаг контроллера Brutal (поле схемы совместимости). |
| `masquerade` | `string \| object` | — | Схема маскировки: URL (`file://`, `http://`, `https://`, абсолютный путь `/...`) либо объект `{"type": "file", "directory": "..."}`, `{"type": "proxy", "url": "...", "rewrite_host": true}`, `{"type": "string", "status_code": 200, "headers": {}, "content": "..."}`. |
| `realm` | `object` | — | Поле схемы совместимости для координации Realm (`server_url`, `token`, `realm_id`, `stun_servers`, `stun_domain_resolver`, `ip_version` `0\|4\|6`, `port_mapping`: `{enabled, timeout, lifetime}`, `http_client`). |
| `tls` | `object` | обязательное | Серверный TLS (`enabled: true`, сертификат и приватный ключ). |

### Пример конфигурации `hysteria2` (с Salamander)

```json
{
  "type": "hysteria2",
  "tag": "hy2-in",
  "listen": "::",
  "listen_port": 443,
  "up_mbps": 200,
  "down_mbps": 200,
  "bbr_profile": "standard",
  "obfs": {
    "type": "salamander",
    "password": "salamander-obfs-password"
  },
  "users": [
    {
      "name": "alice",
      "password": "hy2-user-password"
    }
  ],
  "masquerade": {
    "type": "string",
    "status_code": 404,
    "content": "Not Found"
  },
  "tls": {
    "enabled": true,
    "certificate_path": "/etc/tachyon-core/cert.pem",
    "key_path": "/etc/tachyon-core/key.pem"
  }
}
```

### Пример конфигурации `hysteria2` (с Gecko)

```json
{
  "type": "hysteria2",
  "tag": "hy2-gecko-in",
  "listen": "::",
  "listen_port": 8443,
  "ignore_client_bandwidth": true,
  "obfs": {
    "type": "gecko",
    "password": "gecko-obfs-password",
    "min_packet_size": 512,
    "max_packet_size": 1200
  },
  "users": [
    {
      "name": "bob",
      "password": "hy2-bob-password"
    }
  ],
  "tls": {
    "enabled": true,
    "certificate_path": "/etc/tachyon-core/cert.pem",
    "key_path": "/etc/tachyon-core/key.pem"
  }
}
```

---

## `tuic`

Серверный инбаунд протокола TUIC v5 поверх QUIC с EKM-аутентификацией на однонаправленном потоке, пробросом TCP через двунаправленные QUIC-потоки (`CMD_CONNECT`) и поддержкой обоих режимов передачи UDP — QUIC-датаграмм (`native`) и однонаправленных потоков (`quic`), с фрагментацией и сборкой пакетов.

### Поведение рантайма

- **TLS обязателен**: требуется `"tls": {"enabled": true, ...}` с сертификатом и приватным ключом.
- **Таймаут аутентификации**: если клиент не прислал валидную команду `CMD_AUTHENTICATE` за 10 секунд, соединение закрывается.
- **Heartbeat**: обрабатываются односторонние client -> server кадры `CMD_HEARTBEAT` и отвязка UDP-ассоциаций `CMD_DISSOCIATE`.
- **Горячее обновление пользователей**: список `users` обновляется при `reload_in_place`.

### Поля конфигурации `tuic`

Помимо общих полей прослушивания, `tuic` принимает QUIC-поля (`idle_timeout`, `keep_alive_period`, `stream_receive_window`, `connection_receive_window`, `max_concurrent_streams`, `initial_packet_size`, `disable_path_mtu_discovery`, `quic_migration`, `quic_rebind_interval`):

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | обязательное | `"tuic"`. |
| `tag` | `string` | `""` | Идентификатор инбаунда. |
| `listen` | `string` | `"127.0.0.1"` | IP-адрес прослушивания UDP (`"::"` для dual-stack). |
| `listen_port` | `uint16` | обязательное | UDP-порт прослушивания QUIC. |
| `users` | `object[]` | обязательное | Непустой массив `{"name": "...", "uuid": "...", "password": "..."}`. Поле `uuid` валидируется как корректный UUID. |
| `congestion_control` | `string` | `"cubic"` | Алгоритм контроля перегрузки: `"cubic"`, `"new_reno"` или `"bbr"`. |
| `auth_timeout` | `duration` | `"10s"` | Таймаут ожидания аутентификации клиента (валидируется как duration). |
| `zero_rtt_handshake` | `bool` | `false` | Разрешить 0-RTT рукопожатие QUIC (поле схемы совместимости). |
| `heartbeat` | `duration` | — | Интервал heartbeat (валидируется как duration). |
| `tls` | `object` | обязательное | Серверный TLS (`enabled: true`, сертификат и приватный ключ). |

### Пример конфигурации `tuic`

```json
{
  "type": "tuic",
  "tag": "tuic-in",
  "listen": "::",
  "listen_port": 8443,
  "users": [
    {
      "name": "alice",
      "uuid": "27848739-7e62-4138-9fd3-098a63964b6b",
      "password": "tuic-v5-password"
    }
  ],
  "congestion_control": "bbr",
  "auth_timeout": "10s",
  "zero_rtt_handshake": false,
  "heartbeat": "10s",
  "tls": {
    "enabled": true,
    "alpn": ["h3"],
    "certificate_path": "/etc/tachyon-core/cert.pem",
    "key_path": "/etc/tachyon-core/key.pem"
  }
}
```

---

## `masque`

Серверный инбаунд MASQUE (RFC 9484 CONNECT-IP поверх HTTP/3 QUIC, ALPN `h3`). Согласует Extended CONNECT и HTTP/3 Datagrams через кадры `SETTINGS`, отвечает `200 OK` с заголовком `capsule-protocol: ?1` и капсулой `ROUTE_ADVERTISEMENT` (`0.0.0.0/0` и `::/0`), после чего терминирует входящие IP-пакеты через встроенный стек `smoltcp` (TCP), маршрутизатор UDP и ICMP-обработчик.

### Поля конфигурации `masque`

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | обязательное | `"masque"`. |
| `tag` | `string` | `"masque"` | Идентификатор инбаунда. |
| `listen` | `string` | `"127.0.0.1"` | IP-адрес прослушивания UDP (`"::"` для dual-stack). |
| `listen_port` | `uint16` | обязательное | UDP-порт прослушивания QUIC/HTTP/3. |
| `tls` | `object` | обязательное | Серверный TLS (`enabled: true`, сертификат и приватный ключ). |
| `mtu` | `uint32` | `1280` | MTU IP-туннеля в байтах (значения `< 1200` игнорируются в пользу `1280`). |
| `users` | `object[]` | `[]` | Поле схемы совместимости для списка пользователей. |
| `ipv4_pool` | `string` | — | Поле схемы совместимости для IPv4-пула клиентов. |
| `ipv6_pool` | `string` | — | Поле схемы совместимости для IPv6-пула клиентов. |

### Пример конфигурации `masque`

```json
{
  "type": "masque",
  "tag": "masque-in",
  "listen": "::",
  "listen_port": 443,
  "mtu": 1280,
  "tls": {
    "enabled": true,
    "certificate_path": "/etc/tachyon-core/cert.pem",
    "key_path": "/etc/tachyon-core/key.pem"
  }
}
```

---

## `mieru`

Серверный инбаунд протокола Mieru v3, работающий поверх TCP или UDP с поддержкой привязки до 256 портов на один обработчик. Идентифицирует пользователя по первому сегменту и обрабатывает вложенные запросы SOCKS5 CONNECT (TCP и UDP) и UoT v1/v2.

### Поведение рантайма

- **Выбор транспорта**: `transport` задаётся простой строкой `"TCP"` / `"tcp"` (по умолчанию) или `"UDP"` / `"udp"` (не объектом V2Ray).
- **Множественные порты**: помимо `listen_port`, инбаунд может одновременно слушать дополнительные порты и диапазоны (`"8000-8010"` или `"8000:8010"`), собранные из `listen_ports`, `server_ports` и `port_bindings` (в сумме до 256 уникальных портов). Если `listen_port` не задан, но задан диапазон, используется первый порт из списка.
- **Адрес по умолчанию**: при отсутствии `listen` используется `"0.0.0.0"`.

### Поля конфигурации `mieru`

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | обязательное | `"mieru"`. |
| `tag` | `string` | `"mieru"` | Идентификатор инбаунда. |
| `listen` | `string` | `"0.0.0.0"` | IP-адрес прослушивания (`"::"` для dual-stack). |
| `listen_port` | `uint16` | из списка портов | Основной порт прослушивания. |
| `transport` | `string` | `"tcp"` | Транспортный протокол: `"tcp"` или `"udp"` (регистронезависимо). |
| `users` | `object[]` | обязательное | Непустой массив пользователей: `{"name": "...", "password": "..."}` (вместо `name` также принимается `username`). Оба поля обязательны и непусты. |
| `listen_ports` | `string \| string[] \| uint16` | `[]` | Дополнительные порты или диапазоны (`"2000-2010"`, `"2000:2010"`, список через запятую/пробел или массив). |
| `server_ports` | `string \| string[] \| uint16` | `[]` | Альтернативное имя для списка дополнительных портов/диапазонов. |
| `port_bindings` | `object[]` | `[]` | Массив объектов `{"port": 2010}` и/или `{"port_range": "2020-2030"}`. |
| `traffic_pattern` | `string` | `""` | Поле схемы совместимости для шаблона трафика. |
| `multiplexing` | `string` | `""` | Поле схемы совместимости для уровня мультиплексирования. |
| `user_hint_is_mandatory` | `bool` | `false` | Поле схемы совместимости. |

### Пример конфигурации `mieru`

```json
{
  "type": "mieru",
  "tag": "mieru-in",
  "listen": "::",
  "listen_port": 2010,
  "transport": "tcp",
  "listen_ports": ["2011-2015"],
  "users": [
    {
      "name": "alice",
      "password": "mieru-strong-password"
    }
  ]
}
```

---

## `tewfai`

Серверный инбаунд протокола Tewfai: мультиплексирование TCP-потоков и UDP-датаграмм поверх TCP (с TLS 1.3 / REALITY) и/или QUIC (ALPN `h3`), взаимное рукопожатие `HELLO` / `HELLO_OK` с защитой от повторов (кэш nonce 4096 записей / TTL 120 с), передача сессии без разрыва (`handover`), формирование профиля трафика (`morph_profile` / `shaper`) и опциональная коррекция ошибок (`fec`).

### Поведение рантайма

- **Защита от зондирования**:
  - на TCP-носителе при ошибке аутентификации первого фрейма сервер не отправляет ни байта в ответ (а при включённом REALITY неаутентифицированные TLS-рукопожатия прозрачно проксируются на decoy-сервер);
  - на QUIC-носителе (ALPN `h3`) при невалидном первом потоке сервер отвечает как стандартный HTTP/3-сервер: контрольный поток `SETTINGS`, `:status 404` и закрытие `H3_NO_ERROR`. Если для QUIC не указан сертификат (`quic.tls` или `tls`), сервер автоматически генерирует самоподписанный сертификат.
- **Совместная работа TCP и QUIC**: при `"transport": ["tcp", "quic"]` (или при `"quic": true`) оба носителя открываются на одном номере порта (`listen_port`, раздельные TCP и UDP порты).
- **Передача сессий (`handover`)**: при обрыве носителя сессия удерживается в LRU-хранилище (до `sessions.max`, по умолчанию 1024) в течение `grace_secs` (по умолчанию 60 с) с буфером доотправки до 256 КиБ; одноразовый тикет `RESUME` защищает от повторного перехвата.
- **Упрощённый блок `reality`**: можно указать блок `tls` с вложенным `reality` либо сокращённый верхнеуровневый объект `reality` напрямую на инбаунде `tewfai`.

### Поля конфигурации `tewfai`

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | обязательное | `"tewfai"`. |
| `tag` | `string` | `"tewfai"` | Идентификатор инбаунда. |
| `listen` | `string` | `"127.0.0.1"` | IP-адрес прослушивания. |
| `listen_port` | `uint16` | обязательное | Порт прослушивания (TCP и/или UDP QUIC). |
| `users` | `object[]` | `[]` | Массив пользователей `{"uuid": "..."}` или `{"password": "..."}`. Требуется `users`, `uuid` или `password`. |
| `uuid` | `string` | `""` | Одиночный секрет (UUID), если `users` не задан. |
| `password` | `string` | `""` | Одиночный секрет (пароль), если `users` и `uuid` не заданы. |
| `transport` | `string \| string[]` | `"tcp"` | Носители: `"tcp"`, `"quic"` или `["tcp", "quic"]`. |
| `quic` | `bool \| object` | `false` | Включить QUIC-носитель (`true`) или задать объект `{"enabled": true, "tls": {...}}`. |
| `tls` | `object` | — | Серверный TLS / REALITY. |
| `reality` | `object` | — | Сокращённый блок REALITY на верхнем уровне инбаунда (используется, если не задан `tls`; поддерживает `dest` или `handshake`, `private_key`, `short_id`). |
| `inner_cipher` | `string` | `"null"` с TLS, иначе `"aes-256-gcm"` | Внутреннее шифрование кадров: `"aes-256-gcm"` или `"null"` / `"none"` / `"any"` (разрешает нулевой внутренний шифр при наличии внешнего TLS). |
| `morph_profile` | `string` | `"auto"` | Профиль распределения размеров кадров: `"auto"` (`"adaptive"` / `"transformer"`), `"browsing"`, `"video"`, `"webrtc"`, `"bulk"`. |
| `shaper` | `object` | `{"mode": "off"}` | Шейпер потока: `{"mode": "off" \| "adaptive" \| "fixed", "quantum_ms": 10, "rate_mbps": 50}` (`quantum_ms`: `1..=200`, `rate_mbps`: `1..=10000`). |
| `max_streams` | `uint32` | `256` | Максимум одновременных потоков на сессию (`1..=4096`). |
| `sessions` | `object` | `{"max": 1024, "grace_secs": 60}` | Параметры хранилища сессий: `max` (`1..=65536`) и `grace_secs`. |
| `handover` | `bool \| object` | `true` | Включить передачу сессий между носителями: `bool` или `{"enabled": true, "grace_secs": 60}`. |
| `alt_endpoints` | `string[]` | `[]` | Список альтернативных адресов для передачи клиенту в подсказках, например `["quic://alt.example.com:443", "tcp://alt.example.com:8443"]`. |
| `fec` | `bool` | `false` | Включить прямую коррекцию ошибок (FEC). |
| `pqc` | `bool \| string` | — | Поле схемы конфигурации постквантового обмена ключами. |
| `mtu` | `uint16` | `0` (авто) | Подсказка MTU для клиента (значения `>= 256`). |

### Пример конфигурации `tewfai`

```json
{
  "type": "tewfai",
  "tag": "tewfai-in",
  "listen": "::",
  "listen_port": 443,
  "users": [
    {
      "uuid": "27848739-7e62-4138-9fd3-098a63964b6b"
    }
  ],
  "transport": ["tcp", "quic"],
  "inner_cipher": "null",
  "morph_profile": "auto",
  "shaper": {
    "mode": "adaptive",
    "quantum_ms": 10
  },
  "max_streams": 256,
  "sessions": {
    "max": 1024,
    "grace_secs": 60
  },
  "handover": {
    "enabled": true,
    "grace_secs": 60
  },
  "fec": false,
  "tls": {
    "enabled": true,
    "certificate_path": "/etc/tachyon-core/cert.pem",
    "key_path": "/etc/tachyon-core/key.pem"
  }
}
```

---

## `fptn`

Серверный инбаунд протокола FPTN поверх HTTPS и WebSocket, совместимый со штатными клиентами `fptn` и аутбаундом `fptn` в `tachyon-core`.

### Поведение рантайма

- **HTTP и WebSocket эндпоинты**:
  - `POST /api/v1/login` — проверка учётных данных из `users`, выдача JWT-токена;
  - `GET /api/v1/dns` — возвращает клиенту адреса `dns` и `dns_ipv6`;
  - `GET /api/v1/test/file.bin` — выдаёт тестовый блок 100 КиБ для оценки пропускной способности;
  - `GET /api/v1/fptn` — обновление соединения до WebSocket для передачи пакетных батчей (`MSG_IP_ASSIGNMENT`, `MSG_BATCH_IP_PACKET`).
- **Сериализация (`YaFF` / `Protobuf`)**: выбирается автоматически по HTTP-заголовку клиента `X-Serializer`: `"yaff"` включает бинарный формат YaFF, иначе используется Protobuf.
- **Пулинг логических сессий (`SessionID`)**: при наличии заголовка `SessionID` (до 128 байт) несколько WebSocket-соединений клиента (до 16 ссылок на сессию, до 1024 пулированных сессий на инбаунд) объединяются вокруг одного виртуального L3-стека (`smoltcp` + UDP-маршрутизатор + ICMP echo), что обеспечивает работу режимов `RollingTunnel` и `BrowserMimicry` без обрыва TCP-соединений. Клиентам автоматически выдаются виртуальные адреса из `10.88.0.x` и `fc00:88::x`.
- **Автораспознавание TLS, обфускации и `RealityMode2`**: при включённом `tls` сервер анализирует первые байты входящего соединения и поддерживает три режима одновременно на одном порту:
  1. обычный TLS;
  2. обфусцированный TLS (записи с первым байтом `0x17`), поверх которого снимается обфускация на этапе рукопожатия;
  3. `RealityMode2` — при обнаружении decoy ClientHello с 32-байтным `SessionID` сервер запрашивает реальный TLS-ответ у домена из SNI (если его IP публичный; таймаут подключения 2 с, бюджет 2.5 с) либо синтезирует корректный TLS 1.3 ответ, подставляет клиентский `SessionID` и далее принимает защищённую сессию.
- **MD5-отпечаток сертификата**: официальные клиенты FPTN и исходящий `fptn` выполняют пиннинг сертификата по 32-символьному hex MD5-отпечатку DER-представления серверного сертификата из `tls.certificate` / `tls.certificate_path` (значение передаётся на стороне клиента в `md5_fingerprint` или в токене `fptn:` / `fptnb:`).

### Поля конфигурации `fptn`

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | обязательное | `"fptn"`. |
| `tag` | `string` | `"fptn"` | Идентификатор инбаунда. |
| `listen` | `string` | `"127.0.0.1"` | IP-адрес прослушивания. |
| `listen_port` | `uint16` | обязательное | TCP-порт прослушивания. |
| `users` | `object[]` | `[]` | Массив пользователей: `{"username": "...", "password": "..."}` (вместо `username` также принимается `name`). |
| `tls` | `object` | — | Серверный TLS (`enabled: true`, сертификат и приватный ключ). Рекомендуется для работы с официальными клиентами и `RealityMode2`. |
| `dns` | `string` | `"1.1.1.1"` | IPv4 DNS-сервер, возвращаемый клиентам на `GET /api/v1/dns`. |
| `dns_ipv6` | `string` | `"fc00:1::1"` | IPv6 DNS-сервер, возвращаемый клиентам на `GET /api/v1/dns`. |
| `ipv4_pool` | `string` | `"10.88.0.0/24"` (внутр.) | Поле схемы совместимости для IPv4-пула. |
| `ipv6_pool` | `string` | `"fc00:88::/64"` (внутр.) | Поле схемы совместимости для IPv6-пула. |
| `obfuscation` | `string` | авто | Поле схемы совместимости (сервер автоматически распознаёт `none`, обфусцированный TLS и `RealityMode2`). |

### Пример конфигурации `fptn`

```json
{
  "type": "fptn",
  "tag": "fptn-in",
  "listen": "::",
  "listen_port": 443,
  "users": [
    {
      "username": "alice",
      "password": "fptn-strong-password"
    }
  ],
  "dns": "1.1.1.1",
  "dns_ipv6": "2606:4700:4700::1111",
  "tls": {
    "enabled": true,
    "certificate_path": "/etc/tachyon-core/fptn-cert.pem",
    "key_path": "/etc/tachyon-core/fptn-key.pem"
  }
}
```

---

## `mtproto`

Серверный инбаунд протокола MTProto поверх TCP (с опциональным TLS). Принимает 64-байтный инициализационный заголовок обфускации, извлекает ключи потока и идентификатор фрейминга, читает целевой адрес из первого пакета и проксирует TCP-поток через маршрутизатор.

### Поведение рантайма

- **Секреты**: каждый секрет — ровно 32 шестнадцатеричных символа (16 байт). Если `users` и `secret` не заданы, сервер принимает подключения без секрета (plain obfuscation).
- **Транспорты (фрейминг)**: поддерживаются 4 варианта — `"abridged"` (`0xefefefef`), `"intermediate"` (`0xeeeeeeee`), `"padded_intermediate"` / `"padded-intermediate"` (`0xdddddddd`) и `"full"` (`0x00000000`). Если поле `transport` не указано, сервер принимает любой из четырёх вариантов.
- **Таймауты и фильтрация**: рукопожатие и чтение первого пакета ограничены таймаутом `10s`; поддерживается фильтр клиентов `filter`.

### Поля конфигурации `mtproto`

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | обязательное | `"mtproto"`. |
| `tag` | `string` | `"mtproto"` | Идентификатор инбаунда. |
| `listen` | `string` | `"127.0.0.1"` | IP-адрес прослушивания. |
| `listen_port` | `uint16` | обязательное | TCP-порт прослушивания. |
| `secret` | `string` | `""` | Одиночный секрет (32 hex-символа). Используется, если не задан `users`. |
| `users` | `object[]` | `[]` | Список объектов `{"secret": "<32 hex>"}`. Имеет приоритет над `secret`. |
| `transport` | `string` | любой | Принудительный режим фрейминга: `"abridged"`, `"intermediate"`, `"padded_intermediate"` (`"padded-intermediate"`) или `"full"`. |
| `tls` | `object` | — | Опциональный серверный TLS. |

### Пример конфигурации `mtproto`

```json
{
  "type": "mtproto",
  "tag": "mtproto-in",
  "listen": "::",
  "listen_port": 8443,
  "users": [
    {
      "secret": "0123456789abcdef0123456789abcdef"
    }
  ],
  "transport": "padded_intermediate"
}
```

---

## `openconnect`

Серверный инбаунд SSL-VPN OpenConnect с поддержкой шести протокольных диалектов (`flavor`), двух режимов передачи (потоковый туннель и полноценный L3 IP-туннель на базе `smoltcp` + UDP-маршрутизатора + ICMP echo), а также шифрования IP-пакетов ESP.

### Поведение рантайма

- **Поддерживаемые диалекты (`flavor`)**:
  - `"anyconnect"` (по умолчанию, Cisco AnyConnect / CSTP)
  - `"gp"` (Palo Alto GlobalProtect / GPST)
  - `"nc"` (Juniper Network Connect)
  - `"pulse"` (Pulse Secure)
  - `"f5"` (F5 BIG-IP)
  - `"fortinet"` (Fortinet SSL-VPN)
- **Режим IP-туннеля (`ip: true`)**: сервер выдаёт клиенту IP-адрес (по умолчанию `10.10.10.2/24`), до 3 DNS-серверов (`dns`) и маршруты (`route`, по умолчанию `0.0.0.0/0`), после чего терминирует входящие IPv4/IPv6-пакеты через встроенный стек `smoltcp` (TCP), UDP-маршрутизатор и ICMP.
- **Слой ESP (`esp: true`)**: шифрованный транспорт IP-пакетов; требует обязательного включения `"ip": true` (иначе запуск завершается ошибкой).
- **Таймаут рукопожатия**: 30 секунд.

### Поля конфигурации `openconnect`

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | обязательное | `"openconnect"`. |
| `tag` | `string` | `"openconnect"` | Идентификатор инбаунда. |
| `listen` | `string` | `"127.0.0.1"` | IP-адрес прослушивания. |
| `listen_port` | `uint16` | обязательное | TCP-порт прослушивания. |
| `flavor` | `string` | `"anyconnect"` | Протокольный диалект: `"anyconnect"`, `"gp"`, `"nc"`, `"pulse"`, `"f5"` или `"fortinet"`. |
| `cookie` | `string` | `""` | Ожидаемое значение session cookie клиента (если пусто — не проверяется). |
| `user_agent` | `string` | `"Mozilla/5.0 (X11; Linux x86_64) openconnect"` | Строка User-Agent для протокольного обмена. |
| `local_hostname` | `string` | `"openconnect"` | Имя хоста шлюза. |
| `urlpath` | `string` | `""` | Поле схемы совместимости для пути URL шлюза. |
| `tunnel` | `string` | `""` | Поле схемы совместимости для имени/профиля туннеля. |
| `mtu` | `uint16` | `1400` | MTU туннеля в байтах. |
| `ip` | `bool` | `false` | Включить режим L3 IP-туннеля (терминация TCP/UDP/ICMP на сервере). |
| `esp` | `bool` | `false` | Включить шифрованный слой ESP (требует `"ip": true`). |
| `esp_gateway` | `string` | `""` | Поле схемы совместимости для адреса ESP-шлюза. |
| `esp_client` | `string` | `""` | Поле схемы совместимости для адреса ESP-клиента. |
| `address` | `string \| string[]` | `"10.10.10.2/24"` | IPv4 и/или IPv6 CIDR-адрес, выдаваемый клиенту внутри туннеля. |
| `dns` | `string \| string[]` | `[]` | Список IP-адресов DNS-серверов, передаваемых клиенту (до 3 адресов). |
| `route` | `string \| string[]` | `["0.0.0.0/0"]` | Список CIDR-маршрутов split-tunneling, объявляемых клиенту. |
| `tls` | `object` | — | Серверный TLS (`enabled: true`, сертификат и приватный ключ). |

### Пример конфигурации `openconnect`

```json
{
  "type": "openconnect",
  "tag": "oc-in",
  "listen": "::",
  "listen_port": 443,
  "flavor": "anyconnect",
  "cookie": "webvpn-session-secret",
  "mtu": 1400,
  "ip": true,
  "address": ["10.10.10.2/24"],
  "dns": ["1.1.1.1", "8.8.8.8"],
  "route": ["0.0.0.0/0"],
  "tls": {
    "enabled": true,
    "certificate_path": "/etc/tachyon-core/cert.pem",
    "key_path": "/etc/tachyon-core/key.pem"
  }
}
```

---

## `trusttunnel`

Серверный инбаунд протокола TrustTunnel поверх HTTP/2 (TCP + TLS) или HTTP/3 (UDP + QUIC, ALPN `h3`).

### Поведение рантайма

- **Аутентификация**: обязателен непустой список `users`; заголовок `Proxy-Authorization: Basic ...` проверяется в каждом запросе `CONNECT` за постоянное время (constant-time). При ошибке возвращается `407 Proxy Authentication Required`.
- **Служебные псевдохосты**:
  - `CONNECT <host>:<port>` — туннелирование TCP-соединения (а также UoT v1/v2);
  - `CONNECT _udp2` — мультиплексированный канал UDP-датаграмм;
  - `CONNECT _check` — проверка доступности сервера (возвращает `200 OK`).
- **Режим QUIC**: при `"quic": true` открывается UDP/QUIC-слушатель (HTTP/3, ALPN `h3`) вместо TCP; объект `tls` в этом режиме обязателен.

### Поля конфигурации `trusttunnel`

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | обязательное | `"trusttunnel"`. |
| `tag` | `string` | `"trusttunnel"` | Идентификатор инбаунда. |
| `listen` | `string` | `"127.0.0.1"` | IP-адрес прослушивания (`"::"` для dual-stack). |
| `listen_port` | `uint16` | обязательное | Порт прослушивания (TCP при `quic: false`, UDP при `quic: true`). |
| `users` | `object[]` | обязательное | Непустой массив учётных записей `{"username": "...", "password": "..."}`. |
| `quic` | `bool` | `false` | Использовать HTTP/3 поверх QUIC (UDP) вместо HTTP/2 поверх TCP. |
| `tls` | `object` | обязателен при `quic: true` | Серверный TLS (`enabled: true`, сертификат и приватный ключ). |

### Пример конфигурации `trusttunnel`

```json
{
  "type": "trusttunnel",
  "tag": "trusttunnel-in",
  "listen": "::",
  "listen_port": 443,
  "quic": false,
  "users": [
    {
      "username": "ttuser",
      "password": "tt-strong-password"
    }
  ],
  "tls": {
    "enabled": true,
    "alpn": ["h2"],
    "certificate_path": "/etc/tachyon-core/cert.pem",
    "key_path": "/etc/tachyon-core/key.pem"
  }
}
```

---

## `wdtt`

Нативный userspace UDP-сервер протоколов WDTT / qWDTT / CSQTT, объединяющий обфускацию RTP WRAP (`WDTT-WRAP-v1`, `CSQTT-WRAP-v1`), SRTP-обфускацию, DTLS 1.2 с RFC 9146 Connection ID (`tls12_cid`), рукопожатие WireGuard `Noise_IKpsk2` (режим `wg`), быстрый канал с переупорядочиванием кадров `RA` (режим `raw`) и CSQTT (`csqtt` / `csqtt_v1`), с терминацией клиентского IPv4-трафика TCP/UDP/ICMP в маршрутизатор `tachyon-core` через виртуальный стек `smoltcp` и UDP-маршрутизатор.

### Поведение рантайма

- **Порты по умолчанию**: если `listen_port` не задан, используется `56000` (а для режимов `csqtt` и `csqtt_v1` — `46000`). Адрес `listen` по умолчанию `"0.0.0.0"`.
- **Дополнительный порт `raw_port`**: если указан `raw_port` (отличный от `listen_port`), открывается второй UDP-сокет для `raw`-потоков. В режиме `mode: "all"` при ненулевом `listen_port <= 65532` и не заданном `raw_port` сервер автоматически пытается открыть порт `listen_port + 3`.
- **Ресурсы и сессии**: не более 512 незавершённых DTLS-рукопожатий (TTL 15 с), 1024 активных DTLS-пиров, 1024 клиентских туннелей (таймаут неактивности 180 с) и до 128 многопутевых каналов (`legs`) на клиента.
- **Ключ WireGuard (`private_key` / `wg_private_key`)**: 32-байтный X25519-ключ в формате base64 или 64 hex-символа; если не задан, генерируется случайный эфемерный ключ при запуске.

### Поля конфигурации `wdtt`

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | обязательное | `"wdtt"`. |
| `tag` | `string` | `"wdtt-in"` | Идентификатор инбаунда. |
| `listen` | `string` | `"0.0.0.0"` | IP-адрес прослушивания UDP. |
| `listen_port` | `uint16` | `56000` (`46000` для `csqtt*`) | Основной UDP-порт сервера. |
| `raw_port` | `uint16` | `listen_port + 3` в режиме `all` | Дополнительный UDP-порт для режима `raw` (`0..=65535`). |
| `password` | `string` | `""` | Общий пароль (если `users` не задан; создаёт пользователя `"default"`). Требуется непустой `password` или `users`. |
| `users` | `object[]` | `[]` | Массив пользователей: `{"name": "...", "password": "...", "max_devices": 0, "expires_at": ..., "total_bytes": ...}`. Поле `password` обязательно. |
| `max_devices` | `uint32` | `0` | Глобальный лимит одновременных устройств на пользователя (`0` — без ограничения). |
| `mode` | `string` | `"all"` | Режим сервера: `"all"`, `"wg"`, `"raw"`, `"csqtt"` или `"csqtt_v1"`. |
| `obfs` | `string` | `""` | Профиль медиа-обфускации RTP WRAP: `"audio"`, `"video"` или `"unified"`. |
| `network` / `ipv4_pool` | `string` | `"10.66.0.1/16"` | IPv4-подсеть и адрес шлюза для выдачи клиентам. |
| `raw_ipv4_pool` | `string` | `""` | Опциональный отдельный IPv4-пул для `raw`-клиентов (валидируется как строка). |
| `client_dns` | `string` | шлюз подсети | DNS-сервер, передаваемый клиентам (валидируется как строка). |
| `mtu` | `uint16` | `1280` | MTU туннеля (`576..=1500`). |
| `private_key` / `wg_private_key` | `string` | автогенерация | Приватный X25519-ключ сервера WireGuard (base64 или 64 hex-символа). |

### Пример конфигурации `wdtt`

```json
{
  "type": "wdtt",
  "tag": "wdtt-in",
  "listen": "0.0.0.0",
  "listen_port": 56000,
  "raw_port": 56003,
  "mode": "all",
  "obfs": "unified",
  "network": "10.66.0.1/16",
  "mtu": 1280,
  "max_devices": 5,
  "users": [
    {
      "name": "alice",
      "password": "wdtt-alice-password",
      "max_devices": 3
    }
  ]
}
```

---

## Типы, присутствующие только в схеме валидации

Три типа из перечня поддерживаемых схемой валидации распознаются проверкой конфигурации, но не имеют активного обработчика в рантайме `tachyon-core` v0.6.2.

### `hysteria` (v1)

Схема Hysteria v1 проходит `tachyon-core check` (требуется `"tls": {"enabled": true, ...}`), однако при запуске `tachyon-core run` завершается ошибкой `inbound type "hysteria" not implemented yet`. Для серверного развёртывания используйте [`hysteria2`](#hysteria2).

Допустимые поля схемы `hysteria` (помимо общих полей прослушивания):

| Поле | Тип | Описание |
|---|---|---|
| `up`, `down` | `string \| int` | Скорость канала в сетевых единицах (`Bps`, `Kbps`, `KBps`, `Mbps`, `MBps`, `Gbps`, `GBps` и т.д.) или байтах/с. |
| `up_mbps`, `down_mbps` | `int` | Скорость канала в Мбит/с. |
| `obfs` | `string` | Ключ обфускации Hysteria v1. |
| `users` | `object[]` | Массив пользователей. |
| `recv_window_conn`, `recv_window_client` | `uint64` | Размеры приёмных окон QUIC. |
| `max_conn_client` | `int` | Максимум соединений на клиента. |
| `disable_mtu_discovery` | `bool` | Отключить обнаружение Path MTU. |
| `tls` | `object` | Обязательный блок серверного TLS (`enabled: true`). |

### `cloudflared`

Схема `cloudflared` (без общих полей прослушивания) проверяется валидатором, после чего команда `check` возвращает ошибку `Cloudflared is not included in this build, rebuild with -tags with_cloudflared`.

Допустимые поля схемы `cloudflared`:

| Поле | Тип | Описание |
|---|---|---|
| `type`, `tag` | `string` | `"cloudflared"` и тег. |
| `token` | `string` | Токен Cloudflare Tunnel. |
| `ha_connections` | `int` | Число резервных подключений. |
| `protocol` | `string` | Транспортный протокол туннеля. |
| `post_quantum` | `bool` | Постквантовый обмен ключами. |
| `edge_ip_version` | `int` | Версия IP edge-узлов. |
| `datagram_version` | `string` | Версия датаграммного протокола. |
| `grace_period` | `duration` | Период плавного завершения. |
| `region` | `string` | Регион подключения. |
| `control_dialer`, `tunnel_dialer` | `object` | Вложенные объекты `DialerOptions` (см. [common-objects.md](../common-objects.md)). |

### `sudoku`

Идентификатор `"sudoku"` включён в список известных типов инбаундов валидатора, но не имеет серверной реализации в рантайме v0.6.2 (при запуске `run` возвращается ошибка `inbound type "sudoku" not implemented yet`).
