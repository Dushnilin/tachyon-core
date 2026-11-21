# QUIC и туннельные протоколы (`outbounds`)

В этом разделе приведена спецификация QUIC- и туннельных аутбаундов `tachyon-core`: `hysteria2`, `hysteria`, `tuic`, `masque`, `mieru`, `tewfai`, `fptn`, `mtproto`, `openconnect`, `trusttunnel`, `wdtt`, а также описание взаимодействия с туннелями уровня L3 из секции `endpoints` (`wireguard`, `openvpn-client`, `tailscale`).

Общие параметры `dialer` (включая `finalmask`) и `tls` описаны в [Общих объектах конфигурации](../common-objects.md).

## Общие поля QUIC

Аутбаунды `hysteria2`, `hysteria`, `tuic` и `trusttunnel` принимают следующие плоские параметры настройки QUIC-соединения:

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `idle_timeout` | `duration` | `"30s"` | Максимальное время простоя QUIC-соединения до закрытия. |
| `keep_alive_period` | `duration` | `"10s"` (`hysteria2`), `0` (`tuic` / `trusttunnel`) | Интервал отправки QUIC `PING` для поддержания NAT-трансляций. |
| `stream_receive_window` | `string` \| `integer` | Адаптивно | Размер окна приёма на один поток (число байт или строка с единицей, например `"4MB"`). |
| `connection_receive_window` | `string` \| `integer` | Адаптивно | Суммарное окно приёма на QUIC-соединение. |
| `max_concurrent_streams` | `integer` | Адаптивно | Максимальное число одновременных двунаправленных потоков. |
| `initial_packet_size` | `integer` | По умолчанию QUIC | Начальный размер UDP-пакета QUIC в байтах. |
| `disable_path_mtu_discovery` | `boolean` | `false` | Отключает автоматический поиск Path MTU (PMTUD). |
| `quic_migration` | `boolean` | `true` | Разрешает миграцию QUIC-соединения при смене локального адреса/маршрута. |
| `quic_rebind_interval` | `duration` | — | Интервал принудительной перепривязки локального UDP-сокета. |

---

## `hysteria2`

Клиент Hysteria 2 поверх QUIC и HTTP/3. Поддерживает TCP и UDP (QUIC-дейтаграммы с автоматической фрагментацией), управление полосой пропускания (Brutal и BBR), ротацию портов (`server_ports`), обфускацию Salamander и Gecko, а также параметры `finalmask` на уровне диалера.

### Поддерживаемые поля

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | — | Обязательно: `"hysteria2"`. |
| `tag` | `string` | `""` | Уникальный тег аутбаунда. |
| `server` | `string` | — | Обязательно (если не задан `realm`): адрес сервера. |
| `server_port` | `integer` | — | Порт сервера (`1..=65535`). Не обязателен, если задан `server_ports`. |
| `server_ports` | `string` \| `string[]` | — | Диапазоны портов для port hopping в формате `"20000:30000"`, `"20000-30000"` или `"443"` (строка или массив строк). |
| `hop_interval` | `duration` | `"30s"` (при наличии диапазонов) | Базовый интервал смены целевого UDP-порта при активном `server_ports`. |
| `hop_interval_max` | `duration` | `hop_interval` | Верхняя граница случайного интервала смены порта (если больше `hop_interval`, выбирается случайная длительность в диапазоне `[hop_interval, hop_interval_max)`). |
| `up_mbps` | `integer` | `0` | Ограничение и целевая скорость отдачи в Мбит/с (SI: 1 Мбит/с = 125 000 байт/с). При значении `> 0` включает Brutal congestion control; при `0` используется BBR. |
| `down_mbps` | `integer` | `0` | Заявленная скорость приёма в Мбит/с, сообщаемая серверу при аутентификации HTTP/3. |
| `password` | `string` | — | Обязательно: пароль аутентификации Hysteria2. |
| `obfs` | `object` | — | Настройки обфускации UDP-пакетов: `salamander` или `gecko` (см. таблицу ниже). |
| `network` | `string` \| `string[]` | `["tcp", "udp"]` | Разрешённые транспортные сети (`"tcp"`, `"udp"`). |
| `bbr_profile` | `string` | `"standard"` | Профиль BBR (используется, когда Brutal не задан): `"standard"`, `"conservative"` или `"aggressive"`. |
| `brutal_debug` | `boolean` | `false` | Включает информационное логирование параметров Brutal при инициализации. |
| `disable_chrome_parrot` | `boolean` | `false` | Принимается валидатором для совместимости схемы. |
| `realm` | `object` | — | Параметры discovery/NAT traversal (`server_url`, `token`, `realm_id`, `stun_servers`, `ip_version`, `port_mapping`, `http_client`). Конфликтует с `server`/`server_port`/`server_ports`. В v0.6.2 поддерживается валидатором, но не реализован в runtime. |
| `tls` | `object` | — | **Обязательно:** `tls.enabled: true`. Если `tls.insecure` не `true`, требуется непустой `server` или `tls.server_name`. |
| *Общие поля QUIC* | — | — | См. таблицу «Общие поля QUIC» выше. |
| *Поля `dialer`* | — | — | Стандартные поля диалера, включая `finalmask` (см. ниже). |

### Объект `obfs` (Salamander и Gecko) и `finalmask`

| Поле `obfs` | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | — | `"salamander"` (BLAKE2b-маскирование каждого UDP-пакета) или `"gecko"` (дополнительная фрагментация и выравнивание размера пакетов поверх Salamander). |
| `password` | `string` | — | Обязательно: непустой ключ обфускации. |
| `min_packet_size` | `integer` | `512` | Только для `gecko`: минимальный размер UDP-пакета в байтах (`1..=max_packet_size`). |
| `max_packet_size` | `integer` | `1200` | Только для `gecko`: максимальный размер UDP-пакета в байтах (`min_packet_size..=2048`). |

На уровне `dialer` аутбаунд также принимает объект `finalmask` (`tcp`, `udp`, `quicParams`/`quic_params`), в том числе записи `udphop`/`udp_hop` для совместимости с конфигурациями и URI-подписками. В нативной конфигурации Hysteria2 предпочтительно использовать встроенные поля `obfs` (`salamander` / `gecko`) и `server_ports` / `hop_interval` / `hop_interval_max`.

### Пример

```json
{
  "type": "hysteria2",
  "tag": "hy2-gecko",
  "server": "hy2.example.com",
  "server_ports": ["20000:30000"],
  "hop_interval": "20s",
  "hop_interval_max": "45s",
  "up_mbps": 100,
  "down_mbps": 300,
  "password": "hy2-auth-password",
  "bbr_profile": "standard",
  "brutal_debug": false,
  "obfs": {
    "type": "gecko",
    "password": "obfs-shared-secret",
    "min_packet_size": 512,
    "max_packet_size": 1200
  },
  "tls": {
    "enabled": true,
    "server_name": "hy2.example.com"
  }
}
```

---

## `hysteria`

Клиент устаревшей первой версии протокола Hysteria (v1).

> **Статус поддержки:** тип `hysteria` и все поля ниже проверяются валидатором (`tachyon-core check`), но в runtime v0.6.2 не реализованы. Для рабочих развёртываний используйте `hysteria2`.

### Поддерживаемые поля (валидация схемы)

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | — | Обязательно: `"hysteria"`. |
| `tag` | `string` | `""` | Уникальный тег аутбаунда. |
| `server` | `string` | — | Адрес сервера. |
| `server_port` | `integer` | — | Порт сервера. |
| `server_ports` | `string` \| `string[]` | — | Диапазоны портов для ротации. |
| `hop_interval` | `duration` | — | Интервал смены порта. |
| `up` / `up_mbps` | `string` / `integer` | — | Обязательно хотя бы одно из полей: скорость отдачи. |
| `down` / `down_mbps` | `string` / `integer` | — | Обязательно хотя бы одно из полей: скорость приёма. |
| `obfs` | `string` | `""` | Строка обфускации Hysteria v1. |
| `auth` / `auth_str` | `string` | `""` | Данные аутентификации (Base64 или строка). |
| `recv_window_conn` | `integer` | — | Окно приёма QUIC-соединения. |
| `recv_window` | `integer` | — | Окно приёма потока. |
| `disable_mtu_discovery` | `boolean` | `false` | Отключение PMTUD. |
| `network` | `string` \| `string[]` | `["tcp", "udp"]` | Разрешённые сети (`"tcp"`, `"udp"`). |
| `tls` | `object` | — | **Обязательно:** `tls.enabled: true`. |
| *Общие поля QUIC и `dialer`* | — | — | См. таблицы общих параметров. |

---

## `tuic`

Клиент протокола TUIC v5 поверх QUIC с аутентификацией EKM (TLS Exporter), поддержкой 0-RTT и тремя режимами передачи UDP.

### Поддерживаемые поля

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | — | Обязательно: `"tuic"`. |
| `tag` | `string` | `""` | Уникальный тег аутбаунда. |
| `server` | `string` | — | Обязательно: адрес сервера. |
| `server_port` | `integer` | — | Обязательно: порт сервера (`1..=65535`). |
| `uuid` | `string` | — | Обязательно: валидный UUID пользователя. |
| `password` | `string` | — | Обязательно: пароль пользователя. |
| `congestion_control` | `string` | `"cubic"` | Алгоритм управления перегрузкой: `"cubic"`, `"new_reno"` или `"bbr"`. |
| `udp_relay_mode` | `string` | `"native"` | Режим ретрансляции UDP: `"native"` (QUIC-дейтаграммы RFC 9221) или `"quic"` (однонаправленные QUIC-потоки). Конфликтует с `udp_over_stream: true`. |
| `udp_over_stream` | `boolean` | `false` | При `true` передаёт UDP внутри TCP CONNECT-потока с фреймингом UoT. Не может задаваться одновременно с непустым `udp_relay_mode`. |
| `zero_rtt_handshake` | `boolean` | `false` | Включает QUIC 0-RTT handshake. |
| `heartbeat` | `duration` | `"10s"` | Интервал отправки TUIC-пакетов heartbeat. |
| `network` | `string` \| `string[]` | `["tcp", "udp"]` | Разрешённые транспортные сети (`"tcp"`, `"udp"`). |
| `tls` | `object` | — | **Обязательно:** `tls.enabled: true`. Если `tls.insecure` не `true`, требуется непустой `server` или `tls.server_name`. |
| *Общие поля QUIC и `dialer`* | — | — | См. таблицы общих параметров. |

### Пример

```json
{
  "type": "tuic",
  "tag": "tuic-v5",
  "server": "tuic.example.com",
  "server_port": 443,
  "uuid": "11111111-2222-3333-4444-555555555555",
  "password": "tuic-password",
  "congestion_control": "bbr",
  "udp_relay_mode": "native",
  "zero_rtt_handshake": true,
  "heartbeat": "10s",
  "tls": {
    "enabled": true,
    "server_name": "tuic.example.com",
    "alpn": ["h3"]
  }
}
```

---

## `masque`

Клиент IP-туннелирования MASQUE (RFC 9484 CONNECT-IP) с поддержкой профиля Cloudflare WARP (`cloudflare`) и стандартного RFC 9484 (`standard`). Поверх туннеля работает встроенный userspace IP-стек, обеспечивающий передачу TCP и UDP без создания системного TUN-интерфейса.

### Поддерживаемые поля

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | — | Обязательно: `"masque"`. |
| `tag` | `string` | `""` | Уникальный тег аутбаунда. |
| `server` | `string` | — | Обязательно: адрес конечной точки MASQUE / WARP. |
| `server_port` | `integer` | — | Обязательно: порт сервера (`1..=65535`). |
| `profile` | `string` | `"cloudflare"` | Профиль протокола: `"cloudflare"` (WARP, протокол `cf-connect-ip`, пиннинг публичного ECDSA-ключа) или `"standard"` (стандартный RFC 9484 `connect-ip`). |
| `vhttp` | `string` | `"auto"` | Версия HTTP-носителя: `"h3"` (HTTP/3 QUIC), `"h2"` (HTTP/2 TCP, только для `cloudflare`) или `"auto"` (для `cloudflare` — приоритет H3 с откатом на H2; для `standard` — только H3). |
| `uri` | `string` | `"https://cloudflareaccess.com"` (для `cloudflare`) | URI запроса CONNECT-IP. **Обязательно** для `profile: "standard"` (например, `"https://host/.well-known/masque/ip/*/*/"`). |
| `private_key` | `string` | `""` | Приватный ECDSA-ключ клиента в Base64 (DER). Обязателен для `profile: "cloudflare"`. |
| `public_key` | `string` | `""` | Публичный ECDSA-ключ сервера в Base64 (PKIX DER) для проверки подлинности. Обязателен для `profile: "cloudflare"`. |
| `ip` | `string` | `""` | Локальный IPv4-адрес или CIDR внутри туннеля (например, `"172.16.0.2/32"`). Обязателен хотя бы один из `ip` или `ipv6`. |
| `ipv6` | `string` | `""` | Локальный IPv6-адрес или CIDR внутри туннеля (например, `"2606:4700:110::2/128"`). |
| `mtu` | `integer` | `1280` | MTU внутреннего IP-туннеля. Для `vhttp: "h2"` и `"auto"` не может превышать `16000`. |
| `network_list` | `string` \| `string[]` | `["tcp", "udp"]` | Разрешённые транспортные сети (`"tcp"`, `"udp"`). |
| `idle_timeout` | `duration` | — | Таймаут простоя туннеля (отрицательное значение или `null` отключает). |
| `keep_alive_period` | `duration` | По умолчанию включён | Интервал keepalive-проверок туннеля (отрицательное значение отключает). |
| `quic_migration` | `boolean` | `true` | Разрешает миграцию QUIC-сокета. |
| `quic_rebind_interval` | `duration` | — | Период перепривязки локального UDP-сокета QUIC. |
| `tls` | `object` | — | Объект клиентского TLS (например, `server_name`, `certificate`, `insecure`). |
| `network` | `string` | `""` | Устаревший алиас `vhttp` (при конфликте с `vhttp` возвращается ошибка). |
| `sni` | `string` | `""` | Устаревший алиас `tls.server_name` (при конфликте возвращается ошибка). |
| `skip_cert_verify` | `boolean` | `false` | Устаревший алиас `tls.insecure`. |
| `fragment` / `record_fragment` / `fragment_fallback_delay` | `boolean`\|`object` / `boolean` / `duration` | — | Принимаются валидатором; в runtime MASQUE не применяются (выдаётся предупреждение). |
| *Поля `dialer`* | — | — | Стандартные поля диалера. |

### Пример (Cloudflare WARP)

```json
{
  "type": "masque",
  "tag": "warp-masque",
  "server": "162.159.198.1",
  "server_port": 443,
  "profile": "cloudflare",
  "vhttp": "auto",
  "ip": "172.16.0.2/32",
  "ipv6": "2606:4700:110:8a00::2/128",
  "private_key": "Base64EncodedEcPrivateKeyDer",
  "public_key": "Base64EncodedServerEcdsaPublicKeyDer",
  "mtu": 1280,
  "tls": {
    "enabled": true,
    "server_name": "consumer-masque.cloudflareclient.com"
  }
}
```

---

## `mieru`

Клиент протокола Mieru v3 с шифрованным транспортом поверх TCP или UDP, поддержкой многопортовых диапазонов и шаблонов трафика (`traffic_pattern`). Переносит TCP и UDP.

### Поддерживаемые поля

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | — | Обязательно: `"mieru"`. |
| `tag` | `string` | `""` | Уникальный тег аутбаунда. |
| `server` | `string` | — | Обязательно: адрес сервера. |
| `server_port` | `integer` | — | Порт сервера (`1..=65535`). Обязателен, если не заданы `server_ports`, `listen_port` или `listen_ports`. |
| `server_ports` | `string` \| `(string\|integer)[]` | — | Один или несколько портов/диапазонов (до 256 записей; форматы `"2090"`, `"2090-2099"`, `"2090:2099"`). |
| `listen_port` / `listen_ports` | `integer` / `string`\|`array` | — | Совместимые алиасы для `server_port` / `server_ports`. |
| `transport` | `string` | `"TCP"` | Несущий транспорт до сервера: `"TCP"` или `"UDP"` (регистронезависимо). |
| `username` | `string` | — | Обязательно (либо через `users[0].name`): имя пользователя. |
| `password` | `string` | — | Обязательно (либо через `users[0].password`): пароль пользователя. |
| `users` | `object[]` | — | Альтернативная форма задания учётных данных (берётся первый элемент с полями `name`/`username` и `password`). |
| `mtu` | `integer` | `1400` | MTU для UDP-транспорта (`576..=9000`). |
| `traffic_pattern` | `string` | `""` | Закодированный в Base64 шаблон формирования трафика Mieru. |
| `multiplexing` | `string` | `""` | Принимается валидатором для совместимости конфигурации. |
| `handshake_mode` | `string` | `""` | Принимается валидатором для совместимости конфигурации. |
| `user_hint_is_mandatory` | `boolean` | `false` | Принимается валидатором для совместимости конфигурации. |
| *Поля `dialer`* | — | — | Стандартные поля диалера. |

### Пример

```json
{
  "type": "mieru",
  "tag": "mieru-out",
  "server": "mieru.example.com",
  "server_ports": ["2010-2020"],
  "transport": "UDP",
  "username": "alice",
  "password": "mieru-secret-password",
  "mtu": 1400
}
```

---

## `tewfai`

Мульти-транспортный туннельный клиент TewFai с поддержкой носителей TCP (TLS / REALITY) и QUIC (HTTP/3 ALPN), переключения носителей без разрыва сессии (make-before-break `handover`), профилей морфинга трафика (`morph_profile`), шейпера (`shaper`), FEC и постквантового обмена ключами (`pqc`). Поддерживает TCP и UDP.

### Поддерживаемые поля

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | — | Обязательно: `"tewfai"`. |
| `tag` | `string` | `""` | Уникальный тег аутбаунда. |
| `server` | `string` | — | Обязательно: адрес сервера. |
| `server_port` | `integer` | — | Обязательно: порт сервера (`1..=65535`). |
| `uuid` | `string` | — | Секрет аутентификации (обязателен `uuid` или `password`). |
| `password` | `string` | — | Альтернативный способ задания общего секрета, если не указан `uuid`. |
| `transport` | `string` \| `string[]` | `["tcp"]` | Список несущих транспортов в порядке приоритета: `"tcp"`, `"quic"` или оба (`["quic", "tcp"]`). Повторы не допускаются. |
| `inner_cipher` | `string` | `"aes-256-gcm"` | Внутреннее шифрование кадров: `"aes-256-gcm"` или `"null"` / `"none"`. |
| `morph_profile` | `string` | `"auto"` | Профиль распределения размеров кадров: `"auto"` (алиасы `"adaptive"`, `"transformer"`, `""`), `"browsing"`, `"video"`, `"webrtc"` или `"bulk"`. |
| `max_streams` | `integer` | `256` | Максимум мультиплексируемых потоков на одну сессию (`1..=4096`). |
| `mtu` | `integer` | `16381` | Максимальный размер полезной нагрузки кадра (`256..=16381`). |
| `fec` | `boolean` | `false` | Включает прямую коррекцию ошибок (Forward Error Correction). |
| `pqc` | `boolean` | `false` | Включает постквантовый обмен ключами при рукопожатии сессии. |
| `desync` | `boolean` | `false` | Включает встроенные приёмы пакетной десинхронизации на TCP-носителе. |
| `tls` | `object` | — | Стандартный объект клиентского TLS (для TCP-носителя и по умолчанию для QUIC). |
| `fingerprint` | `string` | `""` | Сокращённая запись для `tls.utls.fingerprint` (работает, если объект `tls` не задан явно). |
| `reality` | `object` | — | Сокращённая запись для `tls.reality` (если объект `tls` не задан явно). |
| `server_name` / `sni` | `string` | `""` | Сокращённое задание SNI при использовании `fingerprint` / `reality` без явного блока `tls`. |
| `quic` | `object` | — | Настройки QUIC-носителя (если `"quic"` указан в `transport`): `up_mbps` (целое, 0 — BBR, > 0 — Brutal), `server_ports`, `hop_interval` (секунды, по умолчанию 30 при `server_ports`), `hop_interval_max` (секунды), отдельный объект `tls` и общие поля QUIC. |
| `handover` | `boolean` \| `object` | — | Управление горячим переключением носителей (см. таблицу ниже). |
| `shaper` | `boolean` \| `object` | — | Управление сглаживанием скорости передачи (см. таблицу ниже). |
| *Поля `dialer`* | — | — | Стандартные поля диалера. |

### Объекты `handover` и `shaper`

| Объект / Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `handover.enabled` | `boolean` | `true` (если передан объект) | Включает автоматическое переключение носителей без разрыва потоков. |
| `handover.grace_secs` | `integer` | `60` | Время (в секундах), в течение которого старый носитель удерживается для завершения текущих кадров. |
| `handover.timeout_ms` | `integer` | `10000` | Таймаут установки нового носителя в миллисекундах (`250..=60000`). |
| `handover.rotate_secs` | `integer` | `0` | Периодическая плановая ротация носителя по времени в секундах (`0` — отключено). |
| `handover.rotate_mb` | `integer` | `0` | Плановая ротация носителя по объёму переданных данных в МБ (`0` — отключено). |
| `shaper.mode` | `string` | `"off"` | Режим шейпера: `"off"`, `"adaptive"` или `"fixed"`. |
| `shaper.rate_mbps` | `integer` | `50` | Целевая скорость в Мбит/с для режима `"fixed"`. |
| `shaper.quantum_ms` | `integer` | `10` | Квант времени планировщика в миллисекундах. |

### Пример

```json
{
  "type": "tewfai",
  "tag": "tewfai-out",
  "server": "tewfai.example.com",
  "server_port": 443,
  "uuid": "11111111-2222-3333-4444-555555555555",
  "transport": ["quic", "tcp"],
  "inner_cipher": "aes-256-gcm",
  "morph_profile": "auto",
  "pqc": true,
  "handover": {
    "enabled": true,
    "grace_secs": 60,
    "timeout_ms": 10000
  },
  "shaper": {
    "mode": "adaptive",
    "quantum_ms": 10
  },
  "tls": {
    "enabled": true,
    "server_name": "tewfai.example.com",
    "utls": {
      "enabled": true,
      "fingerprint": "chrome"
    }
  },
  "quic": {
    "server_ports": ["20000:25000"],
    "hop_interval": 30
  }
}
```

---

## `fptn`

Клиент туннеля FPTN (аутентификация JWT по HTTPS, передача IP-пакетов через WebSocket `/api/v1/fptn` в бинарных кадрах с пакетной сериализацией Protobuf и поддержкой формата YaFF, встроенный userspace IP-стек для TCP и UDP).

Поддерживаются две формы описания аутбаунда: **токен-подписка** (`token`) и **прямая серверная запись** (`server`).

### Форма 1: токен-подписка (`fptn:` / `fptnb:`)

При указании `token` вместо `server` движок автоматически декодирует токен (`fptn:` / `fptn://` — Base64 JSON; `fptnb:` / `fptnb//` — Brotli + Base64 JSON) и разворачивает его при загрузке конфигурации в:
1. отдельные аутбаунды `type: "fptn"` для каждого сервера из токена с тегами `<tag>/<server.name>` (все поля `dialer`, `obfuscation`, `sni`, `mtu`, `network_list` копируются на каждый узел);
2. группу `urltest` с тегом `<tag>-urltest`, объединяющую все развёрнутые узлы;
3. группу `selector` с исходным `tag` и `"default": "<tag>-urltest"` (чтобы тег оставался переключаемым в Clash API и веб-интерфейсах).

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | — | Обязательно: `"fptn"`. |
| `tag` | `string` | `"fptn"` | Тег итогового `selector` и префикс для развёрнутых серверов. |
| `token` | `string` | — | Обязательно: токен подписки с префиксом `fptn:`, `fptn://`, `fptnb:` или `fptnb//`. (Формат `fptnb:` требует поддержки Brotli в сборке.) |
| `obfuscation` / `bypass_method` | `string` | `"tls"` | Стратегия маскировки рукопожатия, применяемая ко всем серверам из токена (см. ниже). |
| `sni` | `string` | — | Переопределение SNI для всех серверов токена. |
| `mtu` | `integer` | `16384` | MTU внутреннего IP-туннеля. |
| `network_list` | `string` \| `string[]` | `["tcp", "udp"]` | Разрешённые транспортные сети (`"tcp"`, `"udp"`). |
| *Поля `dialer`* | — | — | Копируются на каждый развёрнутый сервер. |

### Форма 2: прямой сервер FPTN

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | — | Обязательно: `"fptn"`. |
| `tag` | `string` | `""` | Уникальный тег аутбаунда. |
| `server` | `string` | — | Обязательно: хост или IP сервера FPTN. |
| `server_port` | `integer` | — | Обязательно: порт сервера (`1..=65535`). |
| `username` | `string` | — | Обязательно: имя пользователя. |
| `password` | `string` | — | Обязательно: пароль пользователя. |
| `md5_fingerprint` | `string` | `""` | MD5-отпечаток листового сертификата сервера (32 hex-символа). Если пуст — пиннинг отключается. |
| `sni` | `string` | `server` (если это домен) | SNI для TLS-рукопожатия. В режиме `reality` длина `sni` обязательна в диапазоне `4..=64` байт (для IP-адреса в `server` необходимо указать `sni` явно). |
| `obfuscation` / `bypass_method` | `string` | `"tls"` | Стратегия оформления TLS-рукопожатия (см. таблицу ниже). |
| `mtu` | `integer` | `16384` | MTU внутреннего IP-туннеля. |
| `network_list` | `string` \| `string[]` | `["tcp", "udp"]` | Разрешённые транспортные сети (`"tcp"`, `"udp"`). |
| *Поля `dialer`* | — | — | Стандартные поля диалера. |

### Значения `obfuscation` (алиас `bypass_method`)

| Значение | Поведение |
|---|---|
| `"tls"` *(по умолчанию, алиасы `"tls_obfuscator"`, `"kTlsObfuscator"`, `"1"`, `"obfuscation"`, `"split"`, `""`)* | Внешнее обёртывание рукопожатия в кадры TlsObfuscator2. |
| `"none"` *(алиасы `"sni"`, `"kSni"`, `"0"`, `"plain"`, `"auto-sni"`)* | Обычное TLS-рукопожатие со стандартным session-id FPTN. |
| `"reality"` | Режим Reality Mode 2 с браузерным шаблоном Chrome 149 (сначала отправляется маскировочный ClientHello, затем реальное рукопожатие в кадрах TlsObfuscator2). |
| Профили браузеров | Явный выбор шаблона для Reality Mode 2: `reality_chrome145` .. `reality_chrome149`, `reality_firefox149` .. `reality_firefox151`, `reality_yandex24`, `reality_yandex25`, `reality_yandex26_3`, `reality_yandex26_4`, `reality_safari26_4`, `reality_safari26_5` (также принимаются официальные имена `kSniRealityMode*` и числовые коды `20..24`, `60..62`, `80..83`, `100`, `101`). |

Устаревший режим Reality Mode 1 (`"kSniRealityMode"` / `"2"`) отклоняется валидатором и runtime.

### Пример

```json
{
  "type": "fptn",
  "tag": "fptn-sub",
  "token": "fptnb:Base64BrotliTokenPayload",
  "obfuscation": "reality_chrome149",
  "sni": "www.example.com"
}
```

---

## `mtproto`

TCP-аутбаунд MTProto с поддержкой классического фреймированного режима, быстрого режима `mtproxy` и нативного WebSocket-моста Telegram (`telegram-ws` / `kws`). UDP не поддерживается.

### Поддерживаемые поля

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | — | Обязательно: `"mtproto"`. |
| `tag` | `string` | `""` | Уникальный тег аутбаунда. |
| `mode` | `string` | `"mtproto"` | Режим работы: `"mtproto"` (стандартное фреймирование пакетов), `"mtproxy"` (быстрый режим без фреймирования после рукопожатия) или `"telegram-ws"` (алиас `"kws"` — WebSocket-мост к дата-центрам Telegram). |
| `server` | `string` | `"web.telegram.org"` (для `telegram-ws`) | Адрес сервера. Обязателен для `mtproto`/`mtproxy`; в режиме `telegram-ws` может быть опущен или задан пользовательским доменом (поддерживается подстановка `{dc}`). |
| `server_port` | `integer` | `443` (для `telegram-ws`) | Порт сервера (`1..=65535`). Обязателен для `mtproto`/`mtproxy`. |
| `secret` | `string` | `""` | 16-байтовый общий секрет в виде ровно 32 hex-символов (опционален). |
| `transport` | `string` | `"intermediate"` | Фрейминг MTProto (собственный, не V2Ray): `"abridged"`, `"intermediate"`, `"padded_intermediate"` (алиас `"padded-intermediate"`) или `"full"`. |
| `tls` | `object` | Включён автоматически для `telegram-ws` | Опциональная обёртка TLS. |
| *Поля `dialer`* | — | — | Стандартные поля диалера. |

### Особенности режима `telegram-ws` (`kws`)

- Автоматически распознаёт 64-байтовый заголовок `obfuscated2` клиента Telegram (с резервным определением по CIDR целевого IP) для выбора дата-центра (`±1..=±5`).
- Подключается к `wss://kws{dc}[-1].web.telegram.org/apiws` с подпротоколом `binary`.
- Если WebSocket-обновление не удалось или поток не является MTProto `obfuscated2`, выполняет прозрачный откат на прямое TCP-соединение с повторной отправкой начального заголовка, а проблемный дата-центр получает 60-секундный cooldown.

### Пример

```json
{
  "type": "mtproto",
  "tag": "tg-kws",
  "mode": "telegram-ws"
}
```

---

## `openconnect`

Клиент корпоративных SSL-VPN протоколов семейства OpenConnect поверх TLS с поддержкой режимов CSTP, userspace IP (`ip`), IPsec ESP (`esp`) и DTLS (`dtls`).

> **Важно:** рабочий клиент OpenConnect конфигурируется в секции **`outbounds`** (`"type": "openconnect"`). В секции `endpoints` тип `openconnect` поддерживается только на уровне проверки схемы (`tachyon-core check`).

### Поддерживаемые поля

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | — | Обязательно: `"openconnect"`. |
| `tag` | `string` | `"openconnect"` | Уникальный тег аутбаунда. |
| `server` | `string` | — | Обязательно: адрес VPN-шлюза. |
| `server_port` | `integer` | — | Обязательно: порт шлюза (`1..=65535`). |
| `flavor` | `string` | `"anyconnect"` | Диалект шлюза: `"anyconnect"` (Cisco AnyConnect / ocserv), `"gp"` (Palo Alto GlobalProtect), `"nc"` (Juniper Network Connect), `"pulse"` (Pulse Secure / Ivanti), `"f5"` (F5 BIG-IP) или `"fortinet"` (Fortinet FortiGate). |
| `cookie` | `string` | `""` | Сессионная cookie, полученная после аутентификации (CSTP / GlobalProtect / F5 / Fortinet). |
| `username` | `string` | `""` | Имя пользователя (обязательно для `flavor: "pulse"`). |
| `password` | `string` | `""` | Пароль пользователя (обязательно для `flavor: "pulse"`). |
| `new_password` | `string` | `""` | Новый пароль при требовании смены пароля шлюзом Pulse. |
| `realm` | `string` | `""` | Имя realm для шлюзов Pulse. |
| `region` | `string` | `""` | Имя региона для шлюзов Pulse. |
| `user_agent` | `string` | `"Mozilla/5.0 (X11; Linux x86_64) openconnect"` | Заголовок `User-Agent`. |
| `local_hostname` | `string` | `"openconnect"` | Локальное имя хоста, передаваемое шлюзу. |
| `urlpath` | `string` | Зависит от `flavor` | Путь туннеля (по умолчанию `"/ssl-tunnel-connect.sslvpn"` для `gp`, `"/myvpn"` для `f5`, `"/remote/sslvpn-tunnel"` для `fortinet`). |
| `tunnel` | `string` | `"sess=&hdlc_framing=no&ipv4=yes&ipv6=yes&Z="` | Строка параметров туннеля для `f5`. |
| `address` | `string` | Выдаётся шлюзом / `10.10.10.2` | Внутренний IPv4-адрес клиента в туннеле. |
| `address_v6` | `string` | — | Внутренний IPv6-адрес клиента в туннеле. |
| `mtu` | `string` \| `integer` | `1400` | MTU туннеля (при проверке строгим валидатором схемы ожидается строковый тип или отсутствие поля; в runtime читается целое число). |
| `ip` | `boolean` | `false` | Включает userspace IP-стек поверх туннеля (обеспечивает TCP и UDP внутри IP-канала). |
| `esp` | `boolean` | `false` | Включает UDP-инкапсуляцию ESP поверх туннеля. Требует `ip: true`. |
| `esp_gateway` | `string` | — | Переопределение IP-адреса шлюза для ESP-проб (задаётся только парой с `esp_client` того же семейства адресов). |
| `esp_client` | `string` | — | Переопределение клиентского IP-адреса для ESP-проб (только парой с `esp_gateway`). |
| `dtls` | `boolean` | `false` | Включает транспорт DTLS поверх UDP. Допустим только для `flavor: "anyconnect"`. |
| `hip_report` | `boolean` | `true` | Отправлять HIP-отчёт по запросу шлюза GlobalProtect (`gp`). |
| `server_cert_pin` | `string` | `""` | Пиннинг открытого ключа сертификата шлюза (формат `pin-sha256:...`). |
| `tls` | `object` | — | **Обязательно:** `tls.enabled: true`. |
| *Поля `dialer`* | — | — | Стандартные поля диалера. |

### Пример

```json
{
  "type": "openconnect",
  "tag": "corp-vpn",
  "server": "vpn.example.com",
  "server_port": 443,
  "flavor": "anyconnect",
  "cookie": "webvpn-session-cookie",
  "ip": true,
  "dtls": true,
  "server_cert_pin": "pin-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  "tls": {
    "enabled": true,
    "server_name": "vpn.example.com"
  }
}
```

---

## `trusttunnel`

Клиент протокола TrustTunnel поверх HTTP/2 (`CONNECT` over TLS) или HTTP/3 (`quic: true`). Поддерживает TCP, UDP (мультиплексирование дейтаграмм через псевдо-хост `_udp2`) и ICMP echo.

### Поддерживаемые поля

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | — | Обязательно: `"trusttunnel"`. |
| `tag` | `string` | `""` | Уникальный тег аутбаунда. |
| `server` | `string` | — | Обязательно: адрес сервера. |
| `server_port` | `integer` | — | Обязательно: порт сервера (`1..=65535`). |
| `username` | `string` | `""` | Логин HTTP Basic-аутентификации (задаётся строго парой с `password`). |
| `password` | `string` | `""` | Пароль HTTP Basic-аутентификации (задаётся строго парой с `username`). |
| `quic` | `boolean` \| `string` | `false` | При `true` (или `"true"` / `"1"`) работает поверх HTTP/3 QUIC; по умолчанию использует HTTP/2 поверх TCP. |
| `quic_congestion_control` | `string` | `"cubic"` | Алгоритм управления перегрузкой для режима `quic: true`: `"cubic"`, `"bbr"`, `"bbr2"` или `"reno"`. |
| `health_check` | `boolean` | `false` | Принимается валидатором для совместимости схемы. |
| `network` | `string` \| `string[]` | `["tcp", "udp"]` | Разрешённые транспортные сети (`"tcp"`, `"udp"`). |
| `tls` | `object` | — | **Обязательно:** `tls.enabled: true`. |
| *Общие поля QUIC и `dialer`* | — | — | См. таблицы общих параметров. |

### Пример

```json
{
  "type": "trusttunnel",
  "tag": "trusttunnel-h3",
  "server": "tt.example.com",
  "server_port": 443,
  "username": "user",
  "password": "secret",
  "quic": true,
  "quic_congestion_control": "bbr",
  "tls": {
    "enabled": true,
    "server_name": "tt.example.com"
  }
}
```

---

## `wdtt`

Нативный userspace-клиент туннеля WDTT / qWDTT / CSQTT поверх TURN/WebRTC/SRTP со встроенным IP-стеком (поддерживает TCP и UDP без системного TUN-интерфейса).

### Поддерживаемые поля

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | — | Обязательно: `"wdtt"`. |
| `tag` | `string` | `""` | Уникальный тег аутбаунда. |
| `server` | `string` | — | Обязательно: адрес удалённого сервера WDTT. |
| `server_port` | `integer` | `56000` (`wg`/`raw`), `46000` (`csqtt`/`csqtt_v1`) | Базовый порт сервера (`1..=65535`). |
| `raw_port` | `integer` | `server_port` | Порт сервера для режима `mode: "raw"` (`1..=65535`). |
| `wg_port` | `integer` | — | Опциональный порт WireGuard-слоя (`1..=65535`). |
| `local_port` | `integer` | — | Опциональный локальный порт (`1..=65535`). |
| `password` | `string` | — | Обязательно: общий пароль сессии. |
| `mode` | `string` | `"wg"` | Режим протокола: `"wg"`, `"raw"`, `"csqtt"` или `"csqtt_v1"`. |
| `obfs` | `string` | `"audio"` | Профиль медиа-кадрирования пакетов: `"audio"`, `"video"` или `"unified"`. |
| `srtp_mode` | `string` | `"auto"` | Режим защиты медиапотока: `"auto"`, `"dtls"` (алиас `"dtls-srtp"`) или `"wrap"` (алиас `"wrap-srtp"`). |
| `hashes` | `string` \| `string[]` | `[]` | Идентификаторы комнат/ссылок для получения динамических TURN-учётных данных (строка с разделителями или массив строк). |
| `vk_auth_mode` | `string` | `"vkcalls"` | Провайдер получения TURN-учётных данных: `"vkcalls"`, `"legacy"`, `"cookie"`, `"oneme"`, `"max"`, `"yandex"` или `"telemost"`. |
| `vk_cookie` | `string` | `""` | Cookie для провайдера авторизации (`vk_auth_mode: "cookie"`). |
| `vk_token` | `string` | `""` | Токен авторизации для получения TURN-учётных данных. |
| `vk_client_ids` | `string` \| `string[]` | `[]` | Список идентификаторов клиентов для провайдера авторизации. |
| `turn_server` / `turn_urls` | `string` \| `string[]` | `[]` | Явный список адресов/URL TURN-серверов (статическая конфигурация TURN). |
| `turn_username` | `string` | `""` | Имя пользователя статического TURN-сервера. |
| `turn_password` | `string` | `""` | Пароль статического TURN-сервера. |
| `turn_transport` | `string` | `"auto"` | Транспорт подключения к TURN-серверу: `"auto"`, `"tcp"`, `"udp"` или `"tcp_tls"` (алиас `"tls"`). |
| `workers` | `integer` | `1` (прямой), `4` (`csqtt`), `18` (TURN) | Количество параллельных воркеров/каналов (`1..=126`). |
| `device_id` | `string` | Вычисляется детерминированно | Идентификатор устройства для сессии. |
| `mtu` | `integer` | `1280` | MTU внутреннего туннеля (`576..=1500`). |
| `chunk1` | `boolean` | `true` | Включает однофрагментный режим разбиения полезной нагрузки. |
| `wg_private_key` | `string` | `""` | Опциональный приватный ключ WireGuard (для режима `wg`). |
| `wg_peer_public_key` | `string` | `""` | Опциональный публичный ключ удалённого пира (для режима `wg`). |
| `wg_address` | `string` | `""` | Опциональный адрес клиента внутри WireGuard-туннеля. |
| *Поля `dialer`* | — | — | Стандартные поля диалера. |

### Пример

```json
{
  "type": "wdtt",
  "tag": "wdtt-out",
  "server": "203.0.113.30",
  "server_port": 46000,
  "password": "wdtt-session-password",
  "mode": "csqtt",
  "obfs": "audio",
  "srtp_mode": "auto",
  "turn_urls": ["turn:turn.example.com:3478?transport=tcp"],
  "turn_username": "turn-user",
  "turn_password": "turn-password",
  "turn_transport": "tcp",
  "workers": 4,
  "mtu": 1280
}
```

---

## Туннели, настраиваемые в секции `endpoints`

Ряд L3-туннелей в `tachyon-core` описывается не в массиве `outbounds`, а в корневом массиве `endpoints`. После инициализации каждый такой endpoint регистрируется в маршрутизаторе по своему `tag` и используется в `route.rules`, `selector`, `urltest`, `chain` и `detour` точно так же, как любой аутбаунд (с поддержкой TCP и UDP). Полные таблицы их полей приведены в [Конечных точках (`endpoints`)](../endpoints.md).

### `wireguard` (`endpoints`)

Устаревший формат `{"type": "wireguard", ...}` внутри массива **`outbounds` удалён** и отклоняется валидатором с требованием перенести описание в секцию `endpoints`.

В секции `endpoints` (`"type": "wireguard"`) поддерживаются стандартный WireGuard и расширения AmneziaWG 2.0/3.x (параметры обфускации `jc`/`jmin`/`jmax`/`s1`–`s4`/`h1`–`h4`/`i1`–`i5`, ротация портов, режим userspace и системный режим). Подробная схема приведена в [Конечных точках (`endpoints`)](../endpoints.md).

### `openvpn-client`

Клиент OpenVPN настраивается в секции `endpoints` с `"type": "openvpn-client"` (не в `outbounds`).

- В runtime v0.6.2 поддерживается userspace-режим с предварительным ключом (`"mode": "static_key"`, `static_key` / `static_key_path`, TCP и UDP, резервный список `servers`, `remote_random`, `mtu`, `cipher`, `auth`, `mss_fix`, `replay_window`, `ping_interval`, `ping_restart`).
- Режим `"mode": "tls"` и системный интерфейс `"system": true` проверяются валидатором схемы, но в текущем runtime не реализованы.

### `tailscale`

Tailscale не поддерживается как отдельный тип в массиве `outbounds` — он настраивается в секции `endpoints` с `"type": "tailscale"`.

- В runtime поддерживаются userspace-режим (Noise_IK, WireGuard mesh, DERP-ретрансляторы), подсетевые маршруты, анонсирование и использование удалённых exit node; созданный endpoint маршрутизируется по своему `tag` для TCP и UDP.
- Системный интерфейс (`system_interface: true`), Taildrop и размещение собственного ретранслятора в текущем runtime не поддерживаются.
- Полная спецификация полей приведена в [Конечных точках (`endpoints`)](../endpoints.md).
