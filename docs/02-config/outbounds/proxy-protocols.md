# Прокси-протоколы (`outbounds`)

В этом разделе приведена спецификация клиентских прокси-аутбаундов: `vless`, `vmess`, `trojan`, `shadowsocks`, `anytls`, `shadowtls`, `naive`, `snell`, а также типов с поддержкой валидации схемы (`ssh`, `tor`, `sudoku`).

Поля `dialer`, `tls` (включая `utls`, `reality`, `ech`), `transport` (`http`, `ws`, `quic`, `grpc`, `httpupgrade`, `xhttp`), `multiplex` (`h2mux`, `smux`, `yamux`) и `udp_over_tcp` описаны подробно в [Общих объектах конфигурации](../common-objects.md).

---

## `vless`

Клиент протокола VLESS с поддержкой потока `xtls-rprx-vision`, постквантового шифрования `mlkem768x25519plus`, TLS / REALITY / uTLS, всех транспортов V2Ray (включая `xhttp`), мультиплексирования и трёх режимов кодирования UDP-пакетов.

### Поддерживаемые поля

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | — | Обязательно: `"vless"`. |
| `tag` | `string` | `""` | Уникальный тег аутбаунда. |
| `server` | `string` | — | Обязательно: адрес сервера. |
| `server_port` | `integer` | — | Обязательно: порт сервера (`1..=65535`). |
| `uuid` | `string` | — | Обязательно: идентификатор пользователя (стандартный UUID с дефисами, 32 hex-символа или произвольная строка, преобразуемая в UUIDv5). |
| `flow` | `string` | `""` | Режим потока: `""`, `"none"`, `"xtls-rprx-vision"` или `"xtls-rprx-vision-udp443"`. Применяется к TCP и XUDP, не применяется к простому UDP. |
| `encryption` | `string` | `"none"` | Шифрование VLESS на уровне протокола: `""` / `"none"` или строка спецификации `mlkem768x25519plus` (см. формат ниже). |
| `network` | `string` \| `string[]` | `["tcp", "udp"]` | Разрешённые транспортные сети (`"tcp"`, `"udp"`). |
| `packet_encoding` | `string` | `"xudp"` | Режим передачи UDP-дейтаграмм: `"xudp"` (по умолчанию, когда поле отсутствует), `"packetaddr"` (адресация в каждом пакете через `sp.packet-addr.v2fly.arpa`) или `""` (простое обрамление длины `[len:u16][payload]`). |
| `tls` | `object` | — | Клиентский объект TLS (поддерживает uTLS, REALITY X25519 и постквантовый REALITY `X25519MLKEM768`, ECH). |
| `transport` | `object` | — | V2Ray-транспорт (`http`, `ws`, `quic`, `grpc`, `httpupgrade`, `xhttp`). Транспорт `quic` требует `tls.enabled: true`. |
| `multiplex` | `object` | — | Настройки мультиплексирования (`h2mux`, `smux`, `yamux`). |
| *Поля `dialer`* | — | — | Стандартные поля диалера. |

### Формат строки `encryption` (`mlkem768x25519plus`)

Поле `encryption` позволяет включить аутентифицированное шифрование и постквантовый обмен ключами (X25519 + ML-KEM-768) непосредственно на уровне VLESS — как самостоятельно, так и в сочетании с TLS/REALITY и `xtls-rprx-vision`.

Синтаксис клиентской строки:

```text
mlkem768x25519plus.<appearance>.<rtt>[.<padding_block>...].<key>[.<key>...]
```

| Сегмент | Допустимые значения | Назначение |
|---|---|---|
| Метод | `mlkem768x25519plus` | Единственный поддерживаемый метод. |
| `<appearance>` | `native`, `xorpub`, `random` | Оформление заголовков AEAD на линии: стилизованное под записи TLS 1.3 (`native`), маскированное XOR публичными ключами (`xorpub`) или полностью псевдослучайное (`random`). |
| `<rtt>` | `0rtt`, `1rtt` | Режим рукопожатия: `0rtt` (повторное использование тикета сессии) или `1rtt` (полное рукопожатие для каждого подключения). |
| `<padding_block>` | `prob-from-to` (опционально, один или несколько через точку) | Блоки вероятностного дополнения и пауз (чётные индексы — длины в байтах, нечётные — интервалы). Для первого блока требуются `prob >= 100` и длины `>= 35`; суммарная максимальная длина всех блоков не превышает `65553` байт. |
| `<key>` | Base64 URL-safe без `=` (один или несколько) | Публичные ключи сервера: 32 байта (X25519) и/или 1184 байта (ML-KEM-768). |

### Примеры

VLESS + REALITY + Vision:

```json
{
  "type": "vless",
  "tag": "vless-reality",
  "server": "203.0.113.10",
  "server_port": 443,
  "uuid": "11111111-2222-3333-4444-555555555555",
  "flow": "xtls-rprx-vision",
  "packet_encoding": "xudp",
  "tls": {
    "enabled": true,
    "server_name": "www.example.com",
    "utls": {
      "enabled": true,
      "fingerprint": "chrome"
    },
    "reality": {
      "enabled": true,
      "public_key": "Base64UrlServerPublicKeyHere",
      "short_id": "0123456789abcdef"
    }
  }
}
```

VLESS + XHTTP + постквантовое `encryption`:

```json
{
  "type": "vless",
  "tag": "vless-xhttp-pq",
  "server": "edge.example.com",
  "server_port": 443,
  "uuid": "11111111-2222-3333-4444-555555555555",
  "encryption": "mlkem768x25519plus.native.0rtt.100-111-1111.75-0-111.AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
  "tls": {
    "enabled": true,
    "server_name": "edge.example.com",
    "utls": {
      "enabled": true,
      "fingerprint": "chrome_pq"
    }
  },
  "transport": {
    "type": "xhttp",
    "path": "/xhttp",
    "mode": "stream-up"
  }
}
```

---

## `vmess`

Клиент протокола VMess с поддержкой AEAD-заголовков (`alter_id: 0`), обратной совместимости с `alter_id > 0`, автоматического выбора шифра, транспортов V2Ray и мультиплексирования.

### Поддерживаемые поля

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | — | Обязательно: `"vmess"`. |
| `tag` | `string` | `""` | Уникальный тег аутбаунда. |
| `server` | `string` | — | Обязательно: адрес сервера. |
| `server_port` | `integer` | — | Обязательно: порт сервера (`1..=65535`). |
| `uuid` | `string` | — | Обязательно: UUID пользователя (или строка, преобразуемая в UUIDv5). |
| `security` | `string` | `"auto"` | Шифр полезной нагрузки: `"auto"`, `"aes-128-gcm"`, `"chacha20-poly1305"`, `"none"`, `"zero"`. В режиме `"auto"` при наличии TLS без `global_padding`/`authenticated_length` и `alter_id: 0` пытается использовать нулевые накладные расходы (`zero`) с откатом на аппаратно-предпочтительный AEAD (`aes-128-gcm` или `chacha20-poly1305`). |
| `alter_id` | `integer` | `0` | Количество дополнительных ID. Значение `0` включает современный AEAD-заголовок VMess (рекомендуется); значения `> 0` включают устаревший формат заголовка. |
| `global_padding` | `boolean` | `false` | Включает глобальное случайное дополнение блоков данных. |
| `authenticated_length` | `boolean` | `false` | Включает аутентифицированное шифрование поля длины блока (игнорируется при `security: "none"`). |
| `network` | `string` \| `string[]` | `["tcp", "udp"]` | Разрешённые транспортные сети (`"tcp"`, `"udp"`). |
| `packet_encoding` | `string` | `""` | Кодирование UDP: `""` (один блок VMess на дейтаграмму, по умолчанию), `"xudp"` или `"packetaddr"`. |
| `tls` | `object` | — | Опциональный объект TLS. |
| `transport` | `object` | — | V2Ray-транспорт (`http`, `ws`, `quic`, `grpc`, `httpupgrade`, `xhttp`). |
| `multiplex` | `object` | — | Настройки мультиплексирования (`h2mux`, `smux`, `yamux`). |
| *Поля `dialer`* | — | — | Стандартные поля диалера. |

### Пример

```json
{
  "type": "vmess",
  "tag": "vmess-ws",
  "server": "vmess.example.com",
  "server_port": 443,
  "uuid": "11111111-2222-3333-4444-555555555555",
  "security": "auto",
  "alter_id": 0,
  "global_padding": false,
  "authenticated_length": true,
  "tls": {
    "enabled": true,
    "server_name": "vmess.example.com"
  },
  "transport": {
    "type": "ws",
    "path": "/vmess"
  }
}
```

---

## `trojan`

Клиент протокола Trojan (аутентификация по SHA-224 от пароля). Поддерживает TCP, UDP, TLS/uTLS/REALITY, транспорты V2Ray и мультиплексирование.

### Поддерживаемые поля

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | — | Обязательно: `"trojan"`. |
| `tag` | `string` | `""` | Уникальный тег аутбаунда. |
| `server` | `string` | — | Обязательно: адрес сервера. |
| `server_port` | `integer` | — | Обязательно: порт сервера (`1..=65535`). |
| `password` | `string` | — | Обязательно: пароль Trojan. |
| `network` | `string` \| `string[]` | `["tcp", "udp"]` | Разрешённые транспортные сети (`"tcp"`, `"udp"`). |
| `tls` | `object` | — | Объект TLS (для классического Trojan включается `tls.enabled: true`; может быть опущен при работе поверх внешнего `detour`). |
| `transport` | `object` | — | V2Ray-транспорт (`http`, `ws`, `quic`, `grpc`, `httpupgrade`, `xhttp`). |
| `multiplex` | `object` | — | Настройки мультиплексирования (`h2mux`, `smux`, `yamux`). |
| *Поля `dialer`* | — | — | Стандартные поля диалера. |

### Пример

```json
{
  "type": "trojan",
  "tag": "trojan-out",
  "server": "trojan.example.com",
  "server_port": 443,
  "password": "strong-password",
  "tls": {
    "enabled": true,
    "server_name": "trojan.example.com",
    "alpn": ["h2", "http/1.1"]
  }
}
```

---

## `shadowsocks`

Клиент Shadowsocks с полной поддержкой Shadowsocks-2022 (BLAKE3), AEAD, потоковых шифров, `none`, нативного UDP, UoT, мультиплексирования и опциональной обёртки TLS.

### Поддерживаемые поля

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | — | Обязательно: `"shadowsocks"`. |
| `tag` | `string` | `""` | Уникальный тег аутбаунда. |
| `server` | `string` | — | Обязательно: адрес сервера. |
| `server_port` | `integer` | — | Обязательно: порт сервера (`1..=65535`). |
| `method` | `string` | — | Обязательно: метод шифрования (см. таблицу ниже). |
| `password` | `string` | `""` | Пароль или Base64-ключ (обязателен для всех методов, кроме `"none"`). Для `2022-blake3-aes-*-gcm` допускается цепочка ключей `server_psk:user_psk` через `:` (для `2022-blake3-chacha20-poly1305` расширенный заголовок с `:` не поддерживается). |
| `plugin` | `string` | `""` | Имя SIP003-плагина (принимается валидатором для совместимости конфигурации; внешние бинарные плагины в runtime не запускаются). |
| `plugin_opts` | `string` | `""` | Опции SIP003-плагина (принимается валидатором для совместимости). |
| `network` | `string` \| `string[]` | `["tcp", "udp"]` | Разрешённые транспортные сети (`"tcp"`, `"udp"`). |
| `udp_over_tcp` | `boolean` \| `object` | `false` | Передача UDP через TCP-туннель (UoT v1/v2) вместо нативного UDP. |
| `multiplex` | `object` | — | Настройки мультиплексирования (`h2mux`, `smux`, `yamux`). |
| `tls` | `object` | — | Опциональная обёртка TLS вокруг всей сессии Shadowsocks. |
| *Поля `dialer`* | — | — | Стандартные поля диалера. |

### Поддерживаемые методы шифрования (`method`)

| Семейство | Значения `method` | Требования к `password` |
|---|---|---|
| Shadowsocks-2022 | `2022-blake3-aes-128-gcm` | Base64 от 16 байт (допускается `psk1:psk2`). |
| Shadowsocks-2022 | `2022-blake3-aes-256-gcm` | Base64 от 32 байт (допускается `psk1:psk2`). |
| Shadowsocks-2022 | `2022-blake3-chacha20-poly1305` | Base64 от 32 байт (один ключ, без `:`). |
| AEAD | `aes-128-gcm`, `aes-192-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`, `xchacha20-ietf-poly1305` | Произвольный непустой пароль. |
| Потоковые (legacy) | `aes-128-ctr`, `aes-192-ctr`, `aes-256-ctr`, `aes-128-cfb`, `aes-192-cfb`, `aes-256-cfb`, `rc4-md5`, `chacha20-ietf`, `xchacha20` | Произвольный непустой пароль. |
| Без шифрования | `none` | Пароль не требуется (используется внутри защищённого `detour` или TLS). |

### Пример

```json
{
  "type": "shadowsocks",
  "tag": "ss-2022",
  "server": "ss.example.com",
  "server_port": 8388,
  "method": "2022-blake3-aes-128-gcm",
  "password": "YWJjZGVmZ2hpamtsbW5vcA==",
  "udp_over_tcp": {
    "enabled": true,
    "version": 2
  }
}
```

---

## `anytls`

Клиент протокола AnyTLS: аутентифицированный мультиплексируемый поток поверх TLS с адаптивным пулом сессий. Поддерживает TCP и UDP (через встроенную инкапсуляцию UoT).

### Поддерживаемые поля

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | — | Обязательно: `"anytls"`. |
| `tag` | `string` | `""` | Уникальный тег аутбаунда. |
| `server` | `string` | — | Обязательно: адрес сервера. |
| `server_port` | `integer` | — | Обязательно: порт сервера (`1..=65535`). |
| `password` | `string` | `""` | Пароль аутентификации (на линии передаётся SHA-256). |
| `tls` | `object` | — | **Обязательно:** `tls.enabled: true`. Поддерживает uTLS и стандартные параметры клиентского TLS. |
| `client_metadata` | `string` | `"tachyon-core/anytls"` | Строка идентификатора клиента, передаваемая серверу в кадре настроек. |
| `idle_session_check_interval` | `duration` | — | Принимается валидатором для совместимости схемы (в runtime размер и срок жизни пула управляются адаптивно). |
| `idle_session_timeout` | `duration` | — | Принимается валидатором для совместимости схемы (управляется адаптивно). |
| `min_idle_session` | `integer` | — | Принимается валидатором для совместимости схемы (управляется адаптивно). |
| *Поля `dialer`* | — | — | Стандартные поля диалера, **кроме `tcp_fast_open: true`** (запрещено валидатором и runtime). |

### Пример

```json
{
  "type": "anytls",
  "tag": "anytls-out",
  "server": "anytls.example.com",
  "server_port": 443,
  "password": "anytls-password",
  "tls": {
    "enabled": true,
    "server_name": "anytls.example.com",
    "utls": {
      "enabled": true,
      "fingerprint": "chrome"
    }
  }
}
```

---

## `shadowtls`

Клиент протокола ShadowTLS (версии 2 и 3). Выполняет TLS 1.3 ClientHello с браузерным профилем (через `tls.utls`, по умолчанию Chrome) к маскировочному SNI и встраивает HMAC-аутентификацию в `Session ID`. Как правило, используется в связке с внутренним прокси-аутбаундом (`shadowsocks`, `vmess` и др.), указывающим тег `shadowtls` в поле `detour`.

### Поддерживаемые поля

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | — | Обязательно: `"shadowtls"`. |
| `tag` | `string` | `"shadowtls"` | Уникальный тег аутбаунда. |
| `server` | `string` | — | Обязательно: адрес сервера ShadowTLS. |
| `server_port` | `integer` | — | Обязательно: порт сервера (`1..=65535`). |
| `version` | `integer` | `3` | Версия протокола: `2` или `3` (рекомендуется `3`). Версия `1` в runtime не поддерживается. |
| `password` | `string` | — | Обязательно: общий пароль для HMAC-аутентификации рукопожатия. |
| `tls` | `object` | — | **Обязательно:** `tls.enabled: true`. В `tls.server_name` задаётся SNI маскировочного домена; поддерживаются `tls.alpn` и `tls.utls`. |
| *Поля `dialer`* | — | — | Стандартные поля диалера. |

### Пример (в связке с Shadowsocks через `detour`)

```json
[
  {
    "type": "shadowsocks",
    "tag": "ss-over-stls",
    "method": "2022-blake3-aes-128-gcm",
    "password": "YWJjZGVmZ2hpamtsbW5vcA==",
    "detour": "stls-transport"
  },
  {
    "type": "shadowtls",
    "tag": "stls-transport",
    "server": "203.0.113.20",
    "server_port": 443,
    "version": 3,
    "password": "shadowtls-shared-secret",
    "tls": {
      "enabled": true,
      "server_name": "www.example.com",
      "utls": {
        "enabled": true,
        "fingerprint": "chrome"
      }
    }
  }
]
```

---

## `naive`

Клиент NaiveProxy поверх HTTP/2 (`CONNECT` over TLS, ALPN `h2`) или HTTP/3 (`quic: true`, поверх QUIC) с фирменным заголовком `Padding` и кадрированием начальных 8 блоков в каждом направлении.

### Поддерживаемые поля

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | — | Обязательно: `"naive"`. |
| `tag` | `string` | `""` | Уникальный тег аутбаунда. |
| `server` | `string` | — | Обязательно: адрес сервера. |
| `server_port` | `integer` | — | Обязательно: порт сервера (`1..=65535`). |
| `username` | `string` | `""` | Логин HTTP Basic-аутентификации (используется вместе с `password`). |
| `password` | `string` | `""` | Пароль HTTP Basic-аутентификации. |
| `extra_headers` | `object` | `{}` | Дополнительные HTTP-заголовки запроса `CONNECT` (`map[string]string` или `map[string]string[]`). |
| `udp_over_tcp` | `boolean` \| `object` | `false` | Включает поддержку UDP через UoT v1/v2. Без включения `udp_over_tcp` UDP-соединения через `naive` недоступны. Если удалённый сервер явно отклоняет UoT, клиент кэширует это состояние. |
| `quic` | `boolean` | `false` | При `true` использует транспорт HTTP/3 поверх QUIC вместо HTTP/2 поверх TCP. |
| `quic_congestion_control` | `string` | `"cubic"` | Алгоритм управления перегрузкой QUIC: `"cubic"`, `"bbr"`, `"bbr2"`, `"reno"`. Проверяется валидатором независимо от значения `quic`. |
| `insecure_concurrency` | `integer` | `0` | Принимается валидатором для совместимости схемы (в runtime игнорируется; пул сессий управляется автоматически). |
| `stream_receive_window` | `string` \| `integer` | — | Принимается валидатором (формат байт/памяти), в runtime окна настраиваются адаптивно. |
| `quic_session_receive_window` | `string` \| `integer` | — | Принимается валидатором, в runtime управляется адаптивно. |
| `tls` | `object` | — | **Обязательно:** `tls.enabled: true`. Поля `tls.insecure: true` и `tls.disable_sni: true` **запрещены** валидатором и runtime. |
| *Поля `dialer`* | — | — | Стандартные поля диалера. |

### Пример

```json
{
  "type": "naive",
  "tag": "naive-h3",
  "server": "naive.example.com",
  "server_port": 443,
  "username": "user",
  "password": "secret-password",
  "quic": true,
  "quic_congestion_control": "bbr",
  "udp_over_tcp": {
    "enabled": true,
    "version": 2
  },
  "tls": {
    "enabled": true,
    "server_name": "naive.example.com"
  }
}
```

---

## `snell`

Клиент протокола Snell версий 4, 5 и 6. Поддерживает TCP, UDP и повторное использование соединений (`reuse`). Набор дополнительных полей зависит от выбранного `version`.

### Поддерживаемые поля

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | — | Обязательно: `"snell"`. |
| `tag` | `string` | `""` | Уникальный тег аутбаунда. |
| `server` | `string` | — | Обязательно: адрес сервера. |
| `server_port` | `integer` | — | Обязательно: порт сервера (`1..=65535`). |
| `version` | `integer` | — | Обязательно: версия протокола — `4`, `5` или `6`. |
| `psk` | `string` | — | Обязательно: общий ключ аутентификации (Pre-Shared Key). |
| `userkey` | `string` | `""` | Опциональный ключ пользователя (не длиннее 255 байт). |
| `reuse` | `boolean` | `false` | Включает пул повторного использования TCP-сессий Snell. |
| `network` | `string` \| `string[]` | `["tcp", "udp"]` | Разрешённые транспортные сети (`"tcp"`, `"udp"`). |
| `obfs_mode` | `string` | `""` | **Только v4 / v5:** режим обфускации (`""`, `"none"`, `"http"`, `"tls"`). |
| `obfs_host` | `string` | `""` | **Только v4 / v5:** значение `Host` / SNI для обфускации `http` или `tls`. |
| `obfs` | `object` | — | **Только v4 / v5:** альтернативный объектный формат обфускации: `{"mode": "http"|"tls"|"none", "host": "..."}` (вместо `mode` допускается ключ `type`). |
| `udp_over_tcp` | `boolean` \| `object` | `false` | **Только v4 / v5:** принимается валидатором для совместимости схемы. |
| `mode` | `string` | `"default"` | **Только v6:** режим работы Snell v6 — `"default"` (с формированием профиля трафика), `"unshaped"` или `"unsafe-raw"`. |
| *Поля `dialer`* | — | — | Стандартные поля диалера. |

> **Важно:** валидатор строго разделяет поля версий. Указание `obfs`/`obfs_mode`/`obfs_host`/`udp_over_tcp` при `version: 6` или указание `mode` при `version: 4`/`5` приведёт к ошибке проверки конфигурации.

### Примеры

Snell v4 с обфускацией TLS:

```json
{
  "type": "snell",
  "tag": "snell-v4",
  "server": "snell.example.com",
  "server_port": 6160,
  "version": 4,
  "psk": "my-pre-shared-key",
  "reuse": true,
  "obfs": {
    "mode": "tls",
    "host": "www.example.com"
  }
}
```

Snell v6:

```json
{
  "type": "snell",
  "tag": "snell-v6",
  "server": "snell6.example.com",
  "server_port": 6160,
  "version": 6,
  "psk": "my-v6-pre-shared-key",
  "reuse": true,
  "mode": "default"
}
```

---

## `ssh`

Туннелирование TCP-подключений поверх SSH.

> **Статус поддержки:** тип `ssh` и все перечисленные поля проверяются валидатором (`tachyon-core check`), но в runtime v0.6.2 не реализованы.

### Поддерживаемые поля (валидация схемы)

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | — | Обязательно: `"ssh"`. |
| `tag` | `string` | `""` | Уникальный тег аутбаунда. |
| `server` | `string` | — | Адрес SSH-сервера. |
| `server_port` | `integer` | `22` | Порт SSH-сервера. |
| `user` | `string` | `""` | Имя пользователя SSH. |
| `password` | `string` | `""` | Пароль пользователя. |
| `private_key` | `string` \| `string[]` | — | Приватный ключ в PEM-формате (строка или массив строк). |
| `private_key_path` | `string` | `""` | Путь к файлу приватного ключа. |
| `private_key_passphrase` | `string` | `""` | Парольная фраза для расшифровки приватного ключа. |
| `host_key` | `string` \| `string[]` | — | Ожидаемые открытые ключи хоста для проверки подлинности сервера. |
| `host_key_algorithms` | `string` \| `string[]` | — | Разрешённые алгоритмы ключа хоста. |
| `client_version` | `string` | `""` | Пользовательская строка идентификации SSH-клиента. |
| `cipher` | `string` \| `string[]` | — | Список предпочтительных шифров SSH. |
| `mac` | `string` \| `string[]` | — | Список алгоритмов MAC. |
| `kex_algorithm` | `string` \| `string[]` | — | Список алгоритмов обмена ключами (KEX). |
| *Поля `dialer`* | — | — | Стандартные поля диалера. |

---

## `tor`

Исходящее подключение через внешний или встроенный процесс Tor.

> **Статус поддержки:** тип `tor` и его поля проверяются валидатором (`tachyon-core check`), но в runtime v0.6.2 не реализованы.

### Поддерживаемые поля (валидация схемы)

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | — | Обязательно: `"tor"`. |
| `tag` | `string` | `""` | Уникальный тег аутбаунда. |
| `executable_path` | `string` | `""` | Путь к исполняемому файлу `tor`. |
| `extra_args` | `string[]` | `[]` | Дополнительные аргументы командной строки. |
| `data_directory` | `string` | `""` | Каталог хранения состояния Tor. |
| `torrc` | `object` | `{}` | Словарь директив `torrc` (`map[string]string`). |
| *Поля `dialer`* | — | — | Стандартные поля диалера. |

---

## `sudoku`

> **Статус поддержки:** тип `sudoku` зарегистрирован в списке допустимых типов конфигурации (`tachyon-core check`) и поддерживается при разборе URI-подписок (`table_type`, `custom_table`, `custom_tables`, `enable_pure_downlink`, `disable_http_mask`, `http_mask_mode`, `http_mask_host`, `http_mask_path_root`, `http_mask_multiplex`), но клиентская реализация в runtime v0.6.2 отсутствует — запуск конфигурации с таким аутбаундом вернёт ошибку инициализации.
