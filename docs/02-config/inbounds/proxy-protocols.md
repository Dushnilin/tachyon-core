# Серверные прокси-инбаунды

В этом разделе описаны серверные прокси-обработчики `tachyon-core`:

- [`vless`](#vless)
- [`vmess`](#vmess)
- [`trojan`](#trojan)
- [`shadowsocks`](#shadowsocks)
- [`anytls`](#anytls)
- [`shadowtls`](#shadowtls)
- [`naive`](#naive)
- [`snell`](#snell)

Все перечисленные типы наследуют общие поля прослушивания (`listen`, `listen_port`, `ipv6_only`, `udp_timeout`, `detour`, `filter`, `ips_excluded`, `domains_excluded`, `fullcone`, `udp_nat_mode`, `udp_fullcone_max_bindings` и др.). Спецификация общих объектов `listen`, серверного `tls` (включая REALITY X25519 и постквантовый `X25519MLKEM768`), `transport` и `multiplex` приведена в [common-objects.md](../common-objects.md).

---

## `vless`

Серверный инбаунд протокола VLESS (TCP, UDP, `packetaddr`, XUDP, `h2mux` и UoT v1/v2) с поддержкой `xtls-rprx-vision`, постквантового шифрования полезной нагрузки `decryption`, перенаправления неаутентифицированных запросов (`fallback` / `fallback_for_alpn`) и защиты `tarpit`.

### Поведение рантайма

- **Потоки (`flow`)**: для каждого пользователя в `users[].flow` можно указать `""` (обычный режим) или `"xtls-rprx-vision"` (значение `"xtls-rprx-vision-udp443"` нормализуется к `"xtls-rprx-vision"`). Режим `xtls-rprx-vision` не допускает сырые UDP-команды (`0x02`) — для UDP в Vision клиенты используют XUDP (команда `0x03`), который поддерживается сервером (до 1024 сессий на соединение).
- **Постквантовое шифрование (`decryption`)**: поддерживает `"none"` (по умолчанию) или строку спецификации:
  ```
  mlkem768x25519plus.<native|xorpub|random>.<0rtt|1rtt|<N>s>[.<padding>...].<private_key_or_seed>...
  ```
  где:
  - облик трафика: `native` (AEAD-заголовки в стиле TLS 1.3), `xorpub` (XOR с публичным ключом), `random` (случайный поток);
  - время жизни тикета сессии: `1rtt` / `0s` (полное рукопожатие, `0`), `0rtt` (`600` секунд) или `<N>s` (произвольное число секунд);
  - опциональные блоки padding вида `<вероятность>-<мин>-<макс>` (разделённые точками; для первого блока вероятность `>= 100`, границы `>= 35`, суммарная максимальная длина `<= 65553`);
  - один или несколько приватных ключей в формате base64url без `=`: 32 байта (X25519) или 64 байта (seed ML-KEM-768).
- **Защита от активного зондирования (`fallback`, `fallback_for_alpn`, `tarpit`)**: при чтении заголовка VLESS захватываются первые до 4096 байт потока. При ошибке аутентификации (если клиент прислал непустой префикс):
  - при совпадении согласованного ALPN с ключом в `fallback_for_alpn` или наличии `fallback` сервер подключается к указанному backend-серверу (таймаут подключения 5 с, сессия до 60 с), воспроизводит захваченный префикс и прозрачно проксирует соединение;
  - иначе при `"tarpit": true` соединение удерживается с медленной побайтовой выдачей фиктивного HTTP-ответа (не более 64 одновременных tarpit-слотов на процесс).
- **Транспорты и мультиплексирование**: поддерживаются `ws`, `httpupgrade`, `http`/`h2`, `grpc`, `xhttp` (`transport`), `h2mux` (`multiplex`), `XUDP` и `UoT` v1/v2.
- **Горячее обновление пользователей**: список `users` обновляется при `reload_in_place` без перезапуска сокета.

### Поля конфигурации `vless`

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | обязательное | `"vless"`. |
| `tag` | `string` | `"vless"` | Идентификатор инбаунда. |
| `listen` | `string` | `"127.0.0.1"` | IP-адрес прослушивания (`"::"` для dual-stack). |
| `listen_port` | `uint16` | обязательное | TCP-порт прослушивания. |
| `users` | `object[]` | обязательное | Непустой массив пользователей: `{"name": "...", "uuid": "...", "flow": "..."}`. Нестандартные строки в `uuid` преобразуются в UUIDv5. |
| `decryption` | `string` | `"none"` | `"none"` либо спецификация `mlkem768x25519plus....` для расшифровки VLESS Encryption. |
| `fallback` | `object` | — | Целевой сервер перенаправления при ошибке аутентификации: `{"server": "...", "server_port": 80}`. |
| `fallback_for_alpn` | `object` | `{}` | Словарь `ALPN -> {"server": "...", "server_port": ...}` с приоритетом над `fallback` (например, `"h2"`, `"http/1.1"`). |
| `tarpit` | `bool` | `false` | Удерживать неаутентифицированные соединения в tarpit (если не сработал `fallback`). |
| `tls` | `object` | — | Серверный TLS / REALITY (см. [common-objects.md](../common-objects.md)). |
| `transport` | `object` | — | Серверный V2Ray-транспорт (`ws`, `httpupgrade`, `http`/`h2`, `grpc`, `xhttp`). |
| `multiplex` | `object` | — | Настройка серверного `h2mux` (`{"enabled": true}`). |

### Пример конфигурации `vless` (REALITY + `xtls-rprx-vision`)

```json
{
  "type": "vless",
  "tag": "vless-reality-in",
  "listen": "::",
  "listen_port": 443,
  "users": [
    {
      "name": "alice",
      "uuid": "27848739-7e62-4138-9fd3-098a63964b6b",
      "flow": "xtls-rprx-vision"
    }
  ],
  "tls": {
    "enabled": true,
    "server_name": "www.example.com",
    "reality": {
      "enabled": true,
      "handshake": {
        "server": "www.example.com",
        "server_port": 443
      },
      "private_key": "REPLACE_WITH_BASE64URL_X25519_PRIVATE_KEY",
      "short_id": ["0123456789abcdef"]
    }
  }
}
```

### Пример конфигурации `vless` (TLS + `xhttp` + `fallback`)

```json
{
  "type": "vless",
  "tag": "vless-xhttp-in",
  "listen": "::",
  "listen_port": 8443,
  "users": [
    {
      "name": "bob",
      "uuid": "a1b2c3d4-e5f6-4789-abcd-ef0123456789"
    }
  ],
  "decryption": "none",
  "fallback": {
    "server": "127.0.0.1",
    "server_port": 8080
  },
  "fallback_for_alpn": {
    "h2": {
      "server": "127.0.0.1",
      "server_port": 8081
    }
  },
  "tarpit": true,
  "transport": {
    "type": "xhttp",
    "path": "/xhttp",
    "mode": "auto"
  },
  "tls": {
    "enabled": true,
    "certificate_path": "/etc/tachyon-core/cert.pem",
    "key_path": "/etc/tachyon-core/key.pem"
  }
}
```

---

## `vmess`

Серверный инбаунд протокола VMess с AEAD-аутентификацией заголовков.

### Поведение рантайма

- **Аутентификация и защита от повторов**: сервер проверяет AEAD Auth ID каждого пользователя, допуская расхождение системного времени клиента и сервера в пределах `±120` секунд, и отбрасывает повторные Auth ID в рамках того же 120-секундного окна. Устаревший режим `alterId > 0` (MD5) не используется.
- **Протоколы**: поддерживаются TCP, UDP (`COMMAND_UDP = 2`), `h2mux` (`sp.mux.sing-box.arpa:444`), UoT v1/v2, а также все серверные транспорты (`ws`, `httpupgrade`, `http`/`h2`, `grpc`, `xhttp`) и серверный `tls`.
- **Горячее обновление пользователей**: список `users` обновляется при `reload_in_place`.

### Поля конфигурации `vmess`

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | обязательное | `"vmess"`. |
| `tag` | `string` | `"vmess"` | Идентификатор инбаунда. |
| `listen` | `string` | `"127.0.0.1"` | IP-адрес прослушивания. |
| `listen_port` | `uint16` | обязательное | TCP-порт прослушивания. |
| `users` | `object[]` | обязательное | Непустой массив пользователей: `{"name": "...", "uuid": "..."}`. Поле `alterId` (если присутствует) должно быть `0`. |
| `tls` | `object` | — | Серверный TLS / REALITY. |
| `transport` | `object` | — | Серверный V2Ray-транспорт (`ws`, `httpupgrade`, `http`/`h2`, `grpc`, `xhttp`). |
| `multiplex` | `object` | — | Серверный `h2mux` (`{"enabled": true}`). |

### Пример конфигурации `vmess`

```json
{
  "type": "vmess",
  "tag": "vmess-ws-in",
  "listen": "::",
  "listen_port": 10086,
  "users": [
    {
      "name": "user1",
      "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811"
    }
  ],
  "transport": {
    "type": "ws",
    "path": "/vmess-ws"
  },
  "tls": {
    "enabled": true,
    "certificate_path": "/etc/tachyon-core/cert.pem",
    "key_path": "/etc/tachyon-core/key.pem"
  }
}
```

---

## `trojan`

Серверный инбаунд протокола Trojan (56-байтный SHA-224 hex хэш пароля + CRLF + команда + SOCKS-адрес + CRLF).

### Поведение рантайма

- **Уникальность паролей**: пароли всех записей в `users` должны быть уникальными; дубликаты отклоняются при запуске.
- **Совместимость UDP**: сервер принимает оба варианта байта UDP-команды — `0x02` (формат `sing-box`) и `0x03` (формат `Xray`), а также `0x7f` и `sp.mux.sing-box.arpa:444` для `h2mux` и UoT v1/v2.
- **Защита от зондирования**: поддерживаются `fallback`, `fallback_for_alpn` и `tarpit` аналогично `vless`.
- **Горячее обновление пользователей**: список `users` обновляется при `reload_in_place`.

### Поля конфигурации `trojan`

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | обязательное | `"trojan"`. |
| `tag` | `string` | `"trojan"` | Идентификатор инбаунда. |
| `listen` | `string` | `"127.0.0.1"` | IP-адрес прослушивания. |
| `listen_port` | `uint16` | обязательное | TCP-порт прослушивания. |
| `users` | `object[]` | обязательное | Непустой массив пользователей: `{"name": "...", "password": "..."}`. Пароли должны быть уникальны. |
| `fallback` | `object` | — | Сервер перенаправления при ошибке аутентификации: `{"server": "...", "server_port": 80}`. |
| `fallback_for_alpn` | `object` | `{}` | Словарь `ALPN -> {"server": "...", "server_port": ...}`. |
| `tarpit` | `bool` | `false` | Удерживать неаутентифицированные соединения в tarpit при отсутствии подходящего `fallback`. |
| `tls` | `object` | — | Серверный TLS / REALITY. |
| `transport` | `object` | — | Серверный V2Ray-транспорт (`ws`, `httpupgrade`, `http`/`h2`, `grpc`, `xhttp`). |
| `multiplex` | `object` | — | Серверный `h2mux` (`{"enabled": true}`). |

### Пример конфигурации `trojan`

```json
{
  "type": "trojan",
  "tag": "trojan-in",
  "listen": "::",
  "listen_port": 443,
  "users": [
    {
      "name": "alice",
      "password": "very-strong-trojan-password"
    }
  ],
  "fallback": {
    "server": "127.0.0.1",
    "server_port": 8080
  },
  "fallback_for_alpn": {
    "h2": {
      "server": "127.0.0.1",
      "server_port": 8081
    }
  },
  "tls": {
    "enabled": true,
    "alpn": ["h2", "http/1.1"],
    "certificate_path": "/etc/tachyon-core/cert.pem",
    "key_path": "/etc/tachyon-core/key.pem"
  }
}
```

---

## `shadowsocks`

Серверный инбаунд Shadowsocks с поддержкой одиночного пользователя, многопользовательского режима (`users`), многопользовательского ретранслятора (`destinations`), нативного UDP, `h2mux` и UoT v1/v2.

### Поддерживаемые методы шифрования (`method`)

- **Shadowsocks-2022 (BLAKE3)**: `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-poly1305` (окно проверки метки времени `±30` секунд; ключи задаются в base64: 16 байт для AES-128, 32 байта для AES-256 и ChaCha20).
- **AEAD (2017)**: `aes-128-gcm`, `aes-192-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`, `xchacha20-ietf-poly1305`.
- **Потоковые (legacy) и без шифрования**: `aes-128-ctr`, `aes-192-ctr`, `aes-256-ctr`, `aes-128-cfb`, `aes-192-cfb`, `aes-256-cfb`, `rc4-md5`, `chacha20-ietf`, `xchacha20`, `none`.

### Режимы работы

1. **Single-user**: задаются `method` и `password` на верхнем уровне инбаунда.
2. **Multi-user (`users`)**:
   - для методов `2022-blake3-*` ключ сервера задаётся в верхнеуровневом `password`, а индивидуальный ключ каждого клиента — в `users[].password` (клиент подключается с составным ключом `<server_psk>:<user_psk>`, либо в `users[].password` можно сразу указать полную цепочку через `:`);
   - для AEAD и legacy методов сервер подбирает подходящий ключ из `users` (и верхнеуровневого `password`, если он задан).
3. **Multi-user relay (`destinations`)**: каждый элемент `{ "name", "server", "server_port", "password" }` привязывает ключ/пароль к фиксированному целевому адресу — весь трафик этого ключа перенаправляется напрямую на `server:server_port`.
4. **UDP и UoT**: если `network` не исключает `udp`, на том же порту открывается UDP-сокет Shadowsocks. Дополнительно поверх TCP автоматически обрабатываются туннели UoT v1 (`sp.udp-over-tcp.arpa`) и UoT v2 (`sp.v2.udp-over-tcp.arpa`) и `h2mux` (`sp.mux.sing-box.arpa:444`).

### Поля конфигурации `shadowsocks`

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | обязательное | `"shadowsocks"`. |
| `tag` | `string` | `"shadowsocks"` | Идентификатор инбаунда. |
| `listen` | `string` | `"127.0.0.1"` | IP-адрес прослушивания (`"::"` для dual-stack). |
| `listen_port` | `uint16` | обязательное | Порт прослушивания TCP (и UDP, если разрешён в `network`). |
| `network` | `string \| string[]` | TCP и UDP | `"tcp"`, `"udp"` или оба. |
| `method` | `string` | обязательное | Метод шифрования (одно из 18 поддерживаемых значений выше). |
| `password` | `string` | `""` | Пароль (для single-user) или серверный PSK в base64 (для multi-user Shadowsocks-2022). Необязателен только при `method: "none"`. |
| `users` | `object[]` | `[]` | Список пользователей: `{"name": "...", "password": "..."}`. |
| `destinations` | `object[]` | `[]` | Список ретрансляционных назначений: `{"name": "...", "server": "...", "server_port": 443, "password": "..."}`. |
| `multiplex` | `object` | — | Серверный `h2mux` (`{"enabled": true}`). |
| `tls` | `object` | — | Опциональная серверная обёртка TLS (поверх TCP). |
| `managed` | `bool` | `false` | Принимается валидатором схемы, но не реализовано в рантайме (при наличии ключа запуск завершается ошибкой). |

### Пример конфигурации `shadowsocks` (multi-user 2022-BLAKE3)

```json
{
  "type": "shadowsocks",
  "tag": "ss-2022-in",
  "listen": "::",
  "listen_port": 8388,
  "network": ["tcp", "udp"],
  "method": "2022-blake3-aes-128-gcm",
  "password": "AAAAAAAAAAAAAAAAAAAAAA==",
  "users": [
    {
      "name": "alice",
      "password": "BBBBBBBBBBBBBBBBBBBBBB=="
    },
    {
      "name": "bob",
      "password": "CCCCCCCCCCCCCCCCCCCCCC=="
    }
  ]
}
```

### Пример конфигурации `shadowsocks` (single-user с `h2mux`)

```json
{
  "type": "shadowsocks",
  "tag": "ss-aead-in",
  "listen": "::",
  "listen_port": 8389,
  "method": "chacha20-ietf-poly1305",
  "password": "strong-ss-password",
  "multiplex": {
    "enabled": true
  }
}
```

---

## `anytls`

Серверный инбаунд протокола AnyTLS: аутентификация по SHA-256 хэшу пароля поверх TLS (или plain TCP при выключенном `tls`), обмен кадрами настроек и встроенное мультиплексирование потоков (`CMD_SYN`, `CMD_PSH`, `CMD_FIN`, `CMD_RST`, heartbeat) в рамках одной сессии.

### Поведение рантайма

- **Мультиплексирование и лимиты**: до 1024 одновременных логических потоков в одной TCP/TLS-сессии; таймаут записи кадра — 30 секунд.
- **UDP**: поддерживается через автоматический перехват UoT v1/v2 внутри потоков AnyTLS.
- **Горячее обновление пользователей**: список `users` (и `password`) обновляется при `reload_in_place`.

### Поля конфигурации `anytls`

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | обязательное | `"anytls"`. |
| `tag` | `string` | `"anytls"` | Идентификатор инбаунда. |
| `listen` | `string` | `"127.0.0.1"` | IP-адрес прослушивания. |
| `listen_port` | `uint16` | обязательное | TCP-порт прослушивания. |
| `users` | `object[]` | `[]` | Массив пользователей `{"name": "...", "password": "..."}` (также принимается `username`). Требуется непустой `users` или `password`. |
| `password` | `string` | `""` | Одиночный пароль (используется, если `users` не задан; имя пользователя — `"default"`). |
| `padding_scheme` | `string \| string[]` | `[]` | Строка или массив строк схемы padding (принимается схемой совместимости). |
| `tls` | `object` | — | Серверный TLS / REALITY (рекомендуется для рабочего развёртывания). |

### Пример конфигурации `anytls`

```json
{
  "type": "anytls",
  "tag": "anytls-in",
  "listen": "::",
  "listen_port": 8443,
  "users": [
    {
      "name": "alice",
      "password": "anytls-secret-password"
    }
  ],
  "padding_scheme": [
    "stop=8",
    "0=30-30",
    "1=100-400",
    "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000",
    "3=9-9,500-1000",
    "4=500-1000",
    "5=500-1000",
    "6=500-1000",
    "7=500-1000"
  ],
  "tls": {
    "enabled": true,
    "certificate_path": "/etc/tachyon-core/cert.pem",
    "key_path": "/etc/tachyon-core/key.pem"
  }
}
```

---

## `shadowtls`

Серверный инбаунд ShadowTLS: перехватывает входящее TLS-рукопожатие (извлекает ClientHello Random, Session ID и SNI), проверяет HMAC-SHA1 аутентификацию клиента, проксирует рукопожатие к реальному внешнему TLS-серверу (`handshake`), а после успешной проверки передаёт полезный поток далее (обычно на локальный прокси-инбаунд через `detour`). Неаутентифицированные соединения прозрачно проксируются на сервер `handshake`.

### Поведение рантайма

- **Версии протокола**: поддерживаются `version: 2` и `version: 3` (по умолчанию `3`). Версия `1` в рантайме не поддерживается и отклоняется при запуске.
- **Перенаправление (`detour`)**: обычно ShadowTLS работает в паре с внутренним инбаундом (например, `shadowsocks`), тег которого указывается в общем поле `detour`.
- **Обработка SNI**: сервер подбирает целевой сервер рукопожатия сначала по точному совпадению SNI в `handshake_for_server_name`, а при отсутствии совпадения использует `handshake` (обязателен по правилам валидации).

### Поля конфигурации `shadowtls`

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | обязательное | `"shadowtls"`. |
| `tag` | `string` | `"shadowtls"` | Идентификатор инбаунда. |
| `listen` | `string` | `"127.0.0.1"` | IP-адрес прослушивания. |
| `listen_port` | `uint16` | обязательное | TCP-порт прослушивания. |
| `version` | `int` | `3` | Версия протокола ShadowTLS: `2` или `3`. |
| `password` | `string` | `""` | Пароль сервера (для v2 или одиночного пользователя). Требуется `password` или непустой `users`. |
| `users` | `object[]` | `[]` | Список пользователей для v3: `{"name": "...", "password": "..."}`. |
| `handshake` | `object` | обязательное | Сервер рукопожатия по умолчанию: `{"server": "...", "server_port": 443}`. Оба поля `server` и `server_port` обязательны для валидации. |
| `handshake_for_server_name` | `object` | `{}` | Словарь `SNI -> {"server": "...", "server_port": 443}` для выбора сервера рукопожатия по домену SNI. |
| `strict_mode` | `bool` | `false` | Строгий режим проверки ShadowTLS v3. |
| `wildcard_sni` | `int` | `0` | Поле схемы совместимости (валидируется как целое число; в рантайме v0.6.2 не используется). |
| `detour` | `string` | `""` | Тег внутреннего инбаунда (из общих полей `listen`), куда передаётся аутентифицированный поток. |

### Пример конфигурации `shadowtls` v3 в связке с `shadowsocks`

```json
{
  "inbounds": [
    {
      "type": "shadowtls",
      "tag": "shadowtls-in",
      "listen": "::",
      "listen_port": 443,
      "version": 3,
      "users": [
        {
          "name": "alice",
          "password": "shadowtls-v3-password"
        }
      ],
      "handshake": {
        "server": "www.example.com",
        "server_port": 443
      },
      "handshake_for_server_name": {
        "cdn.example.net": {
          "server": "cdn.example.net",
          "server_port": 443
        }
      },
      "strict_mode": true,
      "detour": "ss-behind-stls"
    },
    {
      "type": "shadowsocks",
      "tag": "ss-behind-stls",
      "listen": "127.0.0.1",
      "listen_port": 8390,
      "method": "2022-blake3-aes-128-gcm",
      "password": "AAAAAAAAAAAAAAAAAAAAAA=="
    }
  ]
}
```

---

## `naive`

Серверный инбаунд NaiveProxy: принимает `CONNECT`-туннели поверх HTTP/2 (TCP + TLS) и HTTP/3 (UDP + QUIC с ALPN `h3`), поддерживает padding-заголовки (`padding` и `padding-version: 1`), HTTP Basic аутентификацию и автоматическую терминацию UoT v1/v2.

### Поведение рантайма

- **TLS обязателен**: валидатор отклоняет конфигурацию `naive` без `"tls": {"enabled": true, ...}`.
- **HTTP/2 и HTTP/3 (QUIC)**: по умолчанию слушатель поднимает TCP-сокет (HTTP/2 over TLS) и на том же порту UDP-сокет QUIC (HTTP/3, ALPN `h3`). Если задать `"network": "tcp"`, запускается только HTTP/2 поверх TCP.
- **Аутентификация**: при непустом `users` проверяется заголовок `Proxy-Authorization: Basic ...`; при отсутствии или ошибке возвращается `407 Proxy Authentication Required`.
- **Padding**: если клиент прислал заголовок `padding` или `padding-version: 1`, поток оборачивается в декодер/кодер Naive padding.
- **UDP (UoT)**: запросы `CONNECT` к `sp.udp-over-tcp.arpa` / `sp.v2.udp-over-tcp.arpa` автоматически обслуживаются как UoT v1/v2.

### Поля конфигурации `naive`

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | обязательное | `"naive"`. |
| `tag` | `string` | `"naive"` | Идентификатор инбаунда. |
| `listen` | `string` | `"127.0.0.1"` | IP-адрес прослушивания. |
| `listen_port` | `uint16` | обязательное | Порт прослушивания (TCP для HTTP/2 и UDP для HTTP/3 QUIC). |
| `users` | `object[]` | `[]` | Список учётных записей `{"username": "...", "password": "...", "name": "..."}`. |
| `network` | `string \| string[]` | TCP и UDP (QUIC) | Укажите `"tcp"`, чтобы отключить QUIC/HTTP/3 и оставить только HTTP/2 поверх TCP. |
| `quic_congestion_control` | `string` | `""` | Поле схемы совместимости для алгоритма контроля перегрузки QUIC. |
| `tls` | `object` | обязательное | Серверный TLS (`enabled: true`, сертификат и приватный ключ обязательны). |

### Пример конфигурации `naive`

```json
{
  "type": "naive",
  "tag": "naive-in",
  "listen": "::",
  "listen_port": 443,
  "users": [
    {
      "username": "naiveuser",
      "password": "naive-strong-password"
    }
  ],
  "tls": {
    "enabled": true,
    "alpn": ["h2", "http/1.1"],
    "certificate_path": "/etc/tachyon-core/cert.pem",
    "key_path": "/etc/tachyon-core/key.pem"
  }
}
```

---

## `snell`

Серверный инбаунд протокола Snell (версии v5 и v6) поверх TCP с поддержкой переиспользования соединений (`CMD_CONNECT_V2`), одиночных подключений (`CMD_CONNECT`), проверки канала (`CMD_PING`), туннелирования UDP (`CMD_UDP`) и UoT v1/v2.

### Поведение рантайма и валидации

- **Версия (`version`)**: поле обязательно на этапе `check`; валидатор принимает значения `5` и `6` (v4 на серверном инбаунде отклоняется проверкой схемы).
- **Pre-Shared Key (`psk`)**: обязателен для обеих версий; для Snell v6 длина `psk` должна быть строго от `12` до `255` байт.
- **Разделение опций по версиям**:
  - при `version: 5` допустимо поле `obfs_mode` (`""`, `"none"`, `"http"`, `"tls"`), а поле `mode` отклоняется;
  - при `version: 6` допустимо поле `mode` (`""`, `"default"`, `"unshaped"`, `"unsafe-raw"`), а поле `obfs_mode` отклоняется.
- **Поле `users`**: валидатор проверяет элементы `{"name": "...", "userkey": "..."}` (непустой уникальный `userkey` длиной до 255 байт). В рантайме v0.6.2 для клиентских ключей используется общий `psk`, а при проверке `users` рантайм считывает поле `password`; при стандартном развёртывании с общим `psk` массив `users` можно не задавать.

### Поля конфигурации `snell`

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | обязательное | `"snell"`. |
| `tag` | `string` | `"snell"` | Идентификатор инбаунда. |
| `listen` | `string` | `"127.0.0.1"` | IP-адрес прослушивания (`"::"` для dual-stack). |
| `listen_port` | `uint16` | обязательное | TCP-порт прослушивания. |
| `version` | `int` | обязательное | Версия протокола: `5` или `6`. |
| `psk` | `string` | обязательное | Общий секретный ключ (для v6 длина `12..=255` байт). |
| `users` | `object[]` | `[]` | Опциональный список пользователей `{"name": "...", "userkey": "..."}`. |
| `obfs_mode` | `string` | `"none"` | Только для `version: 5`: `"none"`, `"http"` или `"tls"`. |
| `mode` | `string` | `"default"` | Только для `version: 6`: `"default"`, `"unshaped"` или `"unsafe-raw"`. |

### Пример конфигурации `snell` v5

```json
{
  "type": "snell",
  "tag": "snell-v5-in",
  "listen": "::",
  "listen_port": 6160,
  "version": 5,
  "psk": "snell-v5-preshared-key",
  "obfs_mode": "tls"
}
```

### Пример конфигурации `snell` v6

```json
{
  "type": "snell",
  "tag": "snell-v6-in",
  "listen": "::",
  "listen_port": 6161,
  "version": 6,
  "psk": "snell-v6-strong-preshared-key",
  "mode": "default"
}
```
