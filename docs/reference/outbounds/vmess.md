# Аутбаунд `vmess`

Аутбаунд VMess с AEAD и legacy-режимом.

## Обязательные поля

| Поле | Тип | Описание |
|---|---|---|
| `type` | string | Значение `vmess`. |
| `tag` | string | Имя объекта. По нему ссылаются `route.rules`, `dns.rules`, `detour` и группы. |
| `server` | string | Домен или IP-адрес сервера. |
| `server_port` | uint16 | Порт сервера. |

## Собственные поля

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `uuid` | string | -- | Идентификатор пользователя. |
| `security` | string | -- | Шифр VMess: `auto`, `aes-128-gcm`, `chacha20-poly1305`, `none`, `zero`. |
| `alter_id` | uint32 | -- | AlterID. Ненулевое значение — legacy-режим. |
| `global_padding` | boolean | -- | Глобальный паддинг: случайная длина каждого запроса. |
| `authenticated_length` | boolean | -- | Длина аутентифицированная, чтобы скрыть размер. |
| `network` | string | -- | Какие сети задействовать. |
| `packet_encoding` | string | -- | Кодирование адреса внутри пакета: `packetaddr` или `xudp`. |
| `multiplex` | object | -- | Мультиплексирование соединений, см. [multiplex](../common/multiplex.md). |
| `transport` | object | -- | Блок транспорта, см. [transport](../common/transports.md). |

## Общие поля

Поля диалера — [dialer](../common/dialer.md): `detour`, `bind_interface`, `routing_mark`, `inet4_bind_address`, `inet6_bind_address`, `connect_timeout`, `domain_strategy`, `network_strategy`, `network_type`, `fallback_network_type`, `fallback_delay`, `tcp_multi_path`, `tcp_fast_open`, `tcp_keep_alive`, `udp_fragment`, `netns`, `protect_path`, `domain_resolver`, `bind_address_no_port`, `reuse_addr`, `disable_tcp_keep_alive`, `tcp_keep_alive_interval`.


## TLS

Блок `tls` — [tls-client](../common/tls-client.md).


## Транспорт

Блок `transport` — [transports](../common/transports.md).


## Мультиплексирование

Блок `multiplex` — [multiplex](../common/multiplex.md).
