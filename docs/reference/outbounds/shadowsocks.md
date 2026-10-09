# Аутбаунд `shadowsocks`

Аутбаунд Shadowsocks: AEAD-шифры и спецификация 2022.

## Обязательные поля

| Поле | Тип | Описание |
|---|---|---|
| `type` | string | Значение `shadowsocks`. |
| `tag` | string | Имя объекта. По нему ссылаются `route.rules`, `dns.rules`, `detour` и группы. |
| `server` | string | Домен или IP-адрес сервера. |
| `server_port` | uint16 | Порт сервера. |

## Собственные поля

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `method` | string | -- | Шифр: `aes-128-gcm`, `aes-256-gcm`, `chacha20-poly1305`, `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-poly1305`. |
| `password` | string | -- | Пароль или PSK. |
| `plugin` | string | -- | Плагин: `obfs-local`, `v2ray-plugin`, `shadow-tls`. |
| `plugin_opts` | string | -- | Аргументы плагина одной строкой. |
| `network` | string | -- | Какие сети задействовать. |
| `udp_over_tcp` | object | -- | Пробрасывать UDP через TCP-туннель. |
| `multiplex` | object | -- | Мультиплексирование соединений, см. [multiplex](../common/multiplex.md). |

## Общие поля

Поля диалера — [dialer](../common/dialer.md): `detour`, `bind_interface`, `routing_mark`, `inet4_bind_address`, `inet6_bind_address`, `connect_timeout`, `domain_strategy`, `network_strategy`, `network_type`, `fallback_network_type`, `fallback_delay`, `tcp_multi_path`, `tcp_fast_open`, `tcp_keep_alive`, `udp_fragment`, `netns`, `protect_path`, `domain_resolver`, `bind_address_no_port`, `reuse_addr`, `disable_tcp_keep_alive`, `tcp_keep_alive_interval`.


## TLS

Блок `tls` — [tls-client](../common/tls-client.md).


## Мультиплексирование

Блок `multiplex` — [multiplex](../common/multiplex.md).
