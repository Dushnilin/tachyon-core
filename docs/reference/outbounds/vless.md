# Аутбаунд `vless`

Аутбаунд VLESS с поддержкой Vision, uTLS и REALITY.

## Обязательные поля

| Поле | Тип | Описание |
|---|---|---|
| `type` | string | Значение `vless`. |
| `tag` | string | Имя объекта. По нему ссылаются `route.rules`, `dns.rules`, `detour` и группы. |
| `server` | string | Домен или IP-адрес сервера. |
| `server_port` | uint16 | Порт сервера. |

## Собственные поля

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `uuid` | string | -- | Идентификатор пользователя. |
| `flow` | string | -- | Режим потока: `xtls-rprx-vision`. |
| `encryption` | string | -- | Шифрование. Пустая строка или `none`. |
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


`utls_over_tls` не поддерживается.
