# Аутбаунд `http`

Аутбаунд HTTP-прокси с поддержкой CONNECT.

## Обязательные поля

| Поле | Тип | Описание |
|---|---|---|
| `type` | string | Значение `http`. |
| `tag` | string | Имя объекта. По нему ссылаются `route.rules`, `dns.rules`, `detour` и группы. |
| `server` | string | Домен или IP-адрес сервера. |
| `server_port` | uint16 | Порт сервера. |

## Собственные поля

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `username` | string | -- | Имя пользователя Basic-аутентификации. |
| `password` | string | -- | Пароль Basic-аутентификации. |
| `path` | string | -- | Путь для CONNECT-запроса. |
| `headers` | object | -- | Дополнительные HTTP-заголовки, объект строк. |

## Общие поля

Поля диалера — [dialer](../common/dialer.md): `detour`, `bind_interface`, `routing_mark`, `inet4_bind_address`, `inet6_bind_address`, `connect_timeout`, `domain_strategy`, `network_strategy`, `network_type`, `fallback_network_type`, `fallback_delay`, `tcp_multi_path`, `tcp_fast_open`, `tcp_keep_alive`, `udp_fragment`, `netns`, `protect_path`, `domain_resolver`, `bind_address_no_port`, `reuse_addr`, `disable_tcp_keep_alive`, `tcp_keep_alive_interval`.


## TLS

Блок `tls` — [tls-client](../common/tls-client.md).
