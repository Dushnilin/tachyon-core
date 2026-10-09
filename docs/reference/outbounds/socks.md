# Аутбаунд `socks`

Аутбаунд SOCKS4/4a/5 к внешнему прокси-серверу.

## Обязательные поля

| Поле | Тип | Описание |
|---|---|---|
| `type` | string | Значение `socks`. |
| `tag` | string | Имя объекта. По нему ссылаются `route.rules`, `dns.rules`, `detour` и группы. |
| `server` | string | Домен или IP-адрес сервера. |
| `server_port` | uint16 | Порт сервера. |

## Собственные поля

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `version` | uint16 | -- | Версия SOCKS: `4`, `4a` или `5`. |
| `username` | string | -- | Имя пользователя для аутентификации. |
| `password` | string | -- | Пароль для аутентификации. |
| `network` | string | -- | Какие сети задействовать. |
| `udp_over_tcp` | object | -- | Пробрасывать UDP через TCP-туннель SOCKS5. |

## Общие поля

Поля диалера — [dialer](../common/dialer.md): `detour`, `bind_interface`, `routing_mark`, `inet4_bind_address`, `inet6_bind_address`, `connect_timeout`, `domain_strategy`, `network_strategy`, `network_type`, `fallback_network_type`, `fallback_delay`, `tcp_multi_path`, `tcp_fast_open`, `tcp_keep_alive`, `udp_fragment`, `netns`, `protect_path`, `domain_resolver`, `bind_address_no_port`, `reuse_addr`, `disable_tcp_keep_alive`, `tcp_keep_alive_interval`.
