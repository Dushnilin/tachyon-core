# Аутбаунд `ssh`

> **Принимается проверкой конфига, но не реализован в рантайме.** `run` завершится ошибкой `outbound type "ssh" not implemented yet`.
Аутбаунд SSH: туннелирование через SSH-сервер.

## Обязательные поля

| Поле | Тип | Описание |
|---|---|---|
| `type` | string | Значение `ssh`. |
| `tag` | string | Имя объекта. По нему ссылаются `route.rules`, `dns.rules`, `detour` и группы. |
| `server` | string | Домен или IP-адрес сервера. |
| `server_port` | uint16 | Порт сервера. |

## Собственные поля

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `user` | string | -- | Имя пользователя SSH. |
| `password` | string | -- | Пароль. |
| `private_key` | string | -- | Закрытый ключ PEM, строка или список строк. |
| `private_key_path` | string | -- | Путь к файлу закрытого ключа. |
| `private_key_passphrase` | string | -- | Пароль закрытого ключа. |
| `host_key` | string / array | -- | Ожидаемые ключи хоста. |
| `host_key_algorithms` | string / array | -- | Алгоритмы ключей хоста, список строк. |
| `client_version` | string | -- | Строка версии клиента для маскировки. |
| `cipher` | string | -- | Шифр. |
| `mac` | string | -- | MAC. |
| `kex_algorithm` | string | -- | Алгоритм обмена ключами. |

## Общие поля

Поля диалера — [dialer](../common/dialer.md): `detour`, `bind_interface`, `routing_mark`, `inet4_bind_address`, `inet6_bind_address`, `connect_timeout`, `domain_strategy`, `network_strategy`, `network_type`, `fallback_network_type`, `fallback_delay`, `tcp_multi_path`, `tcp_fast_open`, `tcp_keep_alive`, `udp_fragment`, `netns`, `protect_path`, `domain_resolver`, `bind_address_no_port`, `reuse_addr`, `disable_tcp_keep_alive`, `tcp_keep_alive_interval`.
