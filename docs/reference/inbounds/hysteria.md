# Инбаунд `hysteria`

> **Принимается проверкой конфига, но не реализован в рантайме.** `check -c` пропустит, `run` завершится ошибкой `inbound type "hysteria" not implemented yet`.
Серверная точка входа Hysteria 1 (UDP).

## Поля прослушивания

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `listen` | string | -- | Адрес прослушивания: `::` для всех интерфейсов или конкретный IP. |
| `listen_port` | uint16 | -- | Порт прослушивания. Обязателен для всех инбаундов с сокетом. |
| `bind_interface` | string | -- | Имя интерфейса, на котором открывается сокет. |
| `routing_mark` | uint32 | -- | Метка маршрутизации (SO_MARK), число. |
| `reuse_addr` | boolean | -- | Переиспользование адреса (SO_REUSEADDR). |
| `netns` | string | -- | Сетевое пространство имён, в котором живёт сокет. |
| `disable_tcp_keep_alive` | boolean | -- | Отключить TCP keep-alive. |
| `tcp_keep_alive` | boolean | -- | TCP keep-alive. |
| `tcp_keep_alive_interval` | string | -- | Интервал TCP keep-alive, строка--duration. |
| `tcp_fast_open` | boolean | -- | TCP Fast Open. |
| `tcp_multi_path` | boolean | -- | Multipath TCP. |
| `udp_fragment` | boolean | -- | Фрагментировать большие UDP-пакеты. |
| `udp_timeout` | string | -- | Таймаут UDP-сессии, вида `30s` или `5m`. |
| `detour` | string | -- | Тег аутбаунда, через который устанавливается соединение с сервером. |
| `proxy_protocol` | boolean | -- |  |
| `proxy_protocol_accept_no_header` | boolean | -- |  |

## Собственные поля

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `up` | string | -- | Скорость аплинка клиента: `100Mb`, `100Mbps`, число. |
| `up_mbps` | uint32 | -- | Скорость аплинка в Mbps. |
| `down` | string | -- | Скорость даунлинка клиента. |
| `down_mbps` | uint32 | -- | Скорость даунлинка в Mbps. |
| `obfs` | object | -- | Обфускация, объект с `type` и `password`. |
| `users` | array | -- | Список пользователей, см. [users](../common/users.md). |
| `recv_window_conn` | uint32 | -- | Окно приёма соединения, байт. |
| `recv_window_client` | string | -- | Окно приёма клиента, байт. |
| `max_conn_client` | uint32 | -- | Максимум одновременных клиентских соединений. |
| `disable_mtu_discovery` | boolean | -- | Не определять MTU пути. |
| `tls` | object | -- | Блок TLS, см. [TLS клиента](../common/tls-client.md) или [TLS сервера](../common/tls-server.md). |

## Связанные блоки

- [TLS сервера](../common/tls-server.md)
- [пользователи](../common/users.md)

---
