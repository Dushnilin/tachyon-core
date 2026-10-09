# Инбаунд `http`

Клиентский HTTP-прокси с поддержкой CONNECT и Basic-аутентификации.

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
| `users` | array | -- | Список пользователей, см. [users](../common/users.md). |
| `domain_resolver` | string | -- | Тег DNS-сервера для разрешения имени аутбаунда. |
| `set_system_proxy` | boolean | -- | Выставить системные настройки прокси. На роутере не применяется. |
| `tls` | object | -- | Блок TLS, см. [TLS клиента](../common/tls-client.md) или [TLS сервера](../common/tls-server.md). |

## Унаследованные поля

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `sniff` | boolean | -- | Определять домен из TLS SNI, HTTP Host и QUIC SNI. |
| `sniff_override_destination` | boolean | -- | Подменять адрес назначения найденным доменом при маршрутизации. |
| `sniff_timeout` | string | -- | Таймаут сниффинга. |
| `domain_strategy` | string | -- | Стратегия разрешения имён: `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only`. |
| `udp_disable_domain_unmapping` | boolean | -- | Не отображать найденный домен обратно в адрес назначения. |

## Связанные блоки

- [TLS сервера](../common/tls-server.md)
- [пользователи](../common/users.md)

---
