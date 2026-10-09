# Инбаунд `shadowsocks`

Серверная точка входа Shadowsocks (AEAD, включая 2022).

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
| `network` | string | -- | Какие сети задействовать: `tcp`, `udp` или список из обоих. |
| `method` | string | -- | Метод шифрования AEAD или `2022-blake3-*`. |
| `password` | string | -- | Пароль или PSK. |
| `users` | array | -- | Список пользователей, см. [users](../common/users.md). |
| `destinations` | string | -- | Через запятую список адресов назначения, которые нужно предать серверу. |
| `multiplex` | object | -- | Мультиплексирование соединений, см. [multiplex](../common/multiplex.md). |
| `managed` | boolean | -- | Режим серверного управления. |
| `tls` | object | -- | Блок TLS, см. [TLS клиента](../common/tls-client.md) или [TLS сервера](../common/tls-server.md). |

## Связанные блоки

- [TLS сервера](../common/tls-server.md)
- [мультиплексирование](../common/multiplex.md)
- [пользователи](../common/users.md)

## Серверная часть

Обязателен блок `users`. Пустой список пользователей — ошибка конфигурации.

Поведение без валидного клиента задаёт `fallback`: соединения уходят на указанный адрес вместо закрытия. Это позволяет скрыть факт прокси за обычным сайтом. У VLESS, VMess и Trojan поле называется `fallback`, у Shadowsocks — `destinations`.

---
