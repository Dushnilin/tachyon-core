# Аутбаунд `hysteria`

> **Принимается проверкой конфига, но не реализован в рантайме.** `run` завершится ошибкой `outbound type "hysteria" not implemented yet`.
Аутбаунд Hysteria 1 (UDP).

## Обязательные поля

| Поле | Тип | Описание |
|---|---|---|
| `type` | string | Значение `hysteria`. |
| `tag` | string | Имя объекта. По нему ссылаются `route.rules`, `dns.rules`, `detour` и группы. |
| `server` | string | Домен или IP-адрес сервера. |
| `server_port` | uint16 | Порт сервера. |

## Собственные поля

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `server_ports` | string / array | -- | Диапазоны портов для hopping, список строк вида `1000-2000`. |
| `hop_interval` | string | -- | Интервал перебора портов. `30s` означает диапазон 30–60 с. |
| `up` | string | -- | Скорость аплинка клиента: `100Mb`, `100Mbps` или число. |
| `up_mbps` | uint32 | -- | Скорость аплинка в Mbps. |
| `down` | string | -- | Скорость даунлинка клиента. |
| `down_mbps` | uint32 | -- | Скорость даунлинка в Mbps. |
| `obfs` | object | -- | Обфускация, объект с `type` и `password`. |
| `auth` | string | -- | Строка аутентификации. |
| `auth_str` | string | -- | Строка аутентификации. |
| `recv_window_conn` | uint32 | -- | Окно приёма соединения, байт. |
| `recv_window` | uint32 | -- | Окно приёма, байт. |
| `disable_mtu_discovery` | boolean | -- | Не определять MTU пути. |
| `network` | string | -- | Какие сети задействовать. |

## Общие поля

Поля диалера — [dialer](../common/dialer.md): `detour`, `bind_interface`, `routing_mark`, `inet4_bind_address`, `inet6_bind_address`, `connect_timeout`, `domain_strategy`, `network_strategy`, `network_type`, `fallback_network_type`, `fallback_delay`, `tcp_multi_path`, `tcp_fast_open`, `tcp_keep_alive`, `udp_fragment`, `netns`, `protect_path`, `domain_resolver`, `bind_address_no_port`, `reuse_addr`, `disable_tcp_keep_alive`, `tcp_keep_alive_interval`.


## TLS

Блок `tls` — [tls-client](../common/tls-client.md).


## QUIC

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `idle_timeout` | string | -- | Таймаут простоя соединения. |
| `keep_alive_period` | string | -- | Период отправки keep-alive пакетов. |
| `stream_receive_window` | string | -- | Окно приёма одного потока. |
| `connection_receive_window` | uint32 | -- | Окно приёма соединения. |
| `max_concurrent_streams` | uint32 | -- | Максимум одновременных потоков. |
| `initial_packet_size` | uint32 | -- | Начальный размер QUIC-пакета. |
| `disable_path_mtu_discovery` | boolean | -- | Не определять MTU пути. |
