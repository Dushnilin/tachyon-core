# Аутбаунд `tuic`

Аутбаунд TUIC v5 поверх QUIC.

## Обязательные поля

| Поле | Тип | Описание |
|---|---|---|
| `type` | string | Значение `tuic`. |
| `tag` | string | Имя объекта. По нему ссылаются `route.rules`, `dns.rules`, `detour` и группы. |
| `server` | string | Домен или IP-адрес сервера. |
| `server_port` | uint16 | Порт сервера. |

## Собственные поля

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `uuid` | string | -- | Идентификатор пользователя. |
| `password` | string | -- | Пароль. |
| `congestion_control` | string | -- | Алгоритм перегрузки: `bbr`, `bbr2`, `cubic`, `reno`. |
| `udp_relay_mode` | string | -- | Режим ретрансляции UDP: `native`, `quic`, `pktaddr`. |
| `udp_over_stream` | boolean | -- | Передавать UDP поверх потоков QUIC. |
| `zero_rtt_handshake` | boolean | -- | Рукопожатие 0-RTT. |
| `heartbeat` | string | -- | Интервал heartbeat-пакетов. |
| `network` | string | -- | Какие сети задействовать. |
| `tls` | object | -- | Блок TLS, см. [TLS клиента](../common/tls-client.md) или [TLS сервера](../common/tls-server.md). |

## Общие поля

Поля диалера — [dialer](../common/dialer.md), блок `tls` — [tls-client](../common/tls-client.md).


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
