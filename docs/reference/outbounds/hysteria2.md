# Аутбаунд `hysteria2`

Аутбаунд Hysteria 2 поверх QUIC с обфускацией salamander и gecko.

## Обязательные поля

| Поле | Тип | Описание |
|---|---|---|
| `type` | string | Значение `hysteria2`. |
| `tag` | string | Имя объекта. По нему ссылаются `route.rules`, `dns.rules`, `detour` и группы. |
| `server` | string | Домен или IP-адрес сервера. |
| `server_port` | uint16 | Порт сервера. |

## Собственные поля

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `server_ports` | string / array | -- | Диапазоны портов для hopping, список строк вида `1000-2000`. |
| `hop_interval` | string | -- | Интервал перебора портов. |
| `hop_interval_max` | string | -- | Верхняя граница интервала перебора портов. |
| `up_mbps` | uint32 | -- | Скорость аплинка в Mbps. |
| `down_mbps` | uint32 | -- | Скорость даунлинка в Mbps. |
| `obfs` | object | -- | Обфускация: объект с `type: salamander` и `password`, либо строка-пароль. |
| `password` | string | -- | Пароль аутентификации. |
| `network` | string | -- | Какие сети задействовать. |
| `bbr_profile` | string | -- | Профиль BBR. |
| `brutal_debug` | boolean | -- | Отладочный вывод Brutal. |
| `disable_chrome_parrot` | boolean | -- | Отключить Chrome Parrot. |
| `realm` | string | -- | Область аутентификации. |
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
