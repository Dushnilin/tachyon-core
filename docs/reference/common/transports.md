# Транспорты

Блок `transport` меняет способ доставки данных внутри протокола, маскируя
трафик под обычный HTTP. Поддерживается у аутбаундов `vless`, `vmess` и у
серверных инбаундов `vless`, `vmess`, `trojan`, `shadowsocks`.

Тип задаётся полем `type`: `http`, `ws`, `quic`, `grpc`, `httpupgrade`,
`xhttp`.

## http

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `host` | string / array | — | Значение заголовка Host. |
| `path` | string | — | Путь запроса. |
| `method` | string | — | HTTP-метод. |
| `headers` | object | — | Дополнительные заголовки. |
| `idle_timeout` | string | — | Таймаут простоя. |
| `ping_timeout` | string | — | Таймаут ping-сообщения. |

## ws

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `path` | string | — | Путь запроса. |
| `headers` | object | — | Дополнительные заголовки. |
| `max_early_data` | uint32 | — | Объём ранних данных, байт. |
| `early_data_header_name` | string | — | Заголовок, в котором передаются ранние данные. |

## grpc

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `service_name` | string | — | Имя gRPC-сервиса. |
| `idle_timeout` | string | — | Таймаут простоя. |
| `ping_timeout` | string | — | Таймаут ping-сообщения. |
| `permit_without_stream` | boolean | — | Разрешить работу без активного потока. |

## httpupgrade

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `host` | string | — | Значение заголовка Host. |
| `path` | string | — | Путь запроса. |
| `headers` | object | — | Дополнительные заголовки. |

## quic

Тип `quic` дополнительных полей не имеет.

## xhttp

Режимы (`mode`): `auto`, `packet-up`, `stream-up`, `stream-one`. Пустая строка
означает `auto`.

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `host` | string / array | — | Значение заголовка Host. |
| `path` | string | — | Путь запроса. |
| `mode` | string | — | Режим: `auto`, `packet-up`, `stream-up`, `stream-one`. |
| `headers` | object | — | Дополнительные заголовки. |
| `x_padding_bytes` | string | — | Диапазон паддинга, вида `100-1000`. |
| `xmux` | object | — | Настройки мультиплексирования. |
| `no_grpc_header` | boolean | — | Не отправлять gRPC-заголовок. |
| `session_placement` | string | — | Где размещать идентификатор сессии. |
| `session_key` | string | — | Ключ извлечения сессии. |
| `seq_placement` | string | — | Где размещать порядковый номер. |
| `seq_key` | string | — | Ключ извлечения номера. |
| `session_table` | string | — | Хеш-таблица сессий. |
| `session_length` | string | — | Длина идентификатора сессии. |
| `uplink_data_placement` | string | — | Размещение данных аплинка. |
| `uplink_data_key` | string | — | Ключ извлечения данных аплинка. |
| `uplink_chunk_size` | string | — | Размер чанка аплинка. |
| `uplink_http_method` | string | — | HTTP-метод аплинка. `GET` вне `packet-up` — программное отклонение с предупреждением в рантайме. |
| `x_padding_obfs_mode` | string | — | Режим обфускации паддинга. |
| `x_padding_key` | string | — | Ключ паддинга. |
| `x_padding_header` | string | — | Заголовок паддинга. |
| `x_padding_placement` | string | — | Размещение паддинга. |
| `x_padding_method` | string | — | Метод паддинга. |
| `sc_max_each_post_bytes` | string | — | Максимум байт в одном POST. |
| `sc_min_posts_interval_ms` | string | — | Минимальный интервал между POST, мс. |
| `sc_max_concurrent_posts` | string | — | Максимум одновременных POST. |
| `server_max_header_bytes` | string | — | Максимум байт в заголовках сервера. |
| `no_sse_header` | boolean | — | Не отправлять заголовок SSE. |
| `sc_max_buffered_posts` | string | — | Максимум буферизованных POST. |
| `sc_stream_up_server_secs` | string | — | Время жизни сервера в `stream-up`, секунды. |

Пул соединений `H2Pool` держит до четырёх параллельных TCP/TLS-сокетов с
балансировкой стримов по наименее загруженному, расширенные окна потока 4 MiB и
соединения 16 MiB. На мультиплексированных стримах это 4.4+ Gbit/s и задержка
первого байта 408 µs против ~30 мс у Go-ядер.

## Формат XHTTP в подписках

Поля xhttp приходят из vless-ссылок параметрами `type=xhttp`, `path`, `host`,
`mode`, `extra`. Пример разобранной ссылки:

```
vless://uuid@host:443?security=none&type=xhttp&path=/api/x&mode=packet-up#name
```
