# Аутбаунд `naive`

Аутбаунд NaiveProxy: HTTP/2 или HTTP/3 с TLS.

## Обязательные поля

| Поле | Тип | Описание |
|---|---|---|
| `type` | string | Значение `naive`. |
| `tag` | string | Имя объекта. По нему ссылаются `route.rules`, `dns.rules`, `detour` и группы. |
| `server` | string | Домен или IP-адрес сервера. |
| `server_port` | uint16 | Порт сервера. |

## Собственные поля

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `username` | string | -- | Имя пользователя. |
| `password` | string | -- | Пароль. |
| `insecure_concurrency` | boolean | -- | Разрешить небезопасные параллельные запросы. |
| `extra_headers` | array | -- | Массив дополнительных HTTP-заголовков вида `"Name: Value"`. |
| `stream_receive_window` | string | -- | Окно приёма потока, размер с суффиксом. |
| `udp_over_tcp` | object | -- | Пробрасывать UDP через TCP. |
| `quic` | boolean | -- | Использовать HTTP/3 вместо HTTP/2. |
| `quic_congestion_control` | string | -- | Алгоритм перегрузки: `bbr`, `bbr2`, `cubic`, `reno`. |
| `quic_session_receive_window` | string | -- | Окно приёма QUIC-сессии. |

## Общие поля

Поля диалера — [dialer](../common/dialer.md): `detour`, `bind_interface`, `routing_mark`, `inet4_bind_address`, `inet6_bind_address`, `connect_timeout`, `domain_strategy`, `network_strategy`, `network_type`, `fallback_network_type`, `fallback_delay`, `tcp_multi_path`, `tcp_fast_open`, `tcp_keep_alive`, `udp_fragment`, `netns`, `protect_path`, `domain_resolver`, `bind_address_no_port`, `reuse_addr`, `disable_tcp_keep_alive`, `tcp_keep_alive_interval`.


## TLS

Блок `tls` — [tls-client](../common/tls-client.md).


## Ограничения

`insecure: true` и `disable_sni: true` внутри `tls` запрещены: валидатор отклоняет конфиг. Причина — NaiveProxy без проверки сертификата не защищает канал.
