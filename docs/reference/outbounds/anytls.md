# Аутбаунд `anytls`

Аутбаунд AnyTLS.

## Обязательные поля

| Поле | Тип | Описание |
|---|---|---|
| `type` | string | Значение `anytls`. |
| `tag` | string | Имя объекта. По нему ссылаются `route.rules`, `dns.rules`, `detour` и группы. |
| `server` | string | Домен или IP-адрес сервера. |
| `server_port` | uint16 | Порт сервера. |

## Собственные поля

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `tls` | object | -- | Блок TLS, см. [TLS клиента](../common/tls-client.md) или [TLS сервера](../common/tls-server.md). |
| `password` | string | -- | Пароль. |
| `idle_session_check_interval` | string | -- | Интервал проверки простоя сессии. |
| `idle_session_timeout` | string | -- | Таймаут простоя сессии. |
| `min_idle_session` | uint32 | -- | Минимум живых сессий в простое. |
| `client_metadata` | boolean | -- | Передавать метаданные клиента. |

## Общие поля

Поля диалера — [dialer](../common/dialer.md), блок `tls` — [tls-client](../common/tls-client.md).
