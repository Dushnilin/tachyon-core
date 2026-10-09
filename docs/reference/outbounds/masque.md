# Аутбаунд `masque`

Аутбаунд MASQUE (CONNECT-IP), транспорт для Cloudflare WARP.

## Обязательные поля

| Поле | Тип | Описание |
|---|---|---|
| `type` | string | Значение `masque`. |
| `tag` | string | Имя объекта. По нему ссылаются `route.rules`, `dns.rules`, `detour` и группы. |
| `server` | string | Домен или IP-адрес сервера. |
| `server_port` | uint16 | Порт сервера. |

## Собственные поля

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `profile` | string | -- | Профиль MASQUE. |
| `vhttp` | object | -- | Блок конфигурации vhttp. |
| `network` | string | -- | Какие сети задействовать. |
| `private_key` | string | -- | Закрытый ключ X25519 в base64. |
| `public_key` | string | -- | Открытый ключ сервера в base64. |
| `ip` | string | -- | IP-адрес туннеля. |
| `ipv6` | string | -- | IPv6-адрес туннеля. |
| `uri` | string | -- | URI маскировки. |
| `mtu` | uint32 | -- | MTU туннеля. |
| `sni` | string | -- | SNI для маскировки. |
| `skip_cert_verify` | boolean | -- | Не проверять сертификат. |
| `fragment` | object | -- | Фрагментация TLS ClientHello. |
| `fragment_fallback_delay` | string | -- | Задержка перед фрагментацией. |
| `record_fragment` | object | -- | Фрагментация записей TLS. |
| `idle_timeout` | string | -- | Таймаут простоя. |
| `keep_alive_period` | string | -- | Период keep-alive. |
| `network_list` | string | -- | Список сетей для vhttp. |
| `tls` | object | -- | Блок TLS, см. [TLS клиента](../common/tls-client.md) или [TLS сервера](../common/tls-server.md). |

## Общие поля

Поля диалера — [dialer](../common/dialer.md), блок `tls` — [tls-client](../common/tls-client.md).


## Ограничения

Реализован профиль CONNECT-IP для Cloudflare WARP. Часть полей (`vhttp`, `network_list`, `uri`, `sni`) принимается конфигом и используется ограниченно.
