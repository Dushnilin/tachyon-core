# TLS сервера (инбаунды)

Блок `tls` у серверных инбаундов: `vless`, `vmess`, `trojan`, `shadowsocks`,
`shadowtls`, `anytls`, `naive`, `hysteria`, `hysteria2`, `tuic`, `snell`,
`fptn`, а также у клиентских `mixed` и `http`.

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `enabled` | boolean | — | Включить TLS на серверной стороне. |
| `server_name` | string | — | Имя сервера. |
| `insecure` | boolean | — | Не проверять клиентский сертификат. |
| `alpn` | string / array | — | Протоколы ALPN, которые предлагает сервер. |
| `min_version` | string | — | Минимальная версия TLS. |
| `max_version` | string | — | Максимальная версия TLS. |
| `cipher_suites` | string / array | — | Разрешённые шифры. |
| `curve_preferences` | string / array | — | Разрешённые кривые. |
| `certificate` | string | — | Сертификат PEM в конфиге. |
| `certificate_path` | string | — | Путь к файлу сертификата. |
| `client_authentication` | boolean | — | Требовать клиентский сертификат. |
| `client_certificate` | string | — | Сертификат клиента, если он используется вместо проверки. |
| `client_certificate_path` | string | — | Путь к сертификату клиента. |
| `client_certificate_public_key_sha256` | string / array | — | Ожидаемые SHA-256 публичного ключа клиентского сертификата. |
| `key` | string | — | Закрытый ключ PEM в конфиге. |
| `key_path` | string | — | Путь к файлу закрытого ключа. |
| `certificate_provider` | string | — | Источник сертификата: `local`, `acme`, `self`. |
| `acme` | object | — | Автоматическая выдача сертификата через ACME. |
| `ech` | object | — | Encrypted Client Hello. |
| `reality` | object | — | REALITY на стороне сервера. |
| `kernel_tx` | boolean | — | Kernel TLS для отправки. |
| `kernel_rx` | boolean | — | Kernel TLS для приёма. |
| `handshake_timeout` | string | — | Таймаут рукопожатия. |

## Источник сертификата

`certificate_provider` выбирает, откуда взять сертификат:

- `local` — из полей `certificate_path` и `key_path`;
- `self` — сгенерировать самоподписанный;
- `acme` — получить автоматически, см. блок `acme`.

## ACME

Поля блока: `type`, `domain`, `data_directory`, `default_server_name`, `email`, `provider`, `account_key`, `disable_http_challenge`, `disable_tls_alpn_challenge`, `alternative_http_port`, `alternative_tls_port`, `external_account`, `dns01_challenge`, `http_challenge`, `challenges`

Поддерживаемые DNS-провайдеры ACME: `cloudflare`, `alidns`, `duckdns`,
`google cloud dns`, `azure`, `rfc2136`, `acme dns`, `http`, `local`.

## TLS 1.3

Собственная реализация TLS 1.3 на чистом Rust: X25519, набор шифров, ALPN —
поверх любого потока `AsyncRead + AsyncWrite`, без внешних зависимостей.
