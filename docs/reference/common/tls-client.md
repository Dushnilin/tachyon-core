# TLS клиента (аутбаунды)

Блок `tls` у клиентских аутбаундов: `socks`, `http`, `shadowsocks`,
`shadowtls`, `vmess`, `vless`, `trojan`, `hysteria`, `hysteria2`, `tuic`,
`anytls`, `naive`, `masque`, `fptn`, а также у клиентских инбаундов `mixed`
и `http`.

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `enabled` | boolean | — | Включить TLS. Обычно подразумевается наличием других полей блока. |
| `engine` | string | — | Движок TLS: `rustls`, `boring`, `go`, `openssl`. |
| `disable_sni` | boolean | — | Не отправлять SNI в ClientHello. |
| `server_name` | string | — | SNI и имя для проверки сертификата. |
| `insecure` | boolean | — | Не проверять сертификат и имя. |
| `alpn` | string / array | — | Список протоколов ALPN в ClientHello. |
| `min_version` | string | — | Минимальная версия TLS: `1.0`, `1.1`, `1.2`, `1.3`. |
| `max_version` | string | — | Максимальная версия TLS. |
| `cipher_suites` | string / array | — | Разрешённые шифры для исходящих соединений. |
| `curve_preferences` | string / array | — | Разрешённые эллиптические кривые. |
| `certificate` | string | — | Сертификат в формате PEM прямо в конфиге. |
| `certificate_path` | string | — | Путь к файлу сертификата. |
| `certificate_public_key_sha256` | string / array | — | Ожидаемые SHA-256 публичного ключа сертификата. |
| `certificate_sha256` | string / array | — | Ожидаемый SHA-256 отпечаток сертификата. |
| `client_certificate` | string | — | Клиентский сертификат PEM в конфиге. |
| `client_certificate_path` | string | — | Путь к клиентскому сертификату. |
| `client_key` | string | — | Клиентский закрытый ключ PEM в конфиге. |
| `client_key_path` | string | — | Путь к клиентскому ключу. |
| `fragment` | object | — | Фрагментация ClientHello: padding TLS 1.3. |
| `fragment_fallback_delay` | string | — | Задержка перед фрагментацией. |
| `record_fragment` | object | — | Фрагментация записей TLS: размер в байтах и интервал. |
| `spoof` | string | — | Маскировка размера ClientHello. |
| `spoof_method` | string | — | Способ маскировки. |
| `kernel_tx` | boolean | — | Использовать kernel TLS для отправки. |
| `kernel_rx` | boolean | — | Использовать kernel TLS для приёма. |
| `handshake_timeout` | string | — | Таймаут TLS-рукопожатия, вида `10s`. |
| `ech` | object | — | Encrypted Client Hello. |
| `utls` | object | — | Маскировка ClientHello под браузер. |
| `reality` | object | — | REALITY. |

## uTLS

```json
"tls": {
  "enabled": true,
  "server_name": "example.com",
  "utls": { "enabled": true, "fingerprint": "chrome" }
}
```

Доступные отпечатки: `chrome`, `chrome_psk`, `chrome_psk_shuffle`,
`chrome_padding_psk_shuffle`, `chrome_pq`, `chrome_pq_psk`, `firefox`,
`safari`, `edge`, `360`, `qq`, `ios`, `android`, `randomized`, `random`.

Реализация чистая, на собственном ClientHello — внешние C-библиотеки не
задействованы.

## REALITY

```json
"tls": {
  "enabled": true,
  "server_name": "example.com",
  "utls": { "enabled": true, "fingerprint": "chrome" },
  "reality": {
    "enabled": true,
    "public_key": "...",
    "short_id": "0123456789abcdef",
    "key_share": ""
  }
}
```

Поля блока `reality`: `enabled`, `public_key`, `short_id`, `key_share`.

## Ограничения

- У аутбаунда `naive` запрещены `insecure: true` и `disable_sni: true` —
  валидатор отклоняет конфиг: `insecure is not supported on naive outbound`.
- `utls_over_tls` у `vless` не поддерживается.
