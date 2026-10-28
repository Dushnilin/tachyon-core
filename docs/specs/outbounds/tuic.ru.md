# Исходящее подключение TUIC

TUIC v5 прокси на базе QUIC с поддержкой 0-RTT рукопожатия и гибкими режимами ретрансляции UDP.

## Схема

| Поле | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `type` | string | — | Обязательно `"tuic"` |
| `tag` | string | — | Уникальный идентификатор исходящего подключения |
| `server` | string | — | Имя хоста или IP-адрес сервера |
| `server_port` | integer | — | Порт сервера |
| `uuid` | string | — | **Обязательно.** UUID клиента (формат RFC 4122) |
| `password` | string | — | **Обязательно.** Пароль аутентификации |
| `congestion_control` | string | `"cubic"` | Алгоритм управления перегрузкой QUIC: `"cubic"`, `"new_reno"` или `"bbr"` |
| `udp_relay_mode` | string | `"native"` | Режим ретрансляции UDP: `"native"` (UDP-через-UDP) или `"quic"` (UDP-через-QUIC-стримы) |
| `zero_rtt_handshake` | bool | `false` | Включить 0-RTT рукопожатие QUIC (снижает задержку, небольшой риск replay) |
| `heartbeat` | duration | `"10s"` | Интервал keep-alive heartbeat |
| `tls.enabled` | bool | — | **Обязательно**, должно быть `true` |
| `tls.server_name` | string | — | Переопределение SNI |
| `tls.alpn` | string[] | `["h3"]` | Список ALPN |
| `tls.insecure` | bool | `false` | Пропустить проверку TLS-сертификата |

> Dial-поля (`detour`, `bind_interface`, `connect_timeout`, `domain_strategy` и др.) поддерживаются — см. общую документацию по dial.

## Пример

```json
{
  "type": "tuic",
  "tag": "tuic-out",
  "server": "example.com",
  "server_port": 443,
  "uuid": "c5d6e7f8-1234-5678-90ab-cdef01234567",
  "password": "s3cr3tP@ss",
  "congestion_control": "bbr",
  "udp_relay_mode": "quic",
  "tls": {
    "enabled": true,
    "server_name": "example.com",
    "alpn": ["h3"]
  }
}
```

## Примечания

- `tls.enabled` всегда должно быть `true` — TUIC v5 работает исключительно через TLS.
- `udp_relay_mode: "quic"` инкапсулирует UDP внутри QUIC-стримов: надёжнее на нестабильных каналах, но с большими накладными расходами по сравнению с `"native"`.
- `congestion_control: "bbr"` как правило эффективнее на высоколатентных или высокоскоростных соединениях; `"cubic"` — безопасный дефолт.
- `zero_rtt_handshake` снижает задержку установки соединения, но создаёт риск replay-атак — не включайте в ненадёжных сетях без дополнительных мер.
- `uuid` должен быть валидным UUID в формате RFC 4122 и точно совпадать с конфигурацией сервера.
