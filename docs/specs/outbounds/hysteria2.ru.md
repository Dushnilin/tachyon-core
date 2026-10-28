# Исходящее подключение Hysteria2

Быстрый UDP-прокси-протокол на базе QUIC с алгоритмом перегрузки BRUTAL и опциональной обфускацией.

## Схема

| Поле | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `type` | string | — | Обязательно `"hysteria2"` |
| `tag` | string | — | Уникальный идентификатор исходящего подключения |
| `server` | string | — | Имя хоста или IP-адрес сервера |
| `server_port` | integer | — | Порт сервера (несовместимо с `server_ports`) |
| `server_ports` | string | — | Диапазон портов для прыжков, например `"10000:20000"` |
| `hop_interval` | duration | `"30s"` | Интервал смены порта (только в режиме port hopping) |
| `obfs.type` | string | — | Тип обфускации; поддерживается только `"salamander"` |
| `obfs.password` | string | — | Пароль обфускации |
| `password` | string | — | **Обязательно.** Пароль аутентификации Hysteria2 |
| `up_mbps` | integer | `0` | Лимит исходящей полосы в Мбит/с; `0` = без ограничений |
| `down_mbps` | integer | `0` | Лимит входящей полосы в Мбит/с; `0` = без ограничений |
| `brutal_debug` | bool | `false` | Включить отладочные логи BRUTAL CC |
| `tls.enabled` | bool | — | **Обязательно**, должно быть `true` |
| `tls.server_name` | string | — | Переопределение SNI |
| `tls.insecure` | bool | `false` | Пропустить проверку TLS-сертификата |
| `tls.alpn` | string[] | `["h3"]` | Список ALPN |
| `tls.certificate_path` | string | — | Путь к корневому CA-сертификату |

> Dial-поля (`detour`, `bind_interface`, `inet4_bind_address`, `inet6_bind_address`, `connect_timeout`, `tcp_fast_open`, `domain_strategy`) поддерживаются — см. общую документацию по dial.

## Пример

```json
{
  "type": "hysteria2",
  "tag": "hy2-out",
  "server": "example.com",
  "server_port": 443,
  "password": "your-hy2-password",
  "up_mbps": 100,
  "down_mbps": 200,
  "tls": {
    "enabled": true,
    "server_name": "example.com"
  }
}
```

### Пример с port hopping

```json
{
  "type": "hysteria2",
  "tag": "hy2-hop",
  "server": "example.com",
  "server_ports": "10000:20000",
  "hop_interval": "30s",
  "password": "your-hy2-password",
  "obfs": {
    "type": "salamander",
    "password": "obfs-secret"
  },
  "tls": {
    "enabled": true,
    "server_name": "example.com"
  }
}
```

## Примечания

- `server_port` и `server_ports` взаимоисключающи; используйте `server_ports` для port hopping.
- `tls.enabled` всегда должно быть `true` — Hysteria2 работает исключительно через TLS.
- BRUTAL игнорирует сигналы справедливого разделения полосы; задавайте `up_mbps`/`down_mbps` точно, чтобы не деградировать общие каналы.
- Обфускация salamander делает пакеты похожими на случайный UDP; требует соответствующей настройки на сервере.
- Изменение `alpn` от значения по умолчанию `["h3"]` скорее всего нарушит совместимость со стандартными серверами Hysteria2.
