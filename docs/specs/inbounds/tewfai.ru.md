# Инбаунд: Tewfai

Серверная точка входа мульти-транспортного протокола Tewfai. Поддерживает носители TCP (TLS 1.3 / REALITY) и QUIC, бесшовную миграцию сессий (`RESUME`), прямую коррекцию ошибок (FEC) и шейпинг/морфинг трафика.

## Схема конфигурации

| Поле | Тип | Обязательно | Описание |
|---|---|---|---|
| `type` | string | Да | Должно быть `"tewfai"`. |
| `tag` | string | Нет | Уникальный идентификатор инбаунда. |
| `listen` | string | Да | Адрес прослушивания. |
| `listen_port` | uint16 | Да | Порт прослушивания. |
| `users` | array | Да | Список пользователей (`{"uuid": "..."}` или `{"password": "..."}`). |
| `transport` | string / array | Нет | `"tcp"`, `"quic"` или `["tcp", "quic"]`. |
| `inner_cipher` | string | Нет | `"aes-256-gcm"` или `"none"` (по умолчанию `"none"` при активном внешнем TLS). |
| `fec` | boolean | Нет | Включить XOR FEC для UDP-дейтаграмм. |
| `max_streams` | uint16 | Нет | Максимум одновременных потоков на сессию (по умолчанию: `256`). |
| `handover` | object | Нет | Настройки восстановления сессий (`{"enabled": true, "grace_secs": 60}`). |
| `tls` | object | Нет | Конфигурация серверного TLS или REALITY. |

## Пример

```json
{
  "type": "tewfai",
  "tag": "tewfai-in",
  "listen": "::",
  "listen_port": 443,
  "transport": ["tcp", "quic"],
  "users": [
    {
      "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811"
    }
  ],
  "fec": true,
  "tls": {
    "enabled": true,
    "certificate_path": "/etc/tachyon/cert.pem",
    "key_path": "/etc/tachyon/key.pem"
  }
}
```
