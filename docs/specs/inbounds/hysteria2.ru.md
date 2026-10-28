# Инбаунд: Hysteria2

Серверная точка входа Hysteria 2 поверх QUIC/HTTP3 с поддержкой UDP-обфускации Salamander.

## Схема конфигурации

| Поле | Тип | Обязательно | Описание |
|---|---|---|---|
| `type` | string | Да | Должно быть `"hysteria2"`. |
| `tag` | string | Нет | Уникальный идентификатор инбаунда. |
| `listen` | string | Да | Адрес прослушивания. |
| `listen_port` | uint16 | Да | UDP-порт прослушивания. |
| `users` | array | Да | Список пользователей (`{"name": "...", "password": "..."}`). |
| `up_mbps` | uint64 | Нет | Лимит входящей полосы (Мбит/с). |
| `down_mbps` | uint64 | Нет | Лимит исходящей полосы (Мбит/с). |
| `obfs` | object | Нет | Обфускация Salamander (`{"type": "salamander", "password": "..."}`). |
| `tls` | object | Да | Конфигурация серверного TLS. |

## Пример

```json
{
  "type": "hysteria2",
  "tag": "hy2-in",
  "listen": "::",
  "listen_port": 443,
  "users": [
    {
      "name": "client1",
      "password": "hy2-secret-password"
    }
  ],
  "up_mbps": 100,
  "down_mbps": 100,
  "obfs": {
    "type": "salamander",
    "password": "salamander-obfs-key"
  },
  "tls": {
    "enabled": true,
    "certificate_path": "/etc/tachyon/cert.pem",
    "key_path": "/etc/tachyon/key.pem"
  }
}
```
