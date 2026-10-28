# VLESS Входящий (Inbound)

VLESS — это легковесный прокси-протокол без собственного шифрования, предназначенный для использования вместе с TLS/REALITY. Поддерживает контроль потока Vision и XUDP.

## Схема

| Поле | Тип | По умолчанию | Описание |
|------|------|--------------|----------|
| type | string | - | Должно быть "vless" |
| tag | string | - | Уникальный идентификатор |
| listen | string | "0.0.0.0" | Адрес для бинда |
| listen_port | integer | - | Обязательно |
| users | array | - | Список разрешенных пользователей |
| tls | object | - | TLS конфигурация сервера |

## Пример

```json
{
  "type": "vless",
  "tag": "vless-in",
  "listen": "0.0.0.0",
  "listen_port": 443,
  "users": [
    {
      "name": "user1",
      "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf",
      "flow": "xtls-rprx-vision"
    }
  ],
  "tls": {
    "enabled": true,
    "reality": {
      "enabled": true,
      "handshake": { "server": "google.com", "server_port": 443 },
      "private_key": "..."
    }
  }
}
```

## Примечания

- VLESS сам по себе не обеспечивает шифрования. TLS или REALITY обязательны для безопасности транспорта.
- Использование Vision крайне рекомендуется для улучшения производительности при обходе DPI.
