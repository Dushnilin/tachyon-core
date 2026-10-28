# VMess Входящий (Inbound)

VMess — это классический протокол V2Ray со встроенной аутентификацией, поддерживающий различные транспорты (TCP, WS, GRPC, HTTPUpgrade).

## Схема

| Поле | Тип | По умолчанию | Описание |
|------|------|--------------|----------|
| type | string | - | Должно быть "vmess" |
| tag | string | - | Уникальный идентификатор |
| listen | string | "0.0.0.0" | Адрес для бинда |
| listen_port | integer | - | Обязательно |
| users | array | - | Список пользователей (uuid, alterId) |
| tls | object | - | TLS конфигурация сервера |

## Пример

```json
{
  "type": "vmess",
  "tag": "vmess-in",
  "listen": "0.0.0.0",
  "listen_port": 10000,
  "users": [
    {
      "name": "user1",
      "uuid": "b3e4e91a-8a6d-4b88-b7e5-3b7a8c1e2f3d",
      "alterId": 0
    }
  ],
  "tls": {
    "enabled": true,
    "certificate_path": "/etc/tachyon/cert.pem",
    "key_path": "/etc/tachyon/key.pem"
  }
}
```

## Примечания

- `alterId` должен быть равен 0 для включения AEAD.
- VMess поддерживает множество транспортов; убедитесь, что конфигурация транспорта соответствует настройкам клиента.
