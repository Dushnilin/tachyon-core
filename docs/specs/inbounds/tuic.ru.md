# TUIC Входящий (Inbound)

TUIC v5 — это высокопроизводительный прокси-протокол на основе QUIC, поддерживающий 0-RTT и встроенное мультиплексирование.

## Схема

| Поле | Тип | По умолчанию | Описание |
|------|------|--------------|----------|
| type | string | - | Должно быть "tuic" |
| tag | string | - | Уникальный идентификатор |
| listen | string | "0.0.0.0" | Адрес для бинда |
| listen_port | integer | - | Обязательно |
| users | array | - | Пользователи (uuid, password) |
| tls | object | - | TLS конфигурация (Обязательно) |

## Пример

```json
{
  "type": "tuic",
  "tag": "tuic-in",
  "listen": "0.0.0.0",
  "listen_port": 443,
  "users": [
    {
      "name": "user1",
      "uuid": "c5d6e7f8-1234-5678-90ab-cdef01234567",
      "password": "password"
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

- TLS обязателен для TUIC v5.
- TUIC отлично подходит для соединений с высокой задержкой благодаря протоколу QUIC.
