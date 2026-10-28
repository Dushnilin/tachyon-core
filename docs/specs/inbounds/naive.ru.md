# Инбаунд: Naive

Серверная точка входа NaiveProxy. Принимает туннели CONNECT поверх HTTP/2 (TCP) и HTTP/3 (QUIC) с паддингом Naive и Basic-авторизацией.

## Схема конфигурации

| Поле | Тип | Обязательно | Описание |
|---|---|---|---|
| `type` | string | Да | Должно быть `"naive"`. |
| `tag` | string | Нет | Уникальный идентификатор инбаунда. |
| `listen` | string | Да | Адрес прослушивания. |
| `listen_port` | uint16 | Да | Порт прослушивания. |
| `network` | string | Нет | `"tcp"` только для HTTP/2, либо не указано (HTTP/2 + HTTP/3 QUIC). |
| `users` | array | Да | Список пользователей (`{"username": "...", "password": "..."}`). |
| `tls` | object | Да | Конфигурация серверного TLS. |

## Пример

```json
{
  "type": "naive",
  "tag": "naive-in",
  "listen": "::",
  "listen_port": 443,
  "users": [
    {
      "username": "naiveuser",
      "password": "naivepassword"
    }
  ],
  "tls": {
    "enabled": true,
    "certificate_path": "/etc/tachyon/cert.pem",
    "key_path": "/etc/tachyon/key.pem"
  }
}
```
