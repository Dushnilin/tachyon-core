# Инбаунд: AnyTLS

Серверная точка входа AnyTLS. Маскирует прокси-трафик внутри стандартных соединений TLS 1.3 с настраиваемыми схемами паддинга и мультиплексированием.

## Схема конфигурации

| Поле | Тип | Обязательно | Описание |
|---|---|---|---|
| `type` | string | Да | Должно быть `"anytls"`. |
| `tag` | string | Нет | Уникальный идентификатор инбаунда. |
| `listen` | string | Да | Адрес прослушивания (например, `"::"` или `"0.0.0.0"`). |
| `listen_port` | uint16 | Да | Порт прослушивания. |
| `users` | array | Да | Список пользователей (`{"name": "...", "password": "..."}`). |
| `padding_scheme` | array of strings | Нет | Пользовательские правила паддинга трафика. |
| `tls` | object | Да | Конфигурация серверного TLS (`enabled: true`, `certificate_path`, `key_path`). |

## Пример

```json
{
  "type": "anytls",
  "tag": "anytls-in",
  "listen": "::",
  "listen_port": 443,
  "users": [
    {
      "name": "user1",
      "password": "super-secret-password"
    }
  ],
  "tls": {
    "enabled": true,
    "certificate_path": "/etc/tachyon/cert.pem",
    "key_path": "/etc/tachyon/key.pem"
  }
}
```
