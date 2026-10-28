# Инбаунд: Mieru

Серверная точка входа Mieru с поддержкой зашифрованных транспортов TCP и UDP.

## Схема конфигурации

| Поле | Тип | Обязательно | Описание |
|---|---|---|---|
| `type` | string | Да | Должно быть `"mieru"`. |
| `tag` | string | Нет | Уникальный идентификатор инбаунда. |
| `listen` | string | Да | Адрес прослушивания. |
| `listen_port` | uint16 | Да | Порт прослушивания. |
| `transport` | string | Нет | `"tcp"` (по умолчанию) или `"udp"`. |
| `users` | array | Да | Список пользователей (`{"name": "...", "password": "..."}`). |

## Пример

```json
{
  "type": "mieru",
  "tag": "mieru-in",
  "listen": "::",
  "listen_port": 8388,
  "transport": "tcp",
  "users": [
    {
      "name": "alice",
      "password": "alice-secret-password"
    }
  ]
}
```
