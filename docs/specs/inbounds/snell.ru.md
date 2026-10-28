# Инбаунд: Snell

Серверная точка входа Snell v4/v5/v6 с поддержкой переиспользования TCP-соединений (`CMD_CONNECT_V2`) и релея UDP (`CMD_UDP`).

## Схема конфигурации

| Поле | Тип | Обязательно | Описание |
|---|---|---|---|
| `type` | string | Да | Должно быть `"snell"`. |
| `tag` | string | Нет | Уникальный идентификатор инбаунда. |
| `listen` | string | Да | Адрес прослушивания. |
| `listen_port` | uint16 | Да | Порт прослушивания. |
| `psk` | string | Да | Предварительно согласованный ключ (Pre-shared key). |
| `version` | uint8 | Нет | Версия протокола: `4`, `5` (по умолчанию) или `6`. |
| `mode` | string | Нет | Режим Snell v6 (`"default"`, `"ascii"`, `"custom"`). |
| `users` | array | Нет | Опциональный список паролей пользователей (`{"password": "..."}`). |

## Пример

```json
{
  "type": "snell",
  "tag": "snell-in",
  "listen": "::",
  "listen_port": 8389,
  "version": 5,
  "psk": "my-snell-pre-shared-key"
}
```
