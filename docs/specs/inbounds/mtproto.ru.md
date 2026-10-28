# Инбаунд: MTProto

Серверная точка входа MTProto с обфускацией потока.

## Схема конфигурации

| Поле | Тип | Обязательно | Описание |
|---|---|---|---|
| `type` | string | Да | Должно быть `"mtproto"`. |
| `tag` | string | Нет | Уникальный идентификатор инбаунда. |
| `listen` | string | Да | Адрес прослушивания. |
| `listen_port` | uint16 | Да | Порт прослушивания. |
| `secret` | string | Нет | 16-байтный hex-секрет (или с префиксом `dd`/`ee`). |
| `users` | array | Нет | Список клиентских секретов (`{"secret": "..."}`). |
| `transport` | string | Нет | Принудительный режим фрейминга (`"abridged"`, `"intermediate"`, `"padded"`, `"full"`). |
| `tls` | object | Нет | Опциональная обёртка серверного TLS. |

## Пример

```json
{
  "type": "mtproto",
  "tag": "mtproto-in",
  "listen": "::",
  "listen_port": 443,
  "users": [
    {
      "secret": "0123456789abcdef0123456789abcdef"
    }
  ],
  "transport": "padded"
}
```
