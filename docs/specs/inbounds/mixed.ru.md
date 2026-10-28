# Инбаунд: Mixed / SOCKS / HTTP

Стандартный локальный прокси-сервер.
- `"mixed"`: Принимает SOCKS4, SOCKS4a, SOCKS5 (включая UDP ASSOCIATE) и HTTP/HTTPS CONNECT на одном порту.
- `"socks"`: Принимает только протоколы семейства SOCKS.
- `"http"`: Принимает только HTTP/HTTPS прокси-запросы.

## Схема конфигурации

| Поле | Тип | Обязательно | Описание |
|---|---|---|---|
| `type` | string | Да | `"mixed"`, `"socks"` или `"http"`. |
| `tag` | string | Нет | Уникальный идентификатор инбаунда. |
| `listen` | string | Нет | Адрес прослушивания (по умолчанию: `"127.0.0.1"`). |
| `listen_port` | uint16 | Да | Порт прослушивания. |
| `users` | array | Нет | Опциональная авторизация (`{"username": "...", "password": "..."}`). |
| `network` | string | Нет | Поддержка `"udp"` для SOCKS5 UDP ASSOCIATE (включена по умолчанию). |

## Пример

```json
{
  "type": "mixed",
  "tag": "mixed-in",
  "listen": "127.0.0.1",
  "listen_port": 7890,
  "users": [
    {
      "username": "localuser",
      "password": "localpassword"
    }
  ]
}
```
