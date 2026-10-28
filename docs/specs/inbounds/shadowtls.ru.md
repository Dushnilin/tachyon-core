# Инбаунд: ShadowTLS

Серверная точка входа ShadowTLS v2/v3. Проверяет аутентификацию рукопожатия по HMAC-SHA1 и прозрачно перенаправляет неавторизованные соединения на настоящий TLS-сервер прикрытия (decoy).

## Схема конфигурации

| Поле | Тип | Обязательно | Описание |
|---|---|---|---|
| `type` | string | Да | Должно быть `"shadowtls"`. |
| `tag` | string | Нет | Уникальный идентификатор инбаунда. |
| `listen` | string | Да | Адрес прослушивания. |
| `listen_port` | uint16 | Да | Порт прослушивания. |
| `version` | uint8 | Нет | Версия протокола: `2` или `3` (по умолчанию: `3`). |
| `password` | string | Нет | Общий пароль. |
| `users` | array | Нет | Список пользователей (`{"name": "...", "password": "..."}`). |
| `handshake` | object | Да | Сервер прикрытия по умолчанию (`{"server": "...", "server_port": 443}`). |
| `handshake_for_server_name` | object | Нет | Карта серверов прикрытия по SNI. |
| `strict_mode` | boolean | Нет | Сбрасывать неавторизованные соединения вместо проксирования на decoy (по умолчанию: `false`). |
| `wildcard_sni` | boolean | Нет | Разрешать произвольный SNI через сервер `handshake` по умолчанию. |

## Пример

```json
{
  "type": "shadowtls",
  "tag": "stls-in",
  "listen": "::",
  "listen_port": 443,
  "version": 3,
  "users": [
    {
      "name": "user1",
      "password": "shadowtls-password"
    }
  ],
  "handshake": {
    "server": "www.microsoft.com",
    "server_port": 443
  },
  "strict_mode": true
}
```
