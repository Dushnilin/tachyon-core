# Инбаунд: Trojan

Серверная точка входа Trojan. Аутентифицирует клиентов по хешу пароля SHA-224 поверх TLS/REALITY и поддерживает сменные транспорты (`ws`, `grpc`, `http`, `httpupgrade`, `xhttp`) и мультиплексирование.

## Схема конфигурации

| Поле | Тип | Обязательно | Описание |
|---|---|---|---|
| `type` | string | Да | Должно быть `"trojan"`. |
| `tag` | string | Нет | Уникальный идентификатор инбаунда. |
| `listen` | string | Да | Адрес прослушивания. |
| `listen_port` | uint16 | Да | Порт прослушивания. |
| `users` | array | Да | Список пользователей (`{"name": "...", "password": "..."}`). |
| `fallback` | object | Нет | Адрес перенаправления неавторизованных соединений (`{"server": "...", "server_port": 80}`). |
| `tls` | object | Нет | Конфигурация серверного TLS / REALITY. |
| `transport` | object | Нет | Транспортный уровень (`ws`, `grpc`, `http`, `httpupgrade`, `xhttp`). |
| `multiplex` | object | Нет | Настройки мультиплексирования (`h2mux`). |

## Пример

```json
{
  "type": "trojan",
  "tag": "trojan-in",
  "listen": "::",
  "listen_port": 443,
  "users": [
    {
      "name": "user1",
      "password": "trojan-secret-password"
    }
  ],
  "tls": {
    "enabled": true,
    "certificate_path": "/etc/tachyon/cert.pem",
    "key_path": "/etc/tachyon/key.pem"
  }
}
```
