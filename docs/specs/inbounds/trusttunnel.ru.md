# Инбаунд: TrustTunnel

Серверная точка входа TrustTunnel поверх HTTP/2 (TCP TLS) или HTTP/3 (QUIC). Поддерживает потоки TCP CONNECT, мультиплексирование дейтаграмм `_udp2` и туннелирование эхо-запросов `_icmp`.

## Схема конфигурации

| Поле | Тип | Обязательно | Описание |
|---|---|---|---|
| `type` | string | Да | Должно быть `"trusttunnel"`. |
| `tag` | string | Нет | Уникальный идентификатор инбаунда. |
| `listen` | string | Да | Адрес прослушивания. |
| `listen_port` | uint16 | Да | Порт прослушивания. |
| `users` | array | Да | Список пользователей (`{"username": "...", "password": "..."}`). |
| `quic` | boolean | Нет | Использовать HTTP/3 QUIC (UDP) вместо HTTP/2 TCP (по умолчанию: `false`). |
| `tls` | object | Да | Конфигурация серверного TLS. |

## Пример

```json
{
  "type": "trusttunnel",
  "tag": "tt-in",
  "listen": "::",
  "listen_port": 443,
  "users": [
    {
      "username": "ttuser",
      "password": "ttpassword"
    }
  ],
  "tls": {
    "enabled": true,
    "certificate_path": "/etc/tachyon/cert.pem",
    "key_path": "/etc/tachyon/key.pem"
  }
}
```
