# Инбаунд: FPTN

Серверная точка входа FPTN. Туннелирует IP-пакеты поверх WebSocket/HTTPS и выдаёт виртуальные IP-адреса авторизованным клиентам.

## Схема конфигурации

| Поле | Тип | Обязательно | Описание |
|---|---|---|---|
| `type` | string | Да | Должно быть `"fptn"`. |
| `tag` | string | Нет | Уникальный идентификатор инбаунда. |
| `listen` | string | Да | Адрес прослушивания. |
| `listen_port` | uint16 | Да | Порт прослушивания. |
| `users` | array | Да | Список пользователей (`{"username": "...", "password": "..."}`). |
| `dns` | string | Нет | Адрес IPv4 DNS-сервера, выдаваемый клиентам. |
| `ipv4_pool` | string | Нет | Пул CIDR для выдачи IPv4-адресов клиентам (например, `"10.10.0.0/24"`). |
| `ipv6_pool` | string | Нет | Пул CIDR для выдачи IPv6-адресов клиентам. |
| `obfuscation` | string | Нет | Режим обфускации рукопожатия (`"tls"` или `"none"`). |
| `tls` | object | Да | Конфигурация серверного TLS. |

## Пример

```json
{
  "type": "fptn",
  "tag": "fptn-in",
  "listen": "::",
  "listen_port": 8443,
  "users": [
    {
      "username": "user1",
      "password": "password123"
    }
  ],
  "ipv4_pool": "10.10.0.0/24",
  "dns": "1.1.1.1",
  "tls": {
    "enabled": true,
    "certificate_path": "/etc/tachyon/cert.pem",
    "key_path": "/etc/tachyon/key.pem"
  }
}
```
