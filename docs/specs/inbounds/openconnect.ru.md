# Инбаунд: OpenConnect

Серверная точка входа корпоративных SSL-VPN с поддержкой профилей Cisco AnyConnect, Palo Alto GlobalProtect, Juniper Network Connect, Pulse Secure, F5 и Fortinet.

## Схема конфигурации

| Поле | Тип | Обязательно | Описание |
|---|---|---|---|
| `type` | string | Да | Должно быть `"openconnect"`. |
| `tag` | string | Нет | Уникальный идентификатор инбаунда. |
| `listen` | string | Да | Адрес прослушивания. |
| `listen_port` | uint16 | Да | Порт прослушивания. |
| `flavor` | string | Да | Профиль протокола: `"anyconnect"`, `"gp"`, `"nc"`, `"pulse"`, `"f5"` или `"fortinet"`. |
| `cookie` | string | Нет | Токен/cookie авторизации сессии. |
| `ip` | boolean | Нет | Передача сырых IP-пакетов внутри туннеля (по умолчанию: `false`). |
| `esp` | boolean | Нет | Включить UDP-транспорт ESP (требует `ip: true`). |
| `dtls` | boolean | Нет | Включить UDP-транспорт DTLS (только для профиля `"anyconnect"`). |
| `dtls_port` | uint16 | Нет | UDP-порт для DTLS (`0` — динамический выбор). |
| `mtu` | uint16 | Нет | MTU туннеля (по умолчанию: `1400`). |
| `tls` | object | Нет | Конфигурация серверного TLS. |

## Пример

```json
{
  "type": "openconnect",
  "tag": "oc-in",
  "listen": "::",
  "listen_port": 443,
  "flavor": "anyconnect",
  "cookie": "secret-session-cookie",
  "ip": true,
  "dtls": true,
  "mtu": 1400,
  "tls": {
    "enabled": true,
    "certificate_path": "/etc/tachyon/cert.pem",
    "key_path": "/etc/tachyon/key.pem"
  }
}
```
