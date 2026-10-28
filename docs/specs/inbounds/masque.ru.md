# Инбаунд: MASQUE

Серверная точка входа MASQUE (RFC 9484 CONNECT-IP поверх HTTP/3 QUIC). Принимает IP-дейтаграммы от клиента и направляет их в маршрутизатор через встроенный пользовательский стек TCP/UDP.

## Схема конфигурации

| Поле | Тип | Обязательно | Описание |
|---|---|---|---|
| `type` | string | Да | Должно быть `"masque"`. |
| `tag` | string | Нет | Уникальный идентификатор инбаунда. |
| `listen` | string | Да | Адрес прослушивания. |
| `listen_port` | uint16 | Да | UDP-порт прослушивания. |
| `mtu` | uint16 | Нет | MTU туннеля (по умолчанию: `1280`, минимум: `1200`). |
| `tls` | object | Да | Конфигурация серверного TLS. |

## Пример

```json
{
  "type": "masque",
  "tag": "masque-in",
  "listen": "::",
  "listen_port": 443,
  "mtu": 1280,
  "tls": {
    "enabled": true,
    "certificate_path": "/etc/tachyon/cert.pem",
    "key_path": "/etc/tachyon/key.pem"
  }
}
```
