# TUN Входящий (Inbound)

Виртуальный сетевой интерфейс TUN, захватывающий системный трафик, поддерживающий TCP/UDP и FakeIP.

## Схема

| Поле | Тип | По умолчанию | Описание |
|------|------|--------------|----------|
| type | string | - | Должно быть "tun" |
| tag | string | - | Уникальный идентификатор |
| interface_name | string | - | Имя интерфейса (напр., "tun0") |
| inet4_address | string | - | IPv4 CIDR |
| inet6_address | string | - | IPv6 CIDR |
| mtu | integer | 9000 | MTU размер |
| gso | boolean | false | Generic Segmentation Offload (Linux) |
| auto_route | boolean | false | Автоматическая настройка маршрутов |
| stack | string | "mixed" | "system", "gvisor", "mixed" |

## Пример

```json
{
  "type": "tun",
  "tag": "tun-in",
  "interface_name": "tun0",
  "inet4_address": "172.19.0.1/30",
  "auto_route": true,
  "stack": "mixed",
  "sniff": true
}
```

## Примечания

- Требует прав суперпользователя для создания сетевых интерфейсов.
- `stack: "mixed"` обеспечивает наилучшую производительность на современных ядрах Linux.
