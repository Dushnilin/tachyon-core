# TPROXY Входящий (Inbound)

Прозрачный прокси-входящий (TPROXY), использующий механизм ядра Linux для перехвата трафика, перенаправленного через правила nftables/iptables.

## Схема

| Поле | Тип | По умолчанию | Описание |
|------|------|--------------|----------|
| type | string | - | Должно быть "tproxy" |
| tag | string | - | Уникальный идентификатор |
| listen | string | "0.0.0.0" | Адрес для бинда |
| listen_port | integer | - | Обязательно: порт для бинда |
| network | string | "tcp,udp" | "tcp", "udp", или "tcp,udp" |
| tcp_fast_open | boolean | false | Включить TFO |
| udp_timeout | duration | "5m" | Таймаут UDP сессии |
| sniff | boolean | false | Включить определение протокола |
| sniff_override_destination | boolean | false | Переопределять назначение при определении |
| mark | integer | - | SO_MARK для обхода маршрутизации |

## Пример

```json
{
  "type": "tproxy",
  "tag": "tproxy-in",
  "listen": "0.0.0.0",
  "listen_port": 1080,
  "network": "tcp,udp",
  "sniff": true,
  "mark": 255
}
```

## Примечания

- Требует `CAP_NET_ADMIN` для установки `SO_MARK` и бинда сокетов TPROXY.
- Предназначен для роутеров на Linux; на OpenWrt настройте соответствующие правила `nftables` для направления трафика на порт слушателя.
