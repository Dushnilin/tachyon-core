# Outbound: direct

Пересылает трафик напрямую к месту назначения без какого-либо прокси. Поддерживает привязку к интерфейсу, подмену адреса и инжекцию заголовка PROXY protocol.

## Схема

| Поле | Тип | По умолчанию | Описание |
|------|-----|--------------|----------|
| `type` | `"direct"` | — | Должно быть `"direct"`. |
| `tag` | string | — | Уникальная метка для этого outbound. |
| `override_address` | string | — | Заменяет адрес назначения для каждого соединения. |
| `override_port` | integer | — | Заменяет порт назначения для каждого соединения. |
| `proxy_protocol` | integer | — | Вставляет заголовок PROXY protocol перед данными; `1` = v1 (текст), `2` = v2 (бинарный). |
| `bind_address` | string | — | Локальный IP-адрес для привязки исходящего сокета. |
| `bind_interface` | string | — | Локальный сетевой интерфейс для привязки исходящего сокета. |
| `routing_mark` | integer | — | Значение `SO_MARK` на исходящих сокетах (только Linux). |
| `reuse_addr` | bool | `false` | Устанавливает `SO_REUSEADDR` на исходящем сокете. |
| `connect_timeout` | duration | `"300s"` | Таймаут установки TCP-соединения. |
| `tcp_fast_open` | bool | `false` | Включить TCP Fast Open. |
| `domain_strategy` | string | `"prefer_ipv4"` | Стратегия разрешения DNS: `"prefer_ipv4"`, `"prefer_ipv6"`, `"ipv4_only"`, `"ipv6_only"`. |
| `fallback_delay` | duration | `"300ms"` | Задержка happy-eyeballs перед попыткой резервного семейства адресов. |

## Пример

```json
{
  "type": "direct",
  "tag": "direct",
  "bind_interface": "eth0",
  "domain_strategy": "prefer_ipv4"
}
```

## Примечания

- `override_address` и `override_port` применяются к **каждому** соединению через данный outbound; использовать осторожно в правилах маршрутизации.
- `proxy_protocol` требует, чтобы сервер на другом конце принимал заголовки PROXY protocol; несовпадение приведёт к ошибке соединения.
- `bind_interface` и `bind_address` взаимоисключающи на большинстве платформ.
- `routing_mark` работает только в Linux и игнорируется на других ОС.
