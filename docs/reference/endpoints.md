# Эндпоинты (туннели)

Секция `endpoints` верхнего уровня. В отличие от аутбаундов это не соединение
с чужим сервером, а собственный туннель, который ядро поднимает и в который
заворачивает трафик правилами.

## Типы

| Тип | Статус |
|---|---|
| `wireguard` | Работает: WireGuard и AmneziaWG 2.0/3.x. |
| `openvpn-client` | Работает: режим `static_key` поверх UDP и TCP. |
| `openconnect` | Принимается конфигом, в рантайме ошибка `not implemented yet (config check parity only)`. |
| `tailscale` | То же. |

## Поля WireGuard и AmneziaWG

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | string | — | `wireguard`. |
| `tag` | string | — | Имя, по нему ссылаются `route.rules`. |
| `system` | boolean | `false` | Использовать существующий системный интерфейс. |
| `name` | string | — | Имя системного интерфейса. |
| `mtu` | uint32 | — | MTU туннеля. |
| `address` | string / array | — | Адреса туннеля в CIDR. |
| `private_key` | string | — | Закрытый ключ в base64. |
| `listen_port` | uint16 | — | Порт, на котором ждать входящие. |
| `peers` | array | — | Список пиров, см. ниже. |
| `udp_timeout` | string | — | Таймаут UDP-сессии. |
| `udp_mapping` | string | — | Режим маппинга UDP. |
| `udp_filtering` | string | — | Фильтрация UDP. |
| `udp_nat_max` | uint16 | — | Размер таблицы NAT. |
| `workers` | uint32 | — | Число рабочих потоков. |

Плюс общие поля диалера — [dialer](common/dialer.md).

### Поля AmneziaWG

Обфускация мусорными пакетами и рандомизация заголовков, чтобы трафик не
опознавался DPI:

| Поле | Тип | Описание |
|---|---|---|
| `jc` | uint32 | Число мусорных пакетов в начале сессии. |
| `jmin`, `jmax` | uint32 | Диапазон размера мусорного пакета. |
| `s1`, `s2`, `s3`, `s4` | uint32 | Рандомизация первого заголовка пакета. |
| `h1`, `h2`, `h3`, `h4` | uint32 | Рандомизация остальных заголовков. |
| `i1`..`i5` | uint32 | Дополнительные интервалы паддинга. |
| `id` | string | Идентификатор профиля. |
| `ip` | string | Значение заголовка IP. |
| `ib` | string | Значение границы. |
| `header_protection_key` | string | Ключ защиты заголовков. |
| `content_padding_addition` | boolean | Добавлять паддинг к содержимому. |
| `rekey_after_time` | string | Время до смены ключа. |
| `rekey_timeout` | string | Таймаут смены ключа. |
| `reject_after_time` | string | Время до отклонения пакета. |
| `keepalive_timeout` | string | Таймаут keep-alive. |
| `max_handshake_attempts` | uint32 | Попыток рукопожатия. |
| `random_trailers` | boolean | Случайные трейлеры. |
| `disable_cookies` | boolean | Отключить cookies. |

Инициализация маскируется под DNS, STUN, SIP и QUIC Initial.

### Поля пира

| Поле | Тип | Описание |
|---|---|---|
| `address` | string / array | Адрес пира. |
| `port` | uint16 | Порт пира. |
| `public_key` | string | Открытый ключ в base64. |
| `pre_shared_key` | string | Дополнительный общий ключ. |
| `allowed_ips` | string / array | Разрешённые подсети. |
| `persistent_keepalive_interval` | string | Интервал keep-alive, вида `25s`. |
| `reserved` | uint32 / array | Зарезервированные байты. |

## Пример

```json
{
  "endpoints": [
    {
      "type": "wireguard",
      "tag": "wg-out",
      "address": ["172.20.0.2/32"],
      "private_key": "...",
      "peers": [
        {
          "address": "example.com",
          "port": 51820,
          "public_key": "...",
          "allowed_ips": ["0.0.0.0/0"],
          "persistent_keepalive_interval": "25s"
        }
      ]
    }
  ],
  "route": {
    "rules": [{ "outbound": "wg-out" }],
    "final": "wg-out"
  }
}
```
