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
| `tailscale` | Нативный userspace endpoint: control, DISCO, WireGuard/DERP, MagicDNS и TCP/UDP subnet routing. Ограничения ниже. |

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

## Tailscale

Реализация использует имеющиеся в workspace Rust-примитивы; отдельный
`tailscaled`, Go runtime, geiserx, дополнительные crate и системные пакеты
не нужны. Control соединяется по HTTPS с проверкой сертификата и Noise IK;
DERP переносит зашифрованные WireGuard-пакеты. DISCO Ping/Pong проверяет
прямой UDP-путь, а недоступные прямые адреса используют DERP.

| Поле | По умолчанию | Описание |
|---|---|---|
| `type` | — | `tailscale`. |
| `tag` | — | Имя endpoint для route и DNS. |
| `state_directory` | — | Обязателен для постоянного узла; содержит private identity. |
| `auth_key` | — | Ключ первоначальной регистрации; секрет, не помещать в журналы. |
| `hostname` | `tachyon-core` | Имя узла. |
| `control_url` | `https://controlplane.tailscale.com` | Только HTTPS origin без embedded credentials. |
| `ephemeral` | `false` | Временная identity без сохранения. |
| `listen_port` | `41641` | UDP-порт WireGuard/DISCO; `0` выбирает свободный порт. |
| `advertise_routes` | `[]` | Публикуемые CIDR subnet routes; одобрение маршрутов выполняется в control plane. |
| `accept_routes` | `false` | Разрешить исходящие соединения к subnet routes других узлов. |
| `advertise_tags` | `[]` | Запрашиваемые теги согласно политике tailnet. |
| `udp_timeout` | общий UDP timeout | Время простоя LAN UDP-сессии. |
| `system_interface_mtu` | `1280` | MTU userspace stack, не создание системного интерфейса. |

Для DNS сервер `type: "tailscale"` ссылается на `endpoint`, например:

```json
{
  "dns": {
    "servers": [{"type": "tailscale", "tag": "tailnet-dns", "endpoint": "tailnet"}]
  },
  "endpoints": [{
    "type": "tailscale",
    "tag": "tailnet",
    "state_directory": "/var/lib/tachyon/tailscale",
    "hostname": "router",
    "advertise_routes": ["192.0.2.0/24"]
  }]
}
```

MagicDNS сохраняет transaction ID клиента и отвечает A/AAAA; split DNS
использует IP resolvers из netmap. Оригинальный `tailscaled.state` читается
для импорта machine/node keys и не переписывается. Новая private identity
хранится в `tachyon-native-identity.json`; повреждённая identity вызывает
ошибку, а не создание другого узла. При неизменённых параметрах reload
сохраняет endpoint и соединения; при изменении старые задачи завершаются.

Входящие новые TCP/UDP соединения проходят проверку source AllowedIPs,
advertised destination и packet ACL. Просроченная или неавторизованная
identity не получает трафик. Tailnet lock, системный интерфейс, exit node,
Taildrop и размещение relay server пока не поддерживаются: конфигурация
завершается ошибкой. ICMP/TSMP, IP fragmentation, IPv6 extension headers,
STUN и peer relay discovery не реализованы; `tailscale ping --tsmp` не
служит проверкой TCP/UDP. Direct discovery пока использует IPv4; DERP
остаётся запасным транспортом. Общие dialer options для этого endpoint
пока не применяются.