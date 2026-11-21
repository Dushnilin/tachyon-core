# Секция `endpoints`

Секция `endpoints` описывает сетевые конечные точки L3-туннелей, которые могут одновременно принимать и/или отправлять IP-трафик и адресуются по тегу `tag` из правил маршрутизации (`route.rules[].outbound`) и полей `detour` точно так же, как исходящие подключения `outbounds`.

Теги `endpoints[].tag` и `outbounds[].tag` находятся в **едином пространстве имён**: дублирование тега между `endpoints` и `outbounds` запрещено.

## Поддерживаемые типы `endpoints[].type`

| `type` | Статус в `check` | Статус в `run` | Назначение |
|---|---|---|---|
| `wireguard` | Поддерживается | Полная поддержка | WireGuard + AmneziaWG 2.0 / 3.x + `wg-obfuscator` (Phobos) + ротация портов + ядерный (`system: true`) и userspace режимы. |
| `tailscale` | Поддерживается | Полная поддержка | Нативный pure-Rust узел Tailscale (DERP, DISCO, MagicDNS, маршрутизация подсетей, exit node, Taildrop). |
| `openvpn-client` | Поддерживается | Полная поддержка | Клиент OpenVPN (TLS и `static_key`, UDP/TCP). |
| `openvpn-server` | Поддерживается | Только `check` | Полная валидация схемы серверного OpenVPN-эндпоинта; в v0.6.2 при запуске отклоняется. |
| `openconnect` | Поддерживается | Только `check` в `endpoints` | Валидация схемы OpenConnect-эндпоинта. Для рабочего клиента используйте `outbounds[]` с `"type": "openconnect"`. |

Примечание о Cloudflare WARP: отдельного типа `"type": "warp"` в `endpoints[]` **нет** (валидатор вернёт `unknown endpoint type: warp`). Подключение к WARP настраивается либо через `endpoints[]` с `"type": "wireguard"` (с указанием 3-байтного `reserved` и ключей WARP), либо через `outbounds[]` с `"type": "masque"`.

---

## Endpoint `wireguard` (WireGuard / AmneziaWG / `wg-obfuscator`)

Поддерживает как современный многопировый формат с массивом `peers[]`, так и плоский формат одиночного пира (`server`, `server_port`, `peer_public_key`, `local_address`). Встраивает все поля [dialer](common-objects.md#объект-dialer-параметры-исходящего-подключения) (`detour`, `bind_interface`, `routing_mark`, `domain_resolver`, `connect_timeout` и т. д.).

### Основные поля `wireguard`

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | `"wireguard"` | Тип конечной точки. |
| `tag` | `string` | индекс элемента | Уникальный тег конечной точки. |
| `system` | `bool` | `false` | На Linux при `true` использует ядерный драйвер (`wireguard` или `amneziawg.ko` через Netlink). Несовместимо с `obfuscator` (`wg-obfuscator`). |
| `name` | `string` | — | Имя системного сетевого интерфейса при `system: true` (например, `"wg0"`). |
| `mtu` | `uint32` | `1408` (автоматически уменьшается на оверхед AWG/obfuscator, минимум `1280`) | MTU туннельного интерфейса (при наличии IPv6 всегда не ниже `1280`). |
| `address` | `Listable<CIDR>` | *(обязательно, если не задан `local_address`)* | Локальный IPv4 и/или IPv6 адрес интерфейса с маской (например, `["10.0.0.2/32", "fd00::2/128"]`). |
| `local_address` | `Listable<CIDR>` | — | Альтернативное имя поля `address` (применяется, если `address` отсутствует/пуст). |
| `private_key` | `string` | *(обязательно)* | 32-байтный приватный ключ X25519 в стандартном base64. |
| `listen_port` | `uint16` | `0` | Локальный UDP-порт (при `0` выделяется автоматически). |
| `peers` | `array<object>` | — | Список удалённых пиров (см. таблицу `peers[]` ниже). |
| `udp_timeout` | `Duration` | `"2m"` | Таймаут UDP-сессий внутри туннеля. |
| `udp_mapping`, `udp_filtering` | `string` | — | Поведение UDP NAT (`"endpoint_independent"`, `"address_dependent"`, `"address_and_port_dependent"`). Принимается `check`, при `run` игнорируется с предупреждением. |
| `udp_nat_max` | `uint32` | — | Лимит таблицы UDP NAT (принимается `check`, при `run` игнорируется с предупреждением). |
| `workers` | `int` | — | Число рабочих потоков (принимается `check`, при `run` игнорируется с предупреждением). |
| `server`, `server_port`, `peer_public_key`, `pre_shared_key`, `reserved`, `persistent_keepalive_interval` | — | — | Плоские поля одиночного пира (используются, когда `peers` не задан). `reserved` принимает массив до 3 байт `[b0, b1, b2]` или base64-строку; `persistent_keepalive_interval` — секунды `uint32` или диапазон `"min-max"`. |

### Поля элемента `peers[]`

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `address` | `string` | — | IP-адрес или доменное имя удалённого пира (допускается запись `host:port`). |
| `port` | `uint16` | `51820` | UDP-порт удалённого пира. |
| `public_key` | `string` | *(обязательно)* | 32-байтный публичный ключ пира в base64. |
| `pre_shared_key` | `string` | — | Опциональный 32-байтный PSK в base64. |
| `allowed_ips` | `Listable<CIDR>` | *(обязательно, непустой)* | Разрешённые подсети, маршрутизируемые через данного пира (например, `["0.0.0.0/0", "::/0"]`). |
| `persistent_keepalive_interval` | `uint32 \| string` | `0` | Интервал keepalive в секундах либо диапазон `"min-max"` (в AWG 3.x перевыбирается при каждом взведении таймера). |
| `reserved` | `[uint8; 3] \| string` | — | 3 зарезервированных байта заголовка WireGuard (массив 0..3 байт или base64, используется в т. ч. для Cloudflare WARP). |
| `server_ports` | `Listable<string>` | — | Диапазоны/порты для ротации UDP-портов пира (см. ниже). |
| `hop_interval` | `Duration \| int \| string` | — | Интервал ротации портов (перекрывает корневой `hop_interval`). |
| `hop_interval_max` | `Duration \| int` | — | Верхняя граница случайного интервала ротации портов. |

### Ротация портов (Port Hopping)

Поля могут задаваться на уровне эндпоинта (действуют по умолчанию) или индивидуально в `peers[]`:

| Поле | Тип | Описание |
|---|---|---|
| `server_ports` | `Listable<string>` | Один или несколько портов/диапазонов: `"20000:30000"`, `"20000-30000"`, `"51820"`. |
| `hop_interval` | `Duration \| int \| string` | Интервал смены целевого порта: длительность (`"30s"`), число секунд (`30`) либо диапазон `"20s-40s"` / `"20-40"`. |
| `hop_interval_max` | `Duration \| int` | Верхняя граница диапазона смены порта, если `hop_interval` задан одним значением. |

### Параметры AmneziaWG 2.0 и 3.x (встроены на верхнем уровне `wireguard`)

Включаются автоматически при задании любого из нижеперечисленных полей. **Несовместимы с `obfuscator` (`wg-obfuscator` / Phobos).** В режиме `system: true` в ядро Linux (`amneziawg.ko`) передаются `jc`, `jmin`, `jmax`, `s1`, `s2`, `h1`–`h4`.

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `jc` | `uint32` | `0` | Количество мусорных UDP-пакетов перед рукопожатием (`0..=65535`). |
| `jmin` | `uint32` | `0` | Минимальный размер мусорного пакета (должно выполняться `jmin <= jmax`). |
| `jmax` | `uint32` | `0` | Максимальный размер мусорного пакета. |
| `s1`, `s2`, `s3`, `s4` | `uint32` | `0` | Длина случайного префикса (в байтах) для пакетов Init (`s1`), Response (`s2`), Cookie (`s3`) и Transport (`s4`). При использовании `header_protection_key` все `s1`–`s4` обязаны быть `>= 12`. |
| `h1`, `h2`, `h3`, `h4` | `uint32 \| string` | `1`, `2`, `3`, `4` | Пользовательские типы заголовков (4 байта) для Init/Response/Cookie/Transport: одиночное `uint32` или диапазон `"min-max"` (AWG 2.0). |
| `i1`–`i5` (псевдонимы `j1`–`j3` для `i1`–`i3`) | `string` | `""` | Цепочки CPS-пакетов (Custom Protocol Signature) перед рукопожатием. Поддерживаемые теги: `<b 0x...>`, `<c>` (счётчик), `<t>` (время Unix), `<r N>` (случайные байты), `<rc N>` (случайные буквы), `<rd N>` (случайные цифры), `<d>`, `<ds>`, `<dz N>`. |
| `id`, `ip`, `ib` | `string` | `""` | Декларативная генерация маскировочного пакета `i1` (конфликтует с явным `i1`; для `ip="sip"` также конфликтует с `i2`): `ip` — протокол (`"quic"`, `"dns"`, `"stun"`, `"sip"`), `id` — маскировочный домен (обязателен для `ip="quic"`), `ib` — профиль браузера (`"chrome"`, `"firefox"`, `"curl"`, допустим только при `ip="quic"`). |
| `itime` | `uint32 \| string` | `0` | Временной параметр CPS (`uint32` или `"min-max"`). |
| `header_protection_key` | `string` | `""` | *(AWG 3.x)* 32-байтный ключ защиты заголовков в стандартном base64 (не может быть нулевым; требует `s1..s4 >= 12`). |
| `content_padding_addition` | `uint32 \| string` | `0` | *(AWG 3.x)* Дополнительное выравнивание полезной нагрузки (`uint32` или `"min-max"`). |
| `rekey_after_time` | `uint32 \| string` | стандарт WG | *(AWG 3.x)* Переопределение таймера пересогласования ключей (секунды или `"min-max"`). |
| `rekey_timeout` | `uint32 \| string` | стандарт WG | *(AWG 3.x)* Таймаут повтора рукопожатия (секунды или `"min-max"`). |
| `reject_after_time` | `uint32 \| string` | стандарт WG | *(AWG 3.x)* Максимальное время жизни сессии без реключевания (секунды или `"min-max"`). |
| `keepalive_timeout` | `uint32 \| string` | стандарт WG | *(AWG 3.x)* Таймаут пассивного keepalive (секунды или `"min-max"`). |
| `max_handshake_attempts` | `uint32 \| string` | стандарт WG | *(AWG 3.x)* Ограничение числа попыток рукопожатия (`uint32` или `"min-max"`). |
| `random_trailers` | `bool` | `false` | *(AWG 3.x)* Добавление случайных завершающих байт к пакетам. |
| `disable_cookies` | `bool` | `false` | *(AWG 3.x)* Отключение механизма WireGuard Cookie Reply. |

### Обфускатор `wg-obfuscator` (Phobos)

Задаётся либо вложенным объектом `obfuscator` (псевдоним `wg_obfuscator`), либо плоскими полями `obfuscator_*` на верхнем уровне эндпоинта. **Несовместим с AmneziaWG и с `system: true` (работает только в userspace).**

| Поле в `obfuscator` | Плоский псевдоним | Тип | По умолчанию | Описание |
|---|---|---|---|---|
| `key` | `obfuscator_key` | `string` | *(обязательно)* | Общий секретный ключ обфускатора (от 1 до 255 байт). |
| `masking` | `obfuscator_masking` | `string` | `"none"` | Режим обёртки UDP-пакетов: `"none"` (`"off"`), `"stun"` (STUN Binding / Data-Indication), `"media"` (`"rtp"` — заголовки H.264/RTP + STUN keepalive), `"auto"`. |
| `max_dummy` (`max-dummy`) | `obfuscator_max_dummy` | `uint16` | `4` | Максимальная длина случайного дополнения (`0..=1024`). |
| `obfuscate_bytes` (`obfuscate-bytes`) | `obfuscator_bytes` | `uint16` | `0` (`16` при `masking: "media"`) | Число начальных байт пакета, подвергаемых XOR-обфускации (`0` — весь пакет). |
| `media_pt` (`media-pt`) | `obfuscator_media_pt` | `uint8` | `0` (из пресета) | RTP Payload Type (`0..=127`) для режима `"media"`. |
| `media_ssrc` (`media-ssrc`) | `obfuscator_media_ssrc` | `uint32 \| string` | `0` (случайный) | RTP SSRC (целое или hex-строка `"0x1234abcd"`). |
| `media_clock` (`media-clock`) | `obfuscator_media_clock` | `uint32` | `0` (из пресета) | Шаг RTP-метки времени. |
| `version` | — | `uint8` | `1` | Версия протокола `wg-obfuscator`: `0` или `1`. |

### Пример `wireguard` (AmneziaWG + ротация портов)

```json
{
  "endpoints": [
    {
      "type": "wireguard",
      "tag": "awg-ep",
      "system": false,
      "mtu": 1380,
      "address": ["10.8.0.2/32", "fd00:8::2/128"],
      "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      "jc": 4,
      "jmin": 40,
      "jmax": 70,
      "s1": 32,
      "s2": 48,
      "s3": 16,
      "s4": 24,
      "h1": "100000-200000",
      "h2": "200001-300000",
      "h3": "300001-400000",
      "h4": "400001-500000",
      "peers": [
        {
          "address": "198.51.100.10",
          "port": 51820,
          "server_ports": ["20000-30000"],
          "hop_interval": "30s-60s",
          "public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
          "allowed_ips": ["0.0.0.0/0", "::/0"],
          "persistent_keepalive_interval": "20-30"
        }
      ]
    }
  ]
}
```

---

## Endpoint `tailscale`

Нативный pure-Rust клиент и маршрутизатор подсетей Tailscale. Встраивает все поля [dialer](common-objects.md#объект-dialer-параметры-исходящего-подключения).

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | `"tailscale"` | Тип конечной точки. |
| `tag` | `string` | индекс элемента | Уникальный тег (используется также в `dns.servers[]` типа `tailscale` в поле `endpoint`). |
| `state_directory` | `string` | `"tailscale"` (если `ephemeral: false`) | Каталог для хранения ключей узла и состояния tailnet. |
| `auth_key` | `string` | — | Предварительно сгенерированный ключ авторизации Tailscale (`tskey-auth-...`). |
| `control_url` | `string` | `"https://controlplane.tailscale.com"` | URL координационного сервера (Tailscale или Headscale). |
| `ephemeral` | `bool` | `false` | Регистрирует узел как эфемерный (без каталога состояния по умолчанию). |
| `hostname` | `string` | имя хоста ОС | Отображаемое имя узла в tailnet. |
| `accept_routes` | `bool` | `false` | Принимать анонсированные подсети от других узлов tailnet. |
| `exit_node` | `string` | — | Имя или IP выходного узла (exit node). Взаимоисключающе с `advertise_exit_node: true`. |
| `exit_node_allow_lan_access` | `bool` | `false` | Разрешает прямой доступ к локальной сети при активном `exit_node`. |
| `advertise_routes` | `array<CIDR>` | `[]` | Список локальных подсетей, анонсируемых в tailnet. Маршруты по умолчанию `0.0.0.0/0` и `::/0` здесь запрещены — используйте `advertise_exit_node`. |
| `advertise_exit_node` | `bool` | `false` | Анонсировать текущий узел как exit node (конфликтует с непустым `exit_node`). |
| `advertise_tags` | `Listable<string>` | `[]` | ACL-теги Tailscale (например, `["tag:router"]`). |
| `listen_port` | `uint16` | `41641` | Локальный UDP-порт WireGuard/DISCO. |
| `relay_server_port` | `uint16` | — | UDP-порт встроенного relay-сервера. |
| `relay_server_static_endpoints` | `array<IP:port>` | `[]` | Статические внешние адреса `IP:port` для relay-сервера. |
| `system_interface` | `bool` | `false` | Поднимать системный сетевой интерфейс ОС вместо чисто userspace-стека. |
| `system_interface_name` | `string` | — | Имя системного интерфейса при `system_interface: true`. |
| `system_interface_mtu` | `uint32` | — | MTU системного интерфейса. |
| `udp_timeout` | `Duration \| number` | `"2m"` (`120s`) | Таймаут UDP-сессий через Tailscale. |
| `ssh_server` | `object` | — | Параметры Tailscale SSH: `{"enabled": bool, "disable_pty": bool, "disable_sftp": bool, "disable_forwarding": bool}`. |
| `taildrop_directory` | `string` | — | Локальный каталог для приёма файлов через Taildrop. |

### Пример `tailscale`

```json
{
  "endpoints": [
    {
      "type": "tailscale",
      "tag": "ts-ep",
      "state_directory": "/var/lib/tachyon-core/tailscale",
      "auth_key": "tskey-auth-example-key",
      "hostname": "openwrt-router",
      "accept_routes": true,
      "advertise_routes": ["192.168.1.0/24"],
      "advertise_tags": ["tag:router"],
      "listen_port": 41641
    }
  ]
}
```

---

## Прочие типы `endpoints`

### `openvpn-client` (работает в `check` и `run`)

Встраивает поля [dialer](common-objects.md#объект-dialer-параметры-исходящего-подключения) и поддерживает режимы `"tls"` и `"static_key"`, протоколы `udp`/`udp4`/`udp6`/`tcp`/`tcp4`/`tcp6`, топологии `net30`/`p2p`/`subnet`, множественные удалённые серверы `servers[]` (`server`, `server_port`, `network`) и ротацию `remote_random`.

Ключевые поля схемы:
- Интерфейс и NAT: `system`, `name`, `mtu`, `udp_timeout`, `udp_mapping`, `udp_filtering`, `udp_nat_max`.
- Подключение и адресация: `server`, `server_port`, `servers`, `remote_random`, `mode` (`"tls"` | `"static_key"`), `network`, `address`, `peer_address`, `peer_address_ipv6`, `topology`.
- Аутентификация и ключи: `username`, `password`, `auth_retry` (`"none"` | `"nointeract"` | `"interact"`), `static_challenge`, `static_challenge_echo`, `static_key`, `static_key_path`, `key_direction` (`"server"` | `"client"`).
- TLS (`tls`): `server_name`, `server_name_type`, `certificate`, `certificate_path`, `client_certificate`, `client_certificate_path`, `client_key`, `client_key_path`, `peer_fingerprint`, `crl_path`, `remote_certificate_ku`, `remote_certificate_eku`, `remote_certificate_tls`, `certificate_profile`, `ns_certificate_type`, `version_min`, `version_max`, `cipher`, `groups`, `control_wrap` (`type`, `key`, `key_path`, `direction`).
- Шифрование и транспорт: `cipher`, `data_ciphers`, `data_ciphers_fallback`, `auth`, `mss_fix`, `mss_fix_disabled`, `mss_fix_mode` (`"mtu"` | `"fixed"`), `fragment`, `replay_window` (`<= 65536`), `replay_window_time` (`0s..=600s`, кратно секундам), `compression`, `compression_lzo`, `allow_compression`.
- Маршрутизация и таймеры: `route_no_pull`, `pull_filters` (`action`: `"accept"` | `"ignore"` | `"reject"`, `text`), `routes`, `route_gateway`, `route_metric`, `redirect_gateway`, `redirect_gateway_flags`, `redirect_private`, `block_ipv6`, `ping_interval`, `ping_restart`, `ping_restart_disabled`, `renegotiate_interval`, `renegotiate_disabled`, `renegotiate_bytes`, `renegotiate_packets`, `tls_timeout`, `handshake_window`, `explicit_exit_notify`.

### `openvpn-server` (валидация `check`)

Встраивает поля [listen](common-objects.md#объект-listen-параметры-прослушивания) и серверные параметры OpenVPN: `system`, `name`, `mtu`, `udp_mapping`, `udp_filtering`, `udp_nat_max`, `mode`, `network` (`"udp"` | `"tcp"`), `remote`, `remote_port`, `max_clients`, `address`, `peer_address`, `peer_address_ipv6`, `topology`, `duplicate_cn`, `users` (`username`, `password`), `static_key`, `static_key_path`, `key_direction`, `tls` (включая `key`/`key_path`, `verify_client_certificate`, `client_name`, `client_name_type`, `control_wrap` с `force_cookie`), `cipher`, `data_ciphers`, `data_ciphers_fallback`, `auth`, `mss_fix*`, `replay_window*`, `push` (`routes`, `dns`, `dns_servers`, `search_domains`, `dhcp_options`, `redirect_gateway*`, `block_outside_dns`, `ping_interval`, `ping_restart`), таймеры `ping_*`, `renegotiate_*`, `handshake_window`. В v0.6.2 проходит `tachyon-core check`, но не запускается в `run`.

### `openconnect` (валидация `check` в `endpoints`)

Встраивает поля [dialer](common-objects.md#объект-dialer-параметры-исходящего-подключения) и клиентские параметры OpenConnect (`server`, `flavor`: `"anyconnect"` | `"gp"` | `"fortinet"` | `"f5"` | `"pulse"` | `"nc"`, `username`, `password`, `auth_group`, `cookie`, `token`, `reported_os`, `user_agent`, `version`, `local_hostname`, `mobile`, `csd`, `hip`, `tncc`, `fortinet_host_check`, `no_udp`, `dtls_local_port`, `compression_disabled`, `compression_mode`, `ipv6_disabled`, `http_keepalive_disabled`, `xml_post_disabled`, `external_auth_disabled`, `password_authentication_disabled`, `tcp_keep_alive_enabled`, `pfs`, `mtu`, `base_mtu`, `dpd_interval`, `reconnect_timeout`, `trojan_interval`, `queue_length`, `allow_insecure_crypto`, `tls`, `form_entries`, `system`, `name`, `udp_timeout`, `udp_mapping`, `udp_filtering`, `udp_nat_max`).

Для рабочего подключения к серверам OpenConnect / AnyConnect / GlobalProtect / FortiGate используйте секцию `outbounds[]` с `"type": "openconnect"` (см. [outbounds/quic-and-tunnels.md](outbounds/quic-and-tunnels.md)).
