# Системные и клиентские инбаунды

В этом разделе описаны локальные и прозрачные входящие обработчики `tachyon-core`:

- [`tun`](#tun) — виртуальный сетевой интерфейс L3
- [`tproxy`](#tproxy) — прозрачный прокси Linux (`TPROXY`)
- [`redirect`](#redirect) — прозрачное перенаправление TCP Linux (`REDIRECT`)
- [`direct`](#direct) — прямой перехватчик TCP/UDP с подменой назначения
- [`mixed`](#mixed) — комбинированный SOCKS4/4a/5 и HTTP/HTTPS прокси
- [`socks`](#socks) — прокси SOCKS4/4a/5
- [`http`](#http) — HTTP/HTTPS прокси

Все типы, кроме `tun`, наследуют общие поля прослушивания (`listen`, `listen_port`, `ipv6_only`, `udp_timeout`, `filter`, `ips_excluded`, `domains_excluded`, `fullcone`, `udp_nat_mode`, `udp_fullcone_max_bindings` и др.), описанные в [common-objects.md](../common-objects.md).

---

## `tun`

Инбаунд `tun` создаёт или подключается к виртуальному сетевому интерфейсу уровня L3 и прозрачно маршрутизирует проходящий через него трафик TCP, UDP и ICMP (v4/v6) через маршрутизатор `tachyon-core`.

В отличие от сетевых инбаундов, `tun` не принимает общие поля `listen` / `listen_port`.

### Архитектура и особенности реализации

- **Стек TCP/IP**: независимо от выбранного значения `stack` (`system`, `gvisor`, `mixed`), TCP-потоки терминации обрабатываются встроенным pure-Rust userspace-стеком `smoltcp` (с отключённым алгоритмом Нагла и задержкой ACK), UDP-потоки — через внутренний UDP-хаб с сохранением исходных адресов, а ICMP/ICMPv6 Echo-запросы отвечаются напрямую.
- **Тюнинг TCP-окна (`TACHYON_SMOL_TCP_BUF`)**: начальный и максимальный размер буферов TCP-сокета `smoltcp` адаптируются автоматически под объём ОЗУ устройства (базовое окно 64–256 КиБ, динамический рост при нагрузке и сжатие неактивных буферов через 15 с простоя или 3 с под давлением памяти). Переменная окружения `TACHYON_SMOL_TCP_BUF` задаёт базовый размер буфера в КиБ (целое число от `64` до `4096`, округляется вверх до степени двойки).
- **GSO / GRO offload (Linux)**: при `"gso": true` устройство `/dev/net/tun` открывается с флагами `IFF_TUN | IFF_NO_PI | IFF_VNET_HDR` и вызовом `TUNSETOFFLOAD` (10-байтный заголовок `virtio_net_hdr`, сегментация суперпакетов TSO). При использовании внешнего файлового дескриптора GSO не включается.
- **Неразрушающая маршрутизация (`auto_route`)**:
  - **Linux**: создаёт изолированную таблицу маршрутизации (`iproute2_table_index`, по умолчанию `2022`) и ip-правила с приоритетом `iproute2_rule_index` (по умолчанию `9000`). Все исходящие сокеты самого `tachyon-core` автоматически получают `fwmark` `0x2022`, обходя таблицу TUN и предотвращая петли маршрутизации. При завершении работы правила и маршруты удаляются автоматически.
  - **Windows**: использует встроенный подписанный драйвер Wintun (`wintun.sys`, без внешней библиотеки `wintun.dll`), назначает адреса и маршруты на адаптер, а исходящие сокеты ядра привязываются к исходному физическому интерфейсу через `IP_UNICAST_IF`. При ошибке открытия адаптера (например, без прав администратора) инбаунд переходит в пассивный режим с предупреждением в логе.
  - **macOS**: открывает системный интерфейс `utun` (имя выделяется ядром), настраивает адреса/маршруты и привязывает исходящие сокеты ядра к физическому интерфейсу через `IP_BOUND_IF` / `IPV6_BOUND_IF`.
- **Внешний файловый дескриптор (`TACHYON_TUN_FD` / `tun_fd`)**: на Linux, Android, macOS и iOS можно передать готовый дескриптор TUN-интерфейса (переменная окружения `TACHYON_TUN_FD` либо параметр `tun_fd` при запуске через встроенный C/JNI FFI, который инжектируется во внутреннее поле `fd` уже после валидации JSON; указывать `"fd"` напрямую в пользовательском JSON нельзя — валидатор отклонит неизвестное поле). На Android (`VpnService`) и iOS (`NEPacketTunnelProvider`) внешний дескриптор обязателен; при его использовании `auto_route` и GSO не применяются, а `mtu` (если не задан явно) считывается из параметров дескриптора ядра.
- **Автокоррекция MTU для IPv6**: если настроены IPv6-адреса (`address`), IPv6-маршруты (`route_address`) или IPv6-диапазон FakeIP, и итоговый `mtu < 1280`, рантайм автоматически повышает `mtu` до `1280` (требование RFC 8200).

### Активные поля конфигурации `tun`

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | обязательное | `"tun"`. |
| `tag` | `string` | `"tun"` | Идентификатор инбаунда. |
| `interface_name` | `string` | `"tun0"` | Имя виртуального интерфейса (на Linux и Windows; на macOS ядро назначает имя `utunN`). |
| `address` | `string \| string[]` | `[]` | Один или несколько IPv4/IPv6 CIDR-префиксов интерфейса, например `["172.19.0.1/30", "fdfe:dcba:9876::1/126"]`. |
| `mtu` | `uint32` | `9000` | MTU интерфейса в байтах. При активном IPv6 минимальное значение принудительно ограничивается `1280`. |
| `stack` | `string` | `"system"` | Режим стека: `"system"`, `"gvisor"` или `"mixed"`. Все три значения принимаются и обслуживаются встроенным userspace-стеком `smoltcp`. |
| `gso` | `bool` | `false` | Включить GRO/GSO offload на Linux (`IFF_VNET_HDR` / `TUNSETOFFLOAD`). Игнорируется при внешнем `tun_fd`. |
| `auto_route` | `bool` | `false` | Автоматически настраивать системную маршрутизацию трафика через TUN (таблица `2022` на Linux, маршруты Wintun на Windows, `utun` на macOS). |
| `strict_route` | `bool` | `false` | Строгий режим политической маршрутизации на Linux при `auto_route: true`. |
| `iproute2_table_index` | `uint32` | `2022` | Номер таблицы маршрутизации `iproute2` на Linux для `auto_route`. |
| `iproute2_rule_index` | `uint32` | `9000` | Базовый приоритет (`pref`) правил `ip rule` на Linux для `auto_route`. |
| `route_address` | `string \| string[]` | `[]` | Явный список IPv4/IPv6 CIDR-префиксов, направляемых в TUN при `auto_route: true` (вместо маршрута по умолчанию). |
| `route_exclude_address` | `string \| string[]` | `[]` | Список IPv4/IPv6 CIDR-префиксов, исключаемых из маршрутизации в TUN при `auto_route: true`. |
| `udp_timeout` | `duration` | `"2m"` (`120s`) | Таймаут неактивности UDP-сессии (строка вроде `"5m"` или число секунд). Значение `0` включает адаптивный таймаут по объёму ОЗУ (30–180 с, сокращается вдвое при давлении памяти). |
| `fullcone` | `bool` | `false` | Включить Full-Cone UDP NAT (Endpoint-Independent Mapping & Filtering, RFC 3489). |
| `udp_nat_mode` | `string` | `""` | Режим UDP NAT: `"fullcone"`, `"full_cone"`, `"full-cone"`, `"eim_eif"`, `"endpoint_independent"` (включают Full-Cone) или `"symmetric"`, `"default"`. |
| `udp_fullcone_max_bindings` | `uint32` | адаптивно | Максимум одновременных Full-Cone UDP-привязок (`64..=65536`). |
| `filter` | `string \| string[] \| object` | — | Фильтр исходных IP/CIDR-адресов (`"10.0.0.0/8"`, `"!10.0.0.2"` или `{"allow"/"include": ..., "deny"/"exclude": ...}`). |
| `ips_excluded` / `ipsExcluded` | `string \| string[]` | `[]` | Список IP, CIDR, `"private"` или `geoip:<код>` / `ext:<файл>:<код>`, исключаемых из sniffing на данном инбаунде. |
| `domains_excluded` / `domainsExcluded` | `string \| string[]` | `[]` | Список доменов, исключаемых из sniffing на данном инбаунде. |

### Поля схемы совместимости (не применяются рантаймом v0.6.2)

Следующие поля принимаются строгим валидатором для совместимости с конфигурациями `sing-box`, но в рантайме `tachyon-core` v0.6.2 не выполняют действий и при старте выводят предупреждение `option ... is not honored by runtime`:

| Группа | Поля | Тип в схеме | Примечание |
|---|---|---|---|
| Сетевое пространство и DNS | `netns`, `dns_mode`, `dns_address`, `exclude_mptcp`, `loopback_address` | `string` / `listable<IP>` / `bool` | Для маршрутизации DNS используйте правило с `action: "hijack-dns"`. |
| Авто-редирект (nftables/netfilter) | `auto_redirect`, `auto_redirect_input_mark`, `auto_redirect_output_mark`, `auto_redirect_reset_mark`, `auto_redirect_nfqueue`, `auto_redirect_iproute2_fallback_rule_index` | `bool` / `uint32` / `string` | Для перехвата через netfilter на роутерах используйте инбаунды `tproxy` или `redirect`. |
| Наборы маршрутов | `route_address_set`, `route_exclude_address_set` | `string \| string[]` | Используйте явные CIDR в `route_address` / `route_exclude_address` или правила `route.rules`. |
| Фильтры интерфейсов, UID, пакетов и MAC | `include_interface`, `exclude_interface`, `include_uid`, `include_uid_range`, `exclude_uid`, `exclude_uid_range`, `include_android_user`, `include_package`, `exclude_package`, `include_mac_address`, `exclude_mac_address` | `listable<string>` / `uint32[]` | На Android/iOS фильтрация приложений задаётся со стороны `VpnService` / `NEPacketTunnelProvider`. |
| Устаревшие/альтернативные NAT-поля | `endpoint_independent_nat`, `udp_mapping`, `udp_filtering`, `udp_nat_max` | `bool` / `string` / `uint32` | Для включения Full-Cone NAT используйте `fullcone: true` или `udp_nat_mode: "fullcone"`. |
| Платформенный HTTP-прокси | `platform` (включая `platform.http_proxy`) | `object` | Принимается как JSON-объект; системный прокси при необходимости поднимается отдельным инбаундом `mixed` / `http`. |

### Удалённые устаревшие поля адресов `tun`

Поля `inet4_address`, `inet6_address`, `inet4_route_address`, `inet6_route_address`, `inet4_route_exclude_address`, `inet6_route_exclude_address` удалены и отклоняются валидатором при проверке конфигурации. Вместо них используйте объединённые массивы `address`, `route_address` и `route_exclude_address`.

### Пример конфигурации `tun` (Linux / роутер)

```json
{
  "type": "tun",
  "tag": "tun-in",
  "interface_name": "tun0",
  "address": [
    "172.19.0.1/30",
    "fdfe:dcba:9876::1/126"
  ],
  "mtu": 9000,
  "auto_route": true,
  "strict_route": true,
  "iproute2_table_index": 2022,
  "iproute2_rule_index": 9000,
  "route_exclude_address": [
    "192.168.0.0/16",
    "10.0.0.0/8"
  ],
  "stack": "system",
  "gso": true,
  "udp_timeout": "2m",
  "udp_nat_mode": "fullcone",
  "udp_fullcone_max_bindings": 1024
}
```

### Пример конфигурации `tun` для мобильного клиента (внешний `tun_fd`)

```json
{
  "type": "tun",
  "tag": "tun-in",
  "address": [
    "172.19.0.1/30"
  ],
  "mtu": 1500,
  "stack": "gvisor",
  "udp_timeout": "2m"
}
```

---

## `tproxy`

Инбаунд `tproxy` реализует прозрачное проксирование TCP и UDP на Linux (IPv4 и IPv6) без преобразования адресов (NAT) с сохранением исходного адреса назначения и адреса источника клиента.

### Поведение рантайма

- **Платформа и права**: работает только на Linux и требует привилегию `CAP_NET_ADMIN` (на других ОС завершается ошибкой при `bind`).
- **TCP**: сокет прослушивания открывается с опцией ядра `IP_TRANSPARENT` (и `IPV6_TRANSPARENT` для IPv6 / dual-stack). Исходный адрес назначения извлекается из `local_addr()` принятого соединения. Для каждого TCP-соединения включаются `TCP_NODELAY` и TCP keepalive (`30s` / интервал `15s` / `3` пробы).
- **UDP**: сокет открывается с `IP_TRANSPARENT` (`IPV6_TRANSPARENT`) и `IP_RECVORIGDSTADDR` (`IPV6_RECVORIGDSTADDR`), исходный адрес назначения извлекается из вспомогательных сообщений `recvmsg` (`cmsg`). Для отправки ответных датаграмм клиенту ядро открывает прозрачный подключённый UDP-сокет, привязанный к исходному адресу назначения (`bind` на адрес сервера назначения с `IP_TRANSPARENT`), чтобы клиент получал ответы с ожидаемого адреса и порта. Одновременный запуск новых UDP-потоков ограничен порогом 512 задач.

### Поля конфигурации `tproxy`

Наследует все общие поля прослушивания из [common-objects.md](../common-objects.md) плюс собственные поля:

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | обязательное | `"tproxy"`. |
| `tag` | `string` | `"tproxy"` | Идентификатор инбаунда. |
| `listen` | `string` | `"127.0.0.1"` | IP-адрес прослушивания (для dual-stack IPv4+IPv6 используйте `"::"`). |
| `listen_port` | `uint16` | обязательное | Порт прослушивания TCP и/или UDP. |
| `ipv6_only` | `bool` | `false` для `::` | Отключить dual-stack при привязке к `::`. |
| `network` | `string \| string[]` | TCP и UDP | Протоколы прослушивания: `"tcp"`, `"udp"` или оба (по умолчанию). |
| `udp_timeout` | `duration` | `"2m"` (`120s`) | Таймаут неактивности UDP-потоков и прозрачных ответных сокетов. |
| `udp_mapping` | `string` | `""` | Поле схемы совместимости (валидируется как строка). Для Full-Cone NAT используйте `fullcone` / `udp_nat_mode`. |
| `udp_filtering` | `string` | `""` | Поле схемы совместимости (валидируется как строка). |
| `udp_nat_max` | `uint32` | `0` | Поле схемы совместимости (валидируется как `uint32`). |

### Пример конфигурации `tproxy`

```json
{
  "type": "tproxy",
  "tag": "tproxy-in",
  "listen": "::",
  "listen_port": 7893,
  "network": ["tcp", "udp"],
  "udp_timeout": "2m",
  "udp_nat_mode": "fullcone"
}
```

---

## `redirect`

Инбаунд `redirect` принимает TCP-соединения, перенаправленные средствами пакетного фильтра Linux (`iptables -j REDIRECT` или `nftables redirect to`), и восстанавливает исходный адрес назначения из таблицы отслеживания соединений (`conntrack`).

### Поведение рантайма

- **Только TCP**: UDP-перенаправление не поддерживается (если в поле `network` указан `udp`, выводится предупреждение и обслуживается только TCP).
- **Восстановление адреса (Linux)**: выполняется `getsockopt(..., SO_ORIGINAL_DST)` на уровне `IPPROTO_IP` для IPv4 и `IPPROTO_IPV6` для IPv6. На платформах, отличных от Linux, попытка восстановления исходного адреса завершается ошибкой неподдерживаемой платформы.
- **Защита от петли (self-redirect guard)**: соединения, чей восстановленный адрес назначения совпадает с адресом прослушивания самого инбаунда `redirect`, отклоняются с предупреждением в лог, предотвращая бесконечную рекурсию.
- **Опции сокета**: включаются `TCP_NODELAY`, TCP keepalive (`15s` / `15s`) и проверка `filter` (если задан).

### Поля конфигурации `redirect`

Инбаунд `redirect` не имеет уникальных протокольных полей помимо общих полей прослушивания из [common-objects.md](../common-objects.md):

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | обязательное | `"redirect"`. |
| `tag` | `string` | `"redirect"` | Идентификатор инбаунда. |
| `listen` | `string` | `"127.0.0.1"` | IP-адрес прослушивания (`"::"` для dual-stack). |
| `listen_port` | `uint16` | обязательное | TCP-порт приёма перенаправленных соединений. |
| `ipv6_only` | `bool` | `false` для `::` | Ограничить привязку `::` только IPv6. |
| `filter` | `string \| string[] \| object` | — | Фильтр разрешённых/запрещённых IP/CIDR клиентов. |

### Пример конфигурации `redirect`

```json
{
  "type": "redirect",
  "tag": "redirect-in",
  "listen": "::",
  "listen_port": 7892,
  "filter": {
    "allow": ["192.168.0.0/16", "fc00::/7"]
  }
}
```

---

## `direct`

Инбаунд `direct` принимает необработанные TCP-соединения и/или UDP-датаграммы и отправляет их в конвейер маршрутизации. Используется для локального проброса портов, перехвата DNS (например, на порту `53` с правилом `hijack-dns`) или статического форвардинга на фиксированный узел.

### Поведение рантайма

- **Адрес назначения**: по умолчанию целевым адресом считается локальный адрес, на который пришло соединение/датаграмма. При задании `override_address` подменяется целевой IP или домен (порт сохраняется), при задании `override_port` — целевой порт (адрес сохраняется), при задании обоих полей — вся пара `адрес:порт`.
- **Общий эфемерный порт**: при `listen_port: 0` и одновременном включении TCP и UDP ядро подбирает свободный порт, доступный для обоих протоколов одновременно.
- **UDP**: поддерживает до 512 одновременных задач инициализации UDP-потоков; таймаут задаётся через `udp_timeout`.

### Поля конфигурации `direct`

Наследует общие поля прослушивания из [common-objects.md](../common-objects.md):

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | обязательное | `"direct"`. |
| `tag` | `string` | `"direct"` | Идентификатор инбаунда. |
| `listen` | `string` | `"127.0.0.1"` | Адрес прослушивания. |
| `listen_port` | `uint16` | обязательное | Порт прослушивания (может быть `0` для автоподбора). |
| `network` | `string \| string[]` | TCP и UDP | Разрешённые транспортные протоколы: `"tcp"`, `"udp"` или оба. |
| `override_address` | `string` | `""` | Переопределить IP-адрес или доменное имя назначения. |
| `override_port` | `uint16` | `0` | Переопределить порт назначения (`1..=65535`). |
| `udp_timeout` | `duration` | `"2m"` (`120s`) | Таймаут неактивности UDP-потоков. |

### Пример конфигурации `direct` (локальный DNS-перехватчик)

```json
{
  "type": "direct",
  "tag": "dns-in",
  "listen": "127.0.0.1",
  "listen_port": 5353,
  "network": ["tcp", "udp"],
  "override_address": "1.1.1.1",
  "override_port": 53
}
```

---

## `mixed`

Инбаунд `mixed` обслуживает протоколы SOCKS4, SOCKS4a, SOCKS5 (TCP `CONNECT` и UDP `ASSOCIATE`) и HTTP-прокси (туннелирование `CONNECT` и обычные HTTP-запросы с абсолютным URI) на одном TCP-порту. Выбор протокола происходит автоматически по первому байту входящего соединения (`0x05` -> SOCKS5, `0x04` -> SOCKS4/4a, иначе HTTP).

### Поведение рантайма

- **TLS на `mixed`**: при включённом `tls` (`"tls": {"enabled": true, ...}`) все соединения после TLS-рукопожатия обслуживаются как HTTPS-прокси (HTTP поверх TLS).
- **Аутентификация (`users`)**:
  - Для SOCKS5 используется метод `0x02` (логин/пароль RFC 1929).
  - Для SOCKS4/4a передаётся только `userid` без пароля — вход разрешается, если в `users` есть запись с совпадающим `username` и пустым `password` (`""`).
  - Для HTTP проверяется заголовок `Proxy-Authorization: Basic ...`.
- **UDP ASSOCIATE**: активен по умолчанию (если `tls` не включён). Поддерживает пересылку UDP-датаграмм с фреймингом SOCKS5.
- **Фильтрация источника**: поддерживается `filter` для ограничения доступа по IP/CIDR.

### Поля конфигурации `mixed`

Наследует общие поля прослушивания из [common-objects.md](../common-objects.md):

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | обязательное | `"mixed"`. |
| `tag` | `string` | `"mixed"` | Идентификатор инбаунда. |
| `listen` | `string` | `"127.0.0.1"` | Адрес прослушивания. |
| `listen_port` | `uint16` | обязательное | Порт прослушивания. |
| `users` | `object[]` | `[]` | Список учётных записей `{"username": "...", "password": "..."}`. Если пуст, аутентификация не требуется. |
| `domain_resolver` | `object` | — | Объект настройки DNS-резолвера для этого инбаунда (см. [common-objects.md](../common-objects.md)). |
| `set_system_proxy` | `bool` | `false` | Поле схемы совместимости для настройки системного прокси ОС. |
| `tls` | `object` | — | Объект серверного TLS (`InboundTLSOptions`, см. [common-objects.md](../common-objects.md)). При включении порт работает как HTTPS-прокси. |

### Пример конфигурации `mixed`

```json
{
  "type": "mixed",
  "tag": "mixed-in",
  "listen": "127.0.0.1",
  "listen_port": 1080,
  "users": [
    {
      "username": "local",
      "password": "change-me"
    }
  ],
  "filter": "127.0.0.0/8"
}
```

---

## `socks`

Инбаунд `socks` обслуживает только протоколы SOCKS4, SOCKS4a и SOCKS5 (TCP `CONNECT` и SOCKS5 UDP `ASSOCIATE`). HTTP-запросы на этом порту отклоняются.

### Поля конфигурации `socks`

Наследует общие поля прослушивания из [common-objects.md](../common-objects.md). Объект `tls` на `socks` не поддерживается.

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | обязательное | `"socks"`. |
| `tag` | `string` | `"socks"` | Идентификатор инбаунда. |
| `listen` | `string` | `"127.0.0.1"` | Адрес прослушивания. |
| `listen_port` | `uint16` | обязательное | Порт прослушивания. |
| `users` | `object[]` | `[]` | Список учётных записей `{"username": "...", "password": "..."}`. |
| `domain_resolver` | `object` | — | Объект настройки DNS-резолвера для этого инбаунда. |

### Пример конфигурации `socks`

```json
{
  "type": "socks",
  "tag": "socks-in",
  "listen": "127.0.0.1",
  "listen_port": 1081,
  "users": [
    {
      "username": "socksuser",
      "password": "strong-password"
    }
  ]
}
```

---

## `http`

Инбаунд `http` обслуживает только HTTP-прокси (туннелирование `CONNECT` для HTTPS/TCP и обычные HTTP-запросы с абсолютным URI). Запросы SOCKS4/5 отклоняются; UDP `ASSOCIATE` отсутствует.

### Поля конфигурации `http`

Наследует общие поля прослушивания из [common-objects.md](../common-objects.md):

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | обязательное | `"http"`. |
| `tag` | `string` | `"http"` | Идентификатор инбаунда. |
| `listen` | `string` | `"127.0.0.1"` | Адрес прослушивания. |
| `listen_port` | `uint16` | обязательное | Порт прослушивания. |
| `users` | `object[]` | `[]` | Список учётных записей `{"username": "...", "password": "..."}` для `Proxy-Authorization: Basic`. |
| `domain_resolver` | `object` | — | Объект настройки DNS-резолвера для этого инбаунда. |
| `set_system_proxy` | `bool` | `false` | Поле схемы совместимости для настройки системного прокси ОС. |
| `tls` | `object` | — | Объект серверного TLS (`InboundTLSOptions`) для запуска HTTPS-прокси. |

### Пример конфигурации `http` (HTTPS-прокси)

```json
{
  "type": "http",
  "tag": "https-proxy-in",
  "listen": "0.0.0.0",
  "listen_port": 8443,
  "users": [
    {
      "username": "proxyuser",
      "password": "strong-password"
    }
  ],
  "tls": {
    "enabled": true,
    "certificate_path": "/etc/tachyon-core/cert.pem",
    "key_path": "/etc/tachyon-core/key.pem"
  }
}
```
