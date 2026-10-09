# Инбаунд `tun`


> **Статус: реализован, но не проверен на живом устройстве.** Код в
> `crates/core-runtime/src/inbound/tun.rs` (1623 строки) содержит TCP-стек на
> `smoltcp`, NAT, GSO-сегментацию и policy routing. Интеграционных тестов на
> реальном `/dev/net/tun` нет, поэтому работоспособность на роутере не
> подтверждена. Проверенный режим прозрачного проксирования — `tproxy`.

Виртуальный L3-интерфейс `/dev/net/tun` для захвата трафика.

## Поля

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `interface_name` | string | `tun0` | Имя создаваемого интерфейса, по умолчанию `tun0`. |
| `netns` | string | -- | Сетевое пространство имён. Предупреждается в лог и игнорируется. |
| `mtu` | uint32 | `9000` | MTU интерфейса, по умолчанию `9000`. На роутере разумно `1500`: ICMP errors не передаются, поэтому при несовпадении MTU соединения будут зависать. |
| `address` | string / array | -- | Адреса интерфейса в CIDR: `172.19.0.1/30`. Строка или список. Основной способ задать адрес. |
| `dns_mode` | string | -- | Режим DNS: `fakeip` или `redir_host`. Предупреждается в лог и игнорируется. |
| `dns_address` | string / array | -- | Адреса DNS-сервера внутри туннеля. Предупреждается в лог и игнорируется. |
| `auto_route` | boolean | `false` | Настроить policy routing автоматически: отдельная таблица (по умолчанию 2022) плюс правила с исключением по fwmark `0x2022`. |
| `iproute2_table_index` | uint32 | `2022` | Индекс таблицы маршрутизации iproute2, по умолчанию `2022`. |
| `iproute2_rule_index` | uint32 | `9000` | Приоритет правила маршрутизации iproute2, по умолчанию `9000`. |
| `auto_redirect` | boolean | -- | Использовать `nftables` redirect для прозрачного перехвата. Предупреждается в лог и игнорируется. |
| `auto_redirect_input_mark` | uint32 | -- | Метка входных пакетов для `auto_redirect`. Предупреждается в лог и игнорируется. |
| `auto_redirect_output_mark` | uint32 | -- | Метка выходных пакетов для `auto_redirect`. Предупреждается в лог и игнорируется. |
| `auto_redirect_reset_mark` | boolean | -- | Сбрасывать метку после обработки. Предупреждается в лог и игнорируется. |
| `auto_redirect_nfqueue` | boolean | -- | Использовать NFQUEUE вместо MARK. Предупреждается в лог и игнорируется. |
| `auto_redirect_iproute2_fallback_rule_index` | uint32 | -- | Индекс запасного правила iproute2. Предупреждается в лог и игнорируется. |
| `exclude_mptcp` | boolean | -- | Исключить MPTCP. Предупреждается в лог и игнорируется. |
| `loopback_address` | string / array | -- | Адреса loopback внутри туннеля. Предупреждается в лог и игнорируется. |
| `strict_route` | boolean | `false` | Добавить blackhole-маршрут по умолчанию в таблицу туннеля, чтобы исключить утечки мимо него. |
| `route_address` | string / array | -- | Маршруты, которые нужно направить в туннель. Предупреждается в лог и игнорируется. |
| `route_address_set` | string / array | -- | Наборы адресов для маршрутизации в туннель. Предупреждается в лог и игнорируется. |
| `route_exclude_address` | string / array | -- | Маршруты, которые нужно исключить из туннеля. Предупреждается в лог и игнорируется. |
| `route_exclude_address_set` | string / array | -- | Наборы адресов, исключаемых из туннеля. Предупреждается в лог и игнорируется. |
| `include_interface` | string / array | -- | Интерфейсы, чей трафик попадает в туннель. Предупреждается в лог и игнорируется. |
| `exclude_interface` | string / array | -- | Интерфейсы, чей трафик не попадает в туннель. Предупреждается в лог и игнорируется. |
| `include_uid` | array | -- | UID процессов, чей трафик попадает в туннель. Предупреждается в лог и игнорируется. |
| `include_uid_range` | string / array | -- | Диапазоны UID, попадающих в туннель. Предупреждается в лог и игнорируется. |
| `exclude_uid` | array | -- | UID процессов, чей трафик не попадает в туннель. Предупреждается в лог и игнорируется. |
| `exclude_uid_range` | string / array | -- | Диапазоны UID, исключённых из туннеля. Предупреждается в лог и игнорируется. |
| `include_android_user` | array | -- | Android: список пользователей. Предупреждается в лог и игнорируется. |
| `include_package` | string / array | -- | Имена пакетов, чей трафик попадает в туннель. Предупреждается в лог и игнорируется. |
| `exclude_package` | string / array | -- | Имена пакетов, чей трафик не попадает в туннель. Предупреждается в лог и игнорируется. |
| `include_mac_address` | string / array | -- | MAC-адреса, чей трафик попадает в туннель. Предупреждается в лог и игнорируется. |
| `exclude_mac_address` | string / array | -- | MAC-адреса, чей трафик не попадает в туннель. Предупреждается в лог и игнорируется. |
| `udp_timeout` | string | `5m` | Таймаут UDP-сессии, вида `30s` или `5m`. **Читается рантаймом.** |
| `udp_mapping` | string | -- | Режим маппинга UDP: `endpoint_independent`, `address_dependent`, `address_and_port_dependent`. Предупреждается в лог и игнорируется. |
| `udp_filtering` | string | -- | Фильтрация UDP: `timeout` или `strict`. Предупреждается в лог и игнорируется. |
| `udp_nat_max` | uint16 | -- | Размер таблицы NAT для UDP. Предупреждается в лог и игнорируется. |
| `stack` | string | -- | Стек: `system` или `mixed`. **Игнорируется без предупреждения**: TCP всегда обрабатывается userspace-стеком `smoltcp`. |
| `platform` | object | -- | Платформенные параметры. Предупреждается в лог и игнорируется. |
| `gso` | boolean | `false` | Включить GSO/GRO через `IFF_VNET_HDR`. По умолчанию выключено. При включении TSO-суперпакеты режутся на отдельные пакеты. |
| `inet4_address` | string / array | -- | Legacy-имя для IPv4-адреса. **Валидатор отклоняет**, используйте `address`. |
| `inet6_address` | string / array | -- | Legacy-имя для IPv6-адреса. **Валидатор отклоняет**, используйте `address`. |
| `inet4_route_address` | string / array | -- | IPv4-маршруты в туннель. Предупреждается в лог и игнорируется. |
| `inet6_route_address` | string / array | -- | IPv6-маршруты в туннель. Предупреждается в лог и игнорируется. |
| `inet4_route_exclude_address` | string / array | -- | IPv4-маршруты вне туннеля. Предупреждается в лог и игнорируется. |
| `inet6_route_exclude_address` | string / array | -- | IPv6-маршруты вне туннеля. Предупреждается в лог и игнорируется. |
| `endpoint_independent_nat` | boolean | -- | Full-Cone NAT для UDP. Предупреждается в лог и игнорируется. |

## Что реализовано

**TCP через userspace-стек `smoltcp`.** Стек инициализируется при bind, на
каждый новый интерфейс добавляются маршруты по умолчанию IPv4 и IPv6 с
`set_any_ip(true)`. Рукопожатие проходит целиком в userspace, соединение
перекачивается в целевой аутбаунд через `drive_transparent`. Сокеты
обслуживаются по событию прихода пакета и по таймеру в 20 мс — второй нужен для
повторов TCP, ACK и уборки сессий.

**UDP NAT с настоящими адресами.** Ответ строится из пары `(src, dest)`,
которую возвращает `UdpHub`, для IPv4 и для IPv6 отдельно. Прежняя потеря
адреса назначения устранена.

**ICMP и ICMPv6 echo.** Ответчик на ping по адресу интерфейса, с пересчётом
контрольных сумм.

**GSO/GRO.** `VirtioNetHdr::parse` разбирает заголовок, `segment_tso_packet`
режет TSO-суперпакет до 64 КБ на отдельные пакеты до обработки. Буфер чтения
при включённом GSO расширен до `65536 + VNET_HDR_LEN`.

**Policy routing без разрушения таблицы `main`.** `auto_route` создаёт
отдельную таблицу (по умолчанию 2022), ставит `ip rule ... lookup <table>
suppress_prefixlength 0` для прохода LAN и `ip rule ... not fwmark 0x2022
lookup <table>` для клиентского трафика, метка `0x2022` исключает собственные
исходящие соединения ядра из петли. Для IPv6 набор правил повторяется через
`ip -6`. `strict_route` добавляет blackhole-маршрут в таблицу туннеля.

**Уборка.** `cleanup_auto_route` вызывается из `Drop`: удаляются оба правила и
таблица (`route flush`), для IPv6 — через `ip -6`. Прежняя утечка `ip rule`
устранена.

**Адреса и маска.** Есть `SIOCSIFNETMASK`, IPv4 и IPv6 адреса разбираются
отдельно (`parse_ipv4_cidr`, `parse_ipv6_cidr`), поддерживается список
адресов.

## Чего нет

- **Нет интеграционных тестов на живом устройстве.** Девять unit-тестов в
  файле покрывают парс CIDR, расчёт netmask, размер и разбор virtio-заголовка,
  контрольные суммы ICMP, сегментацию TSO и capabilities устройства. Ни один
  тест не открывает `/dev/net/tun`. Файл ни разу не запускался в этом
  репозитории на реальном интерфейсе.
- **Multi-queue нет:** один `fd` и один reader-loop, без `IFF_MULTI_QUEUE` и
  `TUNSETQUEUE`.
- **Нет ICMP errors и PMTU:** только echo. Перехваченный ICMP «fragmentation
  needed» наружу не передаётся, поэтому при MTU 9000 и туннеле с меньшим MTU
  зависшие соединения возможны.
- **Ошибки записи по-прежнему глушатся** через `let _ =` в писателях UDP и
  ICMP.
- **`head-of-line blocking` в UDP-ветке:** `handle_ipv4_packet` вызывается в
  read-loop, без fast-path существующей сессии, который есть в `tproxy.rs`.

## Принимается конфигом, но рантаймом не используется

Из 47 разрешённых полей рантайм читает 11.

**Читаются:** `interface_name`, `mtu`, `address`, `gso`, `auto_route`,
`strict_route`, `iproute2_table_index`, `iproute2_rule_index`, `udp_timeout`,
а также legacy-имена `inet4_address` и `inet6_address`.

**Предупреждаются в лог и игнорируются** — 29 полей из списка
`WARN_IGNORED_FIELDS` (`tun.rs:55`). При появлении в конфиге печатается
`inbound tun[<tag>]: option "<поле>" is not honored by runtime`:
`netns`, `dns_mode`, `dns_address`, `auto_redirect`, `auto_redirect_input_mark`,
`auto_redirect_output_mark`, `auto_redirect_reset_mark`,
`auto_redirect_nfqueue`, `auto_redirect_iproute2_fallback_rule_index`,
`exclude_mptcp`, `loopback_address`, `route_address_set`,
`route_exclude_address_set`, `include_interface`, `exclude_interface`,
`include_uid`, `include_uid_range`, `exclude_uid`, `exclude_uid_range`,
`include_android_user`, `include_package`, `exclude_package`,
`include_mac_address`, `exclude_mac_address`, `udp_mapping`, `udp_filtering`,
`udp_nat_max`, `platform`, `endpoint_independent_nat`.

**Игнорируются без предупреждения** — 7 полей, единственное настоящее
нарушение правила «None of them is silent»:
`stack`, `route_address`, `route_exclude_address`, `inet4_route_address`,
`inet6_route_address`, `inet4_route_exclude_address`,
`inet6_route_exclude_address`.

Практическое следствие: фильтры по интерфейсам, UID, пакетам и MAC не
работают — на маршрутизаторе обычно не критично, на приставке с Android да;
маршруты по адресам не задаются; `stack` не выбирает userspace-стек, TCP всегда
обрабатывается `smoltcp`, и ключевое слово `system` ни на что не влияет.

## Значения по умолчанию

| Поле | По умолчанию |
|---|---|
| `interface_name` | `tun0` |
| `mtu` | `9000` |
| `gso` | `false` |
| `auto_route` | `false` |
| `strict_route` | `false` |
| `iproute2_table_index` | `2022` |
| `iproute2_rule_index` | `9000` |
| `udp_timeout` | `5m` |

Метка fwmark — `0x2022`, не настраивается. Правила создаются как
`not fwmark 0x2022 lookup <table>` с приоритетом `iproute2_rule_index` и
`lookup main suppress_prefixlength 0` с приоритетом на единицу меньше. Для
IPv6 набор повторяется через `ip -6`.

Обратите внимание: `gso` по умолчанию выключен, тогда как в документации
эталона он включён.

## Смежное

Инбаунд `fptn` переиспользует часть этого кода (`tun::build_ipv4_udp`,
`tun::ipv4_checksum`), но работает как WebSocket-туннель и к `/dev/net/tun`
не обращается.

## Пример

Конфиг приведён как иллюстрация формы. Работоспособность на устройстве
не подтверждена тестами — проверяйте на стенде, а не на боевом роутере.

```json
{
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "interface_name": "tun0",
      "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
      "mtu": 1500,
      "gso": true,
      "auto_route": true
    }
  ]
}
```

---
