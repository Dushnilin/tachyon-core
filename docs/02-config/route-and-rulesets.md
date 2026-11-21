# Секция `route` и наборы правил (`rule_set`)

Секция `route` определяет конвейер классификации и маршрутизации трафика: перехват DNS, инспекцию протоколов (`sniff`), принудительное разрешение имён (`resolve`), правила сопоставления и наборы правил (`rule_set`), а также глобальные параметры исходящего интерфейса, FullCone NAT и приоритизации интерактивных потоков.

---

## Глобальные поля секции `route`

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `rules` | `array<object>` | `[]` | Список правил маршрутизации, проверяемых последовательно сверху вниз. |
| `final` | `string` | первый outbound | Тег исходящего подключения по умолчанию, если ни одно терминальное правило не совпало. |
| `rule_set` | `array<object>` | `[]` | Объявления наборов правил (`inline`, `local`, `remote`). |
| `auto_detect_interface` | `bool` | `false` | Автоматически определяет исходящий WAN-интерфейс по таблице маршрутизации ОС (Linux; на Android отключено во избежание конфликта с `VpnService.protect`). Имеет более низкий приоритет, чем `default_interface`. |
| `default_interface` | `string` | — | Исходящий сетевой интерфейс по умолчанию для всех `outbounds` без собственного `bind_interface`. |
| `default_mark` | `uint32` | — | Метка маршрутизации Linux (`SO_MARK`) по умолчанию для всех исходящих сокетов без собственной `routing_mark`. |
| `default_domain_resolver` | `string \| object` | — | Тег DNS-сервера (или объект `{"server": "<тег>", "strategy": "...", "timeout": "..."}`) для разрешения адресов серверов в `outbounds`/`endpoints`. Обязателен, если в `dns.servers` задано >= 2 серверов и не у каждого outbound задан свой `domain_resolver`. |
| `default_http_client` | `string` | — | Тег именованного клиента из корневой секции `http_clients`, используемого по умолчанию при загрузке удалённых `rule_set`. |
| `find_process` | `bool` | `false` | Включает поиск локального процесса-владельца сокета для всех соединений (также активируется автоматически, если хотя бы одно правило использует `process_*`, `user`, `user_id`). |
| `find_neighbor` | `bool` | `false` | Включает сбор таблиц соседей (ARP/NDP и DHCP leases) для определения MAC-адреса и имени хоста клиента (активируется автоматически при наличии правил с `source_mac_address` / `source_hostname`). |
| `dhcp_lease_files` | `Listable<string>` | системные пути | Пользовательские пути к файлам DHCP leases (например, `/tmp/dhcp.leases` на OpenWrt) для `find_neighbor`. |
| `fullcone` | `bool` | `false` | Глобально включает FullCone NAT (EIM/EIF) для UDP-сессий. |
| `udp_nat_mode` | `string` | `"default"` | Глобальный режим UDP NAT: `"fullcone"`, `"full_cone"`, `"full-cone"`, `"eim_eif"`, `"endpoint_independent"`, `"symmetric"`, `"default"`. |
| `udp_fullcone_max_bindings` | `int` | `4096` | Максимум одновременных FullCone UDP-привязок (`64..=65536`). |
| `smart_queue` | `bool \| object` | `false` | Приоритизация интерактивных потоков над фоновыми загрузками (CAKE-lite). Принимает `bool` или объект: `enabled` (`bool`, по умолч. `true`), `bulk_threshold_bytes` (`uint64 >= 1024`, по умолч. `1048576` — 1 MiB), `interactive_max_packet_size` (`64..=16384`, по умолч. `1024`), `bulk_quantum_kib` (`4..=1024`, по умолч. `32`). |
| `override_android_vpn` | `bool` | `false` | Поле совместимости схемы для Android VPN. |
| `default_network_strategy` | `string` | — | Стратегия выбора сетей по умолчанию (поле совместимости схемы). |
| `default_network_type` | `Listable<string>` | — | Типы сетей по умолчанию (поле совместимости схемы). |
| `default_fallback_network_type` | `Listable<string>` | — | Резервные типы сетей по умолчанию (поле совместимости схемы). |
| `default_fallback_delay` | `Duration` | — | Задержка переключения по умолчанию (поле совместимости схемы). |
| `interface_addresses` | `object` | — | Карта адресов интерфейсов (поле совместимости схемы). |
| `lx_idle_suspend`, `lx_idle_suspend_reachable`, `lx_idle_teardown` | `Duration` | — | Устаревшие псевдонимы для `lx.wg.idle_suspend*` (выдают предупреждение; конфликтующее значение с `lx.wg.*` вызывает ошибку). |
| `geoip`, `geosite` | `object` | — | Устаревшие базы GeoIP/GeoSite удалены; их использование в правилах завершается ошибкой. Используйте `rule_set`. |

---

## Матчинг правил (`route.rules[]`)

Правила бывают двух видов:
- **Обычное правило** (`"type": "default"` или поле `type` опущено): все перечисленные в объекте условия объединяются через логическое **И** (AND); значения внутри каждого списочного поля — через логическое **ИЛИ** (OR). Должно содержать хотя бы одно условие (кроме `invert` и `type`).
- **Логическое правило** (`"type": "logical"`): объединяет массив вложенных правил `rules` по режиму `mode: "and"` или `mode: "or"`. Вложенные правила являются чистыми условиями и **не могут** содержать поля действий (`action`, `outbound`, `override_address`, `override_port`, `method`, `no_drop`, `sniffer`, `timeout`, `server`, `strategy`, `disable_cache`, `disable_optimistic_cache`, `rewrite_ttl`, `client_subnet`, `network_strategy`, `fallback_delay`, `udp_timeout`, `udp_connect`, `udp_disable_domain_unmapping`, `tls_fragment`, `tls_fragment_fallback_delay`, `tls_record_fragment`, `tls_spoof`, `tls_spoof_method`, `ips_excluded`, `ipsExcluded`, `domains_excluded`, `domainsExcluded`).

### Полная таблица матчеров `route.rules[]`

| Поле | Тип | Описание |
|---|---|---|
| `type` | `string` | `""` / `"default"` или `"logical"`. |
| `mode` | `string` | Режим логического правила: `"and"` или `"or"` (обязательно при `type: "logical"`). |
| `rules` | `array<object>` | Непустой массив вложенных правил-условий (только при `type: "logical"`). |
| `invert` | `bool` | Инвертирует итоговый результат совпадения условий правила. |
| `inbound` | `Listable<string>` | Тег входящего подключения (`inbounds[].tag`). |
| `ip_version` | `int` | Версия IP-протокола назначения: `4` или `6`. |
| `network` | `Listable<string>` | Транспортный протокол: `"tcp"`, `"udp"`. |
| `auth_user` | `Listable<string>` | Имя аутентифицированного пользователя входящего подключения (`users[].name` / `username`). |
| `protocol` | `Listable<string>` | Протокол, определённый инспекцией (`sniff`): `"tls"`, `"http"`, `"quic"`, `"dns"`, `"stun"`, `"bittorrent"`, `"dtls"`, `"ssh"`, `"rdp"`, `"ntp"`. |
| `client` | `Listable<string>` | Идентификатор клиентского приложения (если определён инспекцией, например BitTorrent-клиент). |
| `domain` | `Listable<string>` | Точное совпадение домена назначения (регистронезависимо, пустые строки запрещены). |
| `domain_suffix` | `Listable<string>` | Совпадение домена или его поддоменов (пустые строки запрещены). |
| `domain_keyword` | `Listable<string>` | Вхождение подстроки в домен назначения. |
| `domain_regex` | `Listable<string>` | Регулярное выражение RE2 для домена назначения (валидируется при `check`). |
| `ip_cidr` | `Listable<CIDR>` | IP-адрес или подсеть назначения (IPv4/IPv6). |
| `ip_is_private` | `bool` | `true`, если IP назначения относится к частным/служебным диапазонам (RFC 1918, loopback, link-local, CGNAT, ULA и др.). |
| `source_ip_cidr` | `Listable<CIDR>` | IP-адрес или подсеть источника (клиента). |
| `source_ip_is_private` | `bool` | `true`, если IP источника приватный. |
| `port` | `Listable<uint16>` | Точный порт назначения (`0..65535`). |
| `port_range` | `Listable<port_range>` | Диапазон портов назначения формата `"start:end"` (например, `"10000:20000"`, `":1024"`). |
| `source_port` | `Listable<uint16>` | Точный порт источника. |
| `source_port_range` | `Listable<port_range>` | Диапазон портов источника формата `"start:end"`. |
| `clash_mode` | `Listable<string>` | Текущий режим работы Clash API: `"rule"`, `"global"`, `"direct"`. |
| `rule_set` | `Listable<string>` | Ссылка на тег(и) наборов правил из `route.rule_set`. |
| `rule_set_ip_cidr_match_source` (`rule_set_ipcidr_match_source`) | `bool` | Сопоставляет IP-записи указанных `rule_set` с исходным IP клиента вместо IP назначения. |
| `process_name` | `Listable<string>` | Имя исполняемого файла процесса-владельца сокета (базовое имя пути). |
| `process_path` | `Listable<string>` | Полный путь к исполняемому файлу процесса. |
| `process_path_regex` | `Listable<string>` | Регулярное выражение RE2 для пути процесса (валидируется при `check`). |
| `user` | `Listable<string>` | Имя системного пользователя-владельца процесса. |
| `user_id` | `Listable<int32>` | Числовой UID владельца процесса (`-1` зарезервировано как «неизвестно» и не совпадает). |
| `source_mac_address` | `Listable<string>` | MAC-адрес клиента (из таблицы соседей `find_neighbor`). |
| `source_hostname` | `Listable<string>` | Имя хоста клиента из DHCP leases (`find_neighbor`). |
| `time_window` | `Listable<string>` | Расписание активности правила (см. раздел ниже). |
| `interface_address` | `object` | Словарь `{"<iface>": Listable<CIDR>}` — совпадение, если указанный интерфейс хоста имеет адрес в данном CIDR. |
| `network_interface_address` | `object` | Словарь `{"<тип_сети>": Listable<CIDR>}` — совпадение по типу интерфейса (`wifi`, `ethernet` и т. д.). |
| `default_interface_address` | `Listable<CIDR>` | Совпадение, если текущий WAN-интерфейс по умолчанию имеет адрес из указанного CIDR. |
| `preferred_by` | `Listable<string>` | Совпадение для соединений, предпочитаемых перечисленными тегами исходящих подключений / эндпоинтов (например, подсети `tailscale`). |
| `dns_server_address` | `Listable<CIDR> \| object` | Совпадение с адресом DNS-сервера (плоский список IP/CIDR или карта `{"<dns_tag>": Listable<CIDR>}`). |
| `dns_search_domain` | `Listable<string> \| object` | Совпадение с поисковым доменом DNS (список строк или карта `{"<dns_tag>": Listable<string>}`). |
| `package_name`, `package_name_regex`, `network_type`, `network_is_expensive`, `network_is_constrained`, `wifi_ssid`, `wifi_bssid` | — | Принимаются валидатором для совместимости мобильных профилей; во время выполнения на настольных/роутерных ОС не сопоставляются (всегда возвращают `false` с предупреждением в лог). |

### Формат `time_window`

Матчер `time_window` поддерживается и в `route.rules[]`, и в `dns.rules[]`. Каждая строка имеет синтаксис:

```text
[дни] HH:MM-HH:MM [часовой_пояс]
```

- **`дни`** (опционально; по умолчанию все дни): список через запятую, поддерживаются диапазоны через `-`:
  - англ.: `mon`/`monday`, `tue`/`tues`/`tuesday`, `wed`/`wednesday`, `thu`/`thur`/`thurs`/`thursday`, `fri`/`friday`, `sat`/`saturday`, `sun`/`sunday`;
  - рус.: `пн`, `вт`, `ср`, `чт`, `пт`, `сб`, `вс`;
  - цифры: `1` (пн) .. `7` / `0` (вс);
  - группы: `*`, `all`, `daily`, `everyday`, `weekdays`, `workdays`, `weekends`, `weekend`.
- **`HH:MM-HH:MM`** (обязательно): интервал времени от `00:00` до `24:00`. Если время начала больше времени окончания (например, `"mon-fri 22:00-06:00"`), интервал автоматически переносится через полночь.
- **`часовой_пояс`** (опционально; по умолчанию `local`): `"local"`, `"UTC"`, `"GMT"`, `"Z"`, либо фиксированное смещение `±HH` / `±HH:MM` / `UTC±HH` / `UTC±HH:MM` (в пределах от `-14:00` до `+14:00`).

---

## Действия правил (`route.rules[].action`)

Действия делятся на **промежуточные** (`sniff`, `resolve`, `route-options`), которые обогащают метаданные или модифицируют параметры и передают управление следующему правилу, и **терминальные** (`route`, `direct`, `bypass`, `reject`, `hijack-dns`), которые завершают обход таблицы.

| `action` | Поля действия | По умолчанию | Описание |
|---|---|---|---|
| `route` *(по умолчанию)* | `outbound` *(обязательно)* + все поля `route-options` | — | Направляет соединение в указанный тег `outbounds` или `endpoints`. |
| `route-options` | `override_address` (`string`), `override_port` (`uint16`), `udp_timeout` (`Duration`), `udp_disable_domain_unmapping` (`bool`), `tls_fragment` (`bool`), `tls_fragment_fallback_delay` (`Duration`), `tls_record_fragment` (`bool`), `tls_spoof` (`string`), `tls_spoof_method` (`string`), `network_strategy` (`string`), `fallback_delay` (`Duration`), `udp_connect` (`bool`) | — | Применяет опции маршрутизации к соединению и продолжает проход по правилам. Примечание: `override_address` меняет только хост (встроенный порт в строке игнорируется); поля `network_strategy`, `fallback_delay` и `udp_connect` валидируются схемой, но при выполнении логируют предупреждение и игнорируются. |
| `direct` | — | — | Прямое исходящее соединение (аналог направления в `direct`). |
| `bypass` | `outbound` (опционально) + поля `route-options` | — | Обходное направление: при указанном `outbound` отправляет трафик туда с применёнными опциями. |
| `reject` | `method` (`"default"`, `"drop"`, `"reply"`), `no_drop` (`bool`, запрещено при `method: "drop"`) | `method: "default"`, `no_drop: false` | Отклоняет соединение. В режиме `"default"` отправляет отказ; при превышении порога (>50 срабатываний правила за 30 с) автоматически эскалирует в `"drop"` (если `no_drop` не `true`). `"drop"` молча сбрасывает пакеты/соединение. |
| `hijack-dns` | — | — | Перехватывает DNS-трафик (TCP/UDP) и передаёт запрос во встроенную службу `dns`. |
| `sniff` | `sniffer` (`Listable<string>`), `timeout` (`Duration`), `ips_excluded` / `ipsExcluded` (`Listable<string>`), `domains_excluded` / `domainsExcluded` (`Listable<string>`) | `sniffer`: все; `timeout`: `"300ms"` | Инспектирует начальные байты потока/датаграмм, определяя `protocol` и домен назначения (`domain`). Допустимые имена `sniffer`: `"tls"`, `"http"`, `"quic"`, `"dns"`, `"stun"`, `"bittorrent"`, `"bittorrent-extended"`, `"dtls"`, `"ssh"`, `"rdp"`, `"ntp"`. Поля `ips_excluded`/`domains_excluded` исключают указанные IP/домены из инспекции или подмены домена. |
| `resolve` | `server` (`string`), `strategy` (`string`), `timeout` (`Duration`), `disable_cache` (`bool`), `rewrite_ttl` (`uint32`), `client_subnet` (`IP \| CIDR`), `disable_optimistic_cache` (`bool`) | — | Выполняет DNS-разрешение домена назначения прямо во время маршрутизации, чтобы последующие правила с `ip_cidr` / `ip_is_private` могли сработать по полученному IP. |

---

## Наборы правил (`route.rule_set[]`)

Наборы правил выносят крупные списки доменов, IP-префиксов и портов в отдельные встроенные, локальные или загружаемые по HTTP/HTTPS источники. Один и тот же `rule_set` может использоваться одновременно в `route.rules[]` и `dns.rules[]`.

### Типы наборов правил (`type`)

#### 1. `type: "inline"` (по умолчанию, если `type` не указан)

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | `"inline"` | Встроенный набор правил. |
| `tag` | `string` | *(обязательно)* | Одиночный тег (множественные теги для `inline` запрещены). |
| `format` | `string` | `"source"` | Формат правил (необязательно для `inline`). |
| `rules` | `array<object>` | *(обязательно, непустой)* | Массив безголовых правил (`HeadlessRule`, см. ниже). |

#### 2. `type: "local"`

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | `"local"` | Загрузка набора правил из локального файла. |
| `tag` | `Listable<string>` | *(обязательно)* | Один тег или массив тегов. При массиве из >= 2 тегов поле `path` обязано содержать шаблон `{tag}` (подставляется для каждого тега). |
| `path` | `string` | *(обязательно)* | Путь к локальному файлу (проверяется на существование и корректность заголовка/формата на этапе `check`). |
| `format` | `string` | по расширению файла | Формат файла: `"source"` (`.json`), `"binary"` (`.srs`), `"trs"` / `"tsr"` (`.trs` / `.tsr` — бинарный формат TSRS v2). Если расширение нестандартное, поле `format` обязательно. |
| `mmap` | `bool` | `false` | Включает zero-copy отображение бинарного файла `.trs` в память (`mmap`). |
| `mode` | `string` | `"auto"` | Режим загрузки в память: `"auto"`, `"mmap"`, `"memory"`. |

#### 3. `type: "remote"`

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | `"remote"` | Периодическая загрузка набора правил по HTTP/HTTPS. |
| `tag` | `Listable<string>` | *(обязательно)* | Один или несколько тегов. При >= 2 тегах `url` (и непустой `initial_path`, если задан) обязаны содержать шаблон `{tag}`. |
| `url` | `string` | *(обязательно)* | URL для загрузки набора правил. |
| `format` | `string` | по расширению URL (без query-части) | `"source"` (`.json`), `"binary"` (`.srs`), `"trs"` / `"tsr"` (`.trs` / `.tsr`). |
| `initial_path` | `string` | — | Локальный файл для немедленного старта до завершения первой сетевой загрузки. |
| `update_interval` | `Duration` | `"24h"` | Период проверки обновлений (с поддержкой `ETag`). |
| `download_detour` | `string` | — | Тег outbound, через который выполняется скачивание. |
| `http_client` | `string \| object` | `route.default_http_client` | Тег из корневой секции `http_clients` либо встроенный объект HTTP-клиента (`url`, `headers`, `proxy`, `dialer`, `tls`, `idle_timeout`, `insecure`, `address_resolver`, `address_strategy`, `network`, `network_type`, `network_is_expensive`, `network_is_constrained` + поля `dialer`). |
| `mmap` | `bool` | `false` | Компилирует и подключает загруженный набор через zero-copy `mmap` файл `.trs`. |
| `mode` | `string` | `"auto"` | Режим хранения: `"auto"`, `"mmap"`, `"memory"`. |
| `delta_update` | `bool` | `false` | Включает инкрементальные бинарные дельта-обновления. |
| `cache_interval` | `Duration` | — | Переопределяет интервал обновления кэша набора. |
| `cache_file` | `string` | `/tmp/tachyon-rulesets/<tag>.trs` (Unix) | Пользовательский путь к локальному кэшу `.trs` (на Linux/OpenWrt путь по умолчанию в `/tmp` предотвращает износ flash-памяти; при хранении в `experimental.cache_file` пакеты крупнее 64 KiB выносятся в `.trs`, а в `cache.db` пишутся только 48-байтные метаданные). |

Поведение при старте без сети: по умолчанию включён мягкий старт (`TACHYON_RULESET_SOFT_START` != `"0"`/`"false"`/`"no"`): если удалённый набор недоступен при запуске, ядро стартует с пустым набором и повторяет загрузку по ступенчатой схеме (1 с, 3 с, 5 с, 10 с, 20 с, 30 с).

### Форматы файлов наборов правил

| Формат | Расширение | Особенности |
|---|---|---|
| `source` | `.json` | JSON-объект `{"version": 1..5, "rules": [ ...HeadlessRule ]}`. |
| `binary` | `.srs` | Стандартный сжатый бинарный контейнер sing-box rule-set. |
| `trs` / `tsr` | `.trs`, `.tsr` | Нативный бинарный формат TSRS v2 (магический заголовок `TSRS`, версия `2`), пригодный для прямого zero-copy `mmap` без распаковки в кучу RAM. |

### Допустимые поля безголовых правил (`HeadlessRule`)

Используются в `inline` rule-set и файлах `source` (`.json`):

`type`, `query_type`, `network`, `domain`, `domain_suffix`, `domain_keyword`, `domain_regex`, `source_ip_cidr`, `ip_cidr`, `source_port`, `source_port_range`, `port`, `port_range`, `process_name`, `process_path`, `process_path_regex`, `package_name`, `package_name_regex`, `network_type`, `network_is_expensive`, `network_is_constrained`, `wifi_ssid`, `wifi_bssid`, `network_interface_address`, `default_interface_address`, `interface_address`, `preferred_by`, `dns_server_address`, `dns_search_domain`, `invert`.

---

## Пример конфигурации секции `route`

```json
{
  "route": {
    "auto_detect_interface": true,
    "default_domain_resolver": "dns-local",
    "find_neighbor": true,
    "dhcp_lease_files": ["/tmp/dhcp.leases"],
    "fullcone": true,
    "udp_fullcone_max_bindings": 4096,
    "smart_queue": {
      "enabled": true,
      "bulk_threshold_bytes": 1048576,
      "interactive_max_packet_size": 1024,
      "bulk_quantum_kib": 32
    },
    "rule_set": [
      {
        "type": "inline",
        "tag": "local-corp",
        "rules": [
          {
            "domain_suffix": [".corp.internal"],
            "ip_cidr": ["10.20.0.0/16"]
          }
        ]
      },
      {
        "type": "local",
        "tag": "geoip-private",
        "format": "trs",
        "path": "/etc/tachyon-core/rules/private.trs",
        "mmap": true,
        "mode": "mmap"
      },
      {
        "type": "remote",
        "tag": ["geosite-category-a", "geosite-category-b"],
        "format": "binary",
        "url": "https://rules.example.com/{tag}.srs",
        "download_detour": "proxy-out",
        "update_interval": "24h",
        "mmap": true
      }
    ],
    "rules": [
      {
        "action": "sniff",
        "sniffer": ["tls", "http", "quic", "dns"],
        "timeout": "300ms",
        "ips_excluded": ["192.168.0.0/16"]
      },
      {
        "protocol": "dns",
        "action": "hijack-dns"
      },
      {
        "ip_is_private": true,
        "action": "route",
        "outbound": "direct"
      },
      {
        "type": "logical",
        "mode": "and",
        "rules": [
          { "rule_set": ["geosite-category-a"] },
          { "time_window": "weekdays 09:00-19:00 +03:00" }
        ],
        "action": "route",
        "outbound": "proxy-out"
      },
      {
        "domain_suffix": ["video.example.net"],
        "action": "route-options",
        "tls_record_fragment": true
      },
      {
        "port": [443],
        "network": "udp",
        "action": "reject",
        "method": "drop"
      }
    ],
    "final": "direct"
  }
}
```
