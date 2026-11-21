# Секция `dns`

Секция `dns` настраивает встроенный DNS-резолвер `tachyon-core`: список серверов, правила маршрутизации и фильтрации запросов, кэширование, пулы FakeIP, оптимистичное кэширование и отбор наибыстрейшего IP. Если секция `dns` отсутствует, ядро использует системный резолвер ОС.

При наличии двух и более серверов в `dns.servers` требуется явно указать `route.default_domain_resolver` либо `domain_resolver` на каждом исходящем подключении (кроме `block`) — иначе `tachyon-core check` завершится ошибкой.

---

## Глобальные поля секции `dns`

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `servers` | `array<object>` | *(обязательно)* | Список типизированных DNS-серверов (каждый объект обязан содержать `type`). |
| `rules` | `array<object>` | `[]` | Последовательный список правил обработки DNS-запросов и ответов. |
| `final` | `string` | тег первого сервера в `servers` | Тег DNS-сервера по умолчанию для запросов, не совпавших ни с одним правилом. Сервер по умолчанию **не может** иметь тип `fakeip`. |
| `strategy` | `string` | `""` (`as_is`) | Глобальная стратегия выбора семейства адресов: `""`, `"as_is"`, `"prefer_ipv4"`, `"prefer_ipv6"`, `"ipv4_only"`, `"ipv6_only"`. |
| `timeout` | `Duration` | `"5s"` | Таймаут DNS-запроса по умолчанию для всех серверов (перекрывается полем `timeout` конкретного сервера). |
| `disable_cache` | `bool` | `false` | Полностью отключает кэширование DNS-ответов. Конфликтует с `optimistic`. |
| `disable_expire` | `bool` | `false` | Отключает истечение записей кэша по TTL. Конфликтует с `optimistic`. |
| `cache_capacity` | `int` | адаптивно по ОЗУ (минимум `1024`) | Максимальное число записей в сегментированном LRU-кэше DNS (меньшие значения поднимаются до `1024`). |
| `independent_cache` | `bool` | `false` | Устаревшее поле; принимается схемой, при `true` логируется предупреждение и игнорируется (внутренний кэш изолирован по тегу сервера и параметрам запроса). |
| `reverse_mapping` | `bool` | `false` | Включает обратное отображение `IP -> домен` (LRU на 1024 записи) по ответам `A`/`AAAA`/`HTTPS`/`SVCB`, позволяя правилам маршрутизации восстанавливать доменное имя для подключений по IP. |
| `client_subnet` | `IP \| CIDR` | — | Глобальный префикс EDNS0 Client Subnet (ECS), добавляемый к исходящим запросам (например, `"1.2.3.0/24"` или `"2001:db8::/56"`). |
| `optimistic` | `bool \| object` | `false` | Оптимистичный кэш: немедленно возвращает просроченный ответ в пределах окна и запускает фоновое обновление. Принимает `bool` (`true` -> окно `"72h"` / `3d`) или объект `{"enabled": bool, "timeout": Duration}`. Несовместимо с `disable_cache: true` и `disable_expire: true`. |
| `serve_stale` | `bool \| object` | `false` | Возврат устаревших записей кэша при недоступности вышестоящего DNS-сервера (RFC 8767). Принимает `bool` (окно по умолчанию `7d`) или объект `{"enabled": bool, "timeout": Duration}` (допускается псевдоним `max_stale`). |
| `fastest_ip` | `bool \| object` | `false` | Активная проверка TCP-достижимости возвращённых IP и перестановка самого быстрого IP в начало DNS-ответа (кэш результатов 5 минут). Принимает `bool` или объект `{"enabled": bool, "timeout": Duration (по умолч. "200ms"), "port": uint16 (по умолч. 443)}`. |

---

## Типы DNS-серверов (`dns.servers[]`)

Устаревший формат задания сервера строкой `address` (без поля `type`, например `"udp://1.1.1.1"` или `"rcode://refused"`) удалён и отклоняется ошибкой `legacy DNS server formats are deprecated and removed in tachyon-core, use typed DNS server objects instead`.

### Общие поля всех DNS-серверов

Каждый объект в `dns.servers[]` поддерживает:

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | *(обязательно)* | Тип DNS-транспорта (см. перечень ниже). |
| `tag` | `string` | *(обязательно при `run`)* | Уникальный идентификатор DNS-сервера. |
| `timeout` | `Duration` | `dns.timeout` (`"5s"`) | Индивидуальный таймаут запроса к данному серверу. |
| *(поля dialer)* | — | — | Все поля объекта [dialer](common-objects.md#объект-dialer-параметры-исходящего-подключения), включая `detour`, `bind_interface`, `routing_mark`, `domain_resolver`, `domain_strategy`, `connect_timeout` и др. |

### Сводка поддерживаемых типов `dns.servers[].type`

| `type` | Статус | Порт по умолчанию | Дополнительные поля | Назначение |
|---|---|---|---|---|
| `udp` | Работает | `53` | `server`, `server_port` | Классический DNS по UDP. |
| `tcp` | Работает | `53` | `server`, `server_port` | DNS по TCP. |
| `tls` | Работает | `53` *(рекомендуется явно задавать `853`)* | `server`, `server_port`, `tls` | DNS over TLS (DoT). TLS включается автоматически, даже если блок `tls` опущен. |
| `https` | Работает | `443` | `server`, `server_port`, `tls`, `path`, `method`, `headers` | DNS over HTTPS (DoH, HTTP/2 с пулом соединений). `path` по умолчанию `"/dns-query"`. |
| `quic` | Работает | `853` | `server`, `server_port`, `tls` | DNS over QUIC (DoQ, RFC 9250, ALPN `doq`). |
| `h3` | Работает | `443` | `server`, `server_port`, `tls`, `path`, `method`, `headers` | DNS over HTTP/3 (DoH поверх QUIC, ALPN `h3`). Требует `server` / `tls.server_name` либо `tls.insecure: true`. |
| `hosts` | Работает | — | `path`, `predefined` | Статическое разрешение из файлов hosts и встроенной таблицы `predefined`. |
| `fakeip` | Работает | — | `inet4_range`, `inet6_range` | Выдача виртуальных IP-адресов из выделенных CIDR-пулов с обратным отображением. |
| `local` | Работает | — | `prefer_go`, `neighbor_domain` | Системный резолвер ОС + опциональные ответы по локальным таблицам соседей (`route.find_neighbor`). |
| `dhcp` | Работает | — | `prefer_go`, `neighbor_domain`, `interface` | Использование DNS-серверов, полученных по DHCP (опционально с указанием интерфейса). |
| `mdns` | Работает | — | `prefer_go`, `neighbor_domain`, `interface` | Multicast DNS (RFC 6762, таймаут 1 с) на выбранных или всех сетевых интерфейсах. |
| `resolved` | Работает (только Linux) | `53` | `service`, `accept_default_resolvers` | Локальный stub-резолвер `systemd-resolved` (вне Linux отклоняется на этапе `check`). |
| `tailscale` | Работает | — | `endpoint`, `accept_default_resolvers`, `accept_search_domain` | MagicDNS и split DNS подключённого `tailscale`-эндпоинта. |
| `group` | Работает | — | `servers`, `mode`, `error_ttl`, `win_ttl`, `hosts` | Группа отказоустойчивости и балансировки поверх нескольких DNS-серверов. |
| `openvpn` | Только `check` | — | `endpoint`, `accept_default_resolvers`, `accept_search_domain` | Валидируется схемой (требует непустой `endpoint`); при `run` в v0.6.2 возвращает ошибку неподдерживаемого транспорта. |
| `openconnect` | Только `check` | — | `endpoint`, `accept_default_resolvers`, `accept_search_domain` | Валидируется схемой (требует непустой `endpoint`); при `run` в v0.6.2 возвращает ошибку неподдерживаемого транспорта. |

Примечание: отдельного типа сервера `rcode` не существует — синтетические ответы (`NXDOMAIN`, `REFUSED`, `NOERROR`, подмена записей `A`/`AAAA` и т. д.) настраиваются через правила `dns.rules[]` с `"action": "predefined"` или `"action": "reject"`.

---

### Детали специализированных DNS-серверов

#### `hosts`

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `path` | `Listable<string>` | `/etc/hosts` (Unix) или `C:\Windows\System32\drivers\etc\hosts` (Windows) | Путь или список путей к файлам в формате hosts (перечитываются при изменении mtime/размера не чаще раза в 5 с). |
| `predefined` | `object` | `{}` | Словарь `{"domain": "IP" | ["IP1", "IP2"]}`. Имеет приоритет над файлами из `path`. |

#### `fakeip`

Должен быть задан хотя бы один из диапазонов (`inet4_range` или `inet6_range`). Не может выступать сервером по умолчанию (`dns.final` или первым сервером при отсутствии `final`). При включённой опции `experimental.cache_file.store_fakeip` отображения сохраняются между перезапусками в сайдкаре `.volatile`.

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `inet4_range` | `CIDR` | — | IPv4 CIDR-пул для выдачи FakeIP, длина префикса `/0`..`/30` (типично `"198.18.0.0/15"`). |
| `inet6_range` | `CIDR` | — | IPv6 CIDR-пул для выдачи FakeIP, длина префикса `/0`..`/125` (типично `"fc00::/18"`). |

#### `local`, `dhcp`, `mdns`

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `prefer_go` | `bool` | `false` | Поле совместимости схемы. |
| `neighbor_domain` | `Listable<string>` | `[]` | Суффиксы доменов для локальных хостов из таблицы соседей (каждая запись **обязана** начинаться с точки, например `".lan"`). |
| `interface` | `Listable<string>` | — | Имя или список сетевых интерфейсов (для `dhcp` и `mdns`). |

#### `tailscale` / `resolved`

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `endpoint` | `string` | *(обязательно для `tailscale`)* | Тег `endpoints[]` типа `tailscale`. |
| `service` | `string` | — | Имя сервиса `resolved` (только для `type: "resolved"`). |
| `accept_default_resolvers` | `bool` | `false` | Разрешает fallback на резолверы по умолчанию, переданные из tailnet / systemd-resolved. |
| `accept_search_domain` | `bool` | `false` | Принимать поисковые домены tailnet (для `tailscale`). |

#### `group`

Объединяет несколько DNS-серверов за одним тегом с отслеживанием ошибок и побед.

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `servers` | `Listable<string>` | *(обязательно)* | Непустой список уникальных тегов серверов-участников (группа не может ссылаться на себя). |
| `mode` | `string` | `"stable"` | Режим работы: `"stable"` (удержание рабочего сервера с переключением при ошибке), `"fastest"` (выборы самого быстрого сервера на период `win_ttl`), `"parallel"` (параллельный опрос с возвратом первого успешного ответа). |
| `error_ttl` | `Duration` | `"2m"` | Время жизни записи об ошибке участника (таймаут, сетевая ошибка, `SERVFAIL`). |
| `win_ttl` | `Duration` | `"5m"` | Время удержания победителя в режиме `"fastest"` (в других режимах игнорируется с предупреждением). |
| `hosts` | `Listable<string> \| object` | — | Локальные переопределения, проверяемые до сетевых участников: либо словарь `{"domain": "IP" | ["IP1", ...]}`, либо тег(и) DNS-серверов типа `hosts` (нельзя ссылаться на саму группу). |

---

## Правила DNS (`dns.rules[]`)

Правила проверяются сверху вниз до первого срабатывания терминального действия (`route`, `reject`, `respond`, `predefined`). Действия `route-options` и `evaluate` изменяют контекст и продолжают проход по следующим правилам.

### Условия сопоставления (матчеры `dns.rules[]`)

Внутри одного правила все заданные условия объединяются по логическому **И** (AND), а элементы внутри одного списка — по логическому **ИЛИ** (OR).

| Поле | Тип | Описание |
|---|---|---|
| `type` | `string` | `""` / `"default"` (обычное правило) или `"logical"` (составное правило с `mode: "and" | "or"` и массивом `rules`). |
| `mode` | `string` | Для `type: "logical"`: `"and"` или `"or"`. |
| `rules` | `array<object>` | Для `type: "logical"`: вложенные правила-условия. |
| `invert` | `bool` | Инвертирует результат проверки условий правила. |
| `inbound` | `Listable<string>` | Тег входящего подключения (например, `"tun-in"`). |
| `network` | `Listable<string>` | Транспорт запроса (`"udp"`, `"tcp"`). |
| `query_type` | `Listable<string \| uint16>` | Тип DNS-записи: имя (`"A"`, `"AAAA"`, `"HTTPS"`, `"SVCB"`, `"TXT"`, `"MX"`, `"PTR"`, `"CNAME"`, `"SRV"` и др.) или числовой код `0..65535`. |
| `domain` | `Listable<string>` | Точное совпадение доменного имени (без учёта регистра). |
| `domain_suffix` | `Listable<string>` | Совпадение домена или любого его поддомена. |
| `domain_keyword` | `Listable<string>` | Наличие подстроки в имени домена. |
| `domain_regex` | `Listable<string>` | Регулярное выражение (синтаксис RE2). Компилируется и проверяется на этапе `check`. |
| `rule_set` | `Listable<string>` | Тег(и) наборов правил из `route.rule_set`. |
| `ip_cidr` | `Listable<CIDR>` | Совпадение IP-адреса в DNS-ответе (применяется после `evaluate` или при `match_response: true`). |
| `ip_is_private` | `bool` | Приватный/служебный IP в ответе. |
| `ip_accept_any` | `bool` | Совпадает при наличии любого IP-ответа. |
| `match_response` | `bool \| string` | Переключает правило на сопоставление с уже полученным ответом (от `evaluate`). |
| `source_ip_cidr` | `Listable<CIDR>` | Исходный IP/CIDR клиента. |
| `source_ip_is_private` | `bool` | Исходный IP клиента принадлежит приватной сети. |
| `source_mac_address` | `Listable<string>` | MAC-адрес клиента (требует `route.find_neighbor`). |
| `source_hostname` | `Listable<string>` | DHCP-имя хоста клиента (требует `route.find_neighbor`). |
| `time_window` | `Listable<string>` | Расписание активности правила (формат `[дни] HH:MM-HH:MM [часовой_пояс]`, подробно в [route-and-rulesets.md](route-and-rulesets.md#формат-time_window)). |
| `preferred_by` | `Listable<string>` | Тег(и) серверов/эндпоинтов, предпочитающих домен (например, `tailscale` с `accept_default_resolvers` или `hosts`). |
| `dns_server_address` | `Listable<CIDR> \| object` | Сопоставление по адресу DNS-сервера (`"1.1.1.1/32"` или `{"tag": ["100.100.100.100"]}`). |
| `dns_search_domain` | `Listable<string> \| object` | Сопоставление по поисковому домену DNS (`["corp.local"]` или `{"tag": "ts.net"}`). |
| `clash_mode` | `Listable<string>` | Текущий режим Clash (`"rule"`, `"global"`, `"direct"`). |
| `auth_user`, `outbound`, `ip_version`, `port`, `port_range`, `source_port`, `source_port_range`, `protocol`, `process_name`, `process_path`, `process_path_regex`, `package_name`, `package_name_regex`, `user`, `user_id`, `interface_address`, `network_interface_address`, `default_interface_address`, `network_type`, `network_is_expensive`, `network_is_constrained`, `wifi_ssid`, `wifi_bssid`, `query_client_subnet`, `query_dnssec`, `rule_set_ip_cidr_accept_empty`, `rule_set_ip_cidr_match_source`, `rule_set_ipcidr_match_source`, `speculative`, `geoip`, `geosite`, `source_geoip` | — | Дополнительные поля, допустимые схемой валидации DNS-правил для совместимости профилей. |

### Действия правил (`dns.rules[].action`)

| `action` | Обязательные и опциональные поля | Описание |
|---|---|---|
| `route` *(по умолчанию, если `action` не задан)* | `server` *(обязательно)*, `strategy`, `disable_cache`, `disable_optimistic_cache`, `rewrite_ttl`, `client_subnet`, `remove_client_subnet` | Направляет запрос на указанный DNS-сервер `server` и возвращает результат клиенту. |
| `route-options` | `strategy`, `disable_cache`, `disable_optimistic_cache`, `rewrite_ttl`, `client_subnet`, `remove_client_subnet` | Применяет модификаторы разрешения (`rewrite_ttl`, `disable_cache`, `strategy`, ECS) и продолжает проход по последующим правилам. |
| `evaluate` | `server` *(обязательно)*, `strategy`, `disable_cache`, `rewrite_ttl`, `client_subnet`, `remove_client_subnet` | Выполняет запрос через `server`, сохраняет полученный ответ в контексте и продолжает проход правил (для проверки ответа правилами с `ip_cidr` / `match_response`). |
| `respond` | — | Возвращает клиенту ответ, полученный на предыдущем шаге `evaluate`. |
| `reject` | `method` (`"default"` -> `REFUSED`, `"drop"` -> молчаливый сброс; `"reply"` в DNS-правилах запрещён), `no_drop` | Отклоняет DNS-запрос. |
| `predefined` | `rcode` / `response_rcode` (`NOERROR`, `SUCCESS`, `FORMERR`, `SERVFAIL`, `NXDOMAIN`, `NAMEERROR`, `NOTIMP`, `REFUSED`, `YXDOMAIN`, `YXRRSET`, `NXRRSET`, `NOTAUTH`, `NOTZONE` или `0..255`), `answer` / `response_answer`, `ns` / `response_ns`, `extra` / `response_extra` | Возвращает синтетический DNS-ответ без обращения к сети. Записи задаются строками в формате зоны (`"*. 60 IN A 0.0.0.0"`), base64 wire-формата либо объектами `{"name": "...", "ttl": 60, "value": "0.0.0.0"}`. |

Поля модификации ответа и ECS в `route` / `route-options` / `evaluate`:
- `rewrite_ttl` (`uint32`): перезаписывает TTL всех записей ответа (в секундах).
- `disable_cache` (`bool`): не читать и не записывать данный ответ в кэш.
- `client_subnet` (`IP | CIDR`): переопределяет EDNS0 Client Subnet для данного запроса.
- `remove_client_subnet` (`bool`): удаляет опцию EDNS0 Client Subnet из исходящего запроса.

---

## Пример конфигурации секции `dns`

```json
{
  "dns": {
    "servers": [
      {
        "tag": "dns-local",
        "type": "udp",
        "server": "192.168.1.1",
        "server_port": 53
      },
      {
        "tag": "dns-cf",
        "type": "https",
        "server": "1.1.1.1",
        "server_port": 443,
        "path": "/dns-query",
        "detour": "proxy-out"
      },
      {
        "tag": "dns-quad9",
        "type": "tls",
        "server": "9.9.9.9",
        "server_port": 853,
        "tls": {
          "enabled": true,
          "server_name": "dns.quad9.net"
        },
        "detour": "proxy-out"
      },
      {
        "tag": "dns-remote",
        "type": "group",
        "servers": ["dns-cf", "dns-quad9"],
        "mode": "fastest",
        "error_ttl": "2m",
        "win_ttl": "5m",
        "hosts": {
          "router.local": "192.168.1.1"
        }
      },
      {
        "tag": "dns-fakeip",
        "type": "fakeip",
        "inet4_range": "198.18.0.0/15",
        "inet6_range": "fc00::/18"
      }
    ],
    "rules": [
      {
        "domain_suffix": [".local", ".lan"],
        "action": "route",
        "server": "dns-local"
      },
      {
        "query_type": ["HTTPS", "SVCB"],
        "domain_suffix": ["ads.example.net"],
        "action": "predefined",
        "rcode": "NOERROR"
      },
      {
        "domain_suffix": ["tracker.example.org"],
        "time_window": "mon-fri 09:00-18:00 +03:00",
        "action": "reject",
        "method": "default"
      },
      {
        "query_type": ["A", "AAAA"],
        "inbound": ["tun-in"],
        "action": "route",
        "server": "dns-fakeip",
        "rewrite_ttl": 1
      }
    ],
    "final": "dns-remote",
    "strategy": "prefer_ipv4",
    "reverse_mapping": true,
    "optimistic": {
      "enabled": true,
      "timeout": "72h"
    },
    "serve_stale": true,
    "fastest_ip": {
      "enabled": true,
      "timeout": "200ms",
      "port": 443
    }
  }
}
```
