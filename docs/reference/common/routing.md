# Маршрутизация, sniff и правила

## Унаследованные поля инбаундов

Эти поля доступны инбаундам `mixed`, `socks`, `http`, `tproxy`, `redirect`
и `direct` и соответствуют секции `route` верхнего уровня.

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `sniff` | boolean | — | Определять домен из TLS SNI, HTTP Host и QUIC SNI. |
| `sniff_override_destination` | boolean | — | Подменять адрес назначения найденным доменом. |
| `sniff_timeout` | string | — | Таймаут сниффинга. |
| `domain_strategy` | string | — | Стратегия разрешения имён. |
| `udp_disable_domain_unmapping` | boolean | — | Не отображать домен обратно в адрес. |

Сниффер буферизирует начало потока и разбирает TLS SNI, HTTP Host, QUIC SNI,
DNS, BitTorrent, SSH и RDP, не теряя первых байтов.

## Правила маршрутизации

Секция `route.rules` — список объектов. Поддерживаемые действия: `route`,
`route-options`, `bypass`, `hijack-dns`, `direct`, `sniff`, `reject`,
`resolve`.

Условия правила: `inbound`, `network`, `protocol`, `domain`, `domain_suffix`,
`domain_keyword`, `domain_regex`, `ip_cidr`, `ip_is_private`, `source_ip_cidr`,
`source_ip_is_private`, `source_port`, `source_port_range`, `port`,
`port_range`, `process_name`, `process_path`, `process_path_regex`,
`package_name`, `package_name_regex`, `user`, `user_id`, `clash_mode`,
`network_type`, `network_is_expensive`, `network_is_constrained`, `wifi_ssid`,
`wifi_bssid`, `rule_set`, `rule_set_ip_cidr_match_source`, `source_mac_address`,
`source_hostname`, `mode`, `method`, `strategy`, `client`, `preferred_by`,
`no_drop`, `timeout`, `sniffer`.

`source_mac_address` и `source_hostname` работают через таблицу соседей и
файлы аренды DHCP (`find_neighbor`). Идентификация процессов — через
`/proc/net/*` и дескрипторы сокетов.

## Бинарные правила

Секция `route.rule_set` принимает три вида:

```json
{ "type": "inline", "tag": "local", "rules": [] }
{ "type": "local",  "tag": "file",  "path": "/etc/tachyon/rules.srs" }
{ "type": "remote", "tag": "net",  "url": "https://...", "update_interval": "24h", "download_detour": "proxy" }
```

Формат — SRS v5, компилируется и декомпилируется командой `rule-set`.
