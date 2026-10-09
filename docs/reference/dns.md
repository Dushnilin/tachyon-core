# DNS

Секция `dns` верхнего уровня. Резолверы задаются в `dns.servers`, правила —
в `dns.rules`, поведение по умолчанию — в `dns.final`.

## Поля секции

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `servers` | array | — | Список резолверов. |
| `rules` | array | — | Правила перехвата запросов. |
| `final` | string | — | Резолвер для запросов, не попавших ни под одно правило. |
| `strategy` | string | — | Стратегия разрешения: `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only`. |
| `reverse_mapping` | boolean | — | Сопоставлять `IP → домен` с хранением в течение TTL. |
| `client_subnet` | string | — | Подсеть клиента для пробы EDNS0. |
| `independent_cache` | string | — | Зависимость кэша от маршрута: `route` или `client`. |
| `cache_capacity` | uint32 | — | Ёмкость LRU-кэша. |
| `disable_cache` | boolean | — | Отключить кэширование. |
| `disable_expire` | boolean | — | Отключить устаревание записей. |
| `optimistic` | boolean | — | Отдавать устаревшую запись, пока обновляется свежая. |
| `timeout` | string | — | Таймаут разрешения, вида `10s`. |

## Типы резолверов

Общие для всех тиров поля: `type`, `tag` и блок диалера — [dialer](common/dialer.md).

| Тип | Собственные поля |
|---|---|
| `udp` | `server`, `server_port` |
| `tcp` | `server`, `server_port` |
| `tls` (DoT) | `server`, `server_port`, `tls` |
| `quic` (DoQ) | `server`, `server_port`, `tls` |
| `https` (DoH) | `server`, `server_port`, `tls`, `path`, `method`, `headers` |
| `h3` (DoH3) | `server`, `server_port`, `tls`, `path`, `method`, `headers` |
| `hosts` | `path`, `predefined` |
| `fakeip` | `inet4_range`, `inet6_range` |
| `local` | `prefer_go`, `neighbor_domain` |
| `dhcp` | `prefer_go`, `neighbor_domain`, `interface` |
| `mdns` | `prefer_go`, `neighbor_domain`, `interface` |
| `resolved` | `service`, `accept_default_resolvers` |
| `tailscale` | `endpoint`, `accept_default_resolvers`, `accept_search_domain` |
| `openvpn` | `endpoint`, `accept_default_resolvers`, `accept_search_domain` |
| `openconnect` | `endpoint`, `accept_default_resolvers`, `accept_search_domain` |
| `group` | `servers`, `mode`, `error_ttl`, `win_ttl` |

Блок `tls` у резолверов — [tls-client](common/tls-client.md).

### fakeip

```json
{
  "type": "fakeip",
  "tag": "fakeip",
  "inet4_range": "198.18.0.0/15",
  "inet6_range": "fc00::/18"
}
```

Выдаёт синтетические адреса из пула и хранит соответствие в `cache.db`.
`store_fakeip` в `experimental.cache_file` включает сохранение между
перезапусками.

### hosts

```json
{
  "type": "hosts",
  "tag": "hosts",
  "path": "/etc/hosts",
  "predefined": { "router.lan": ["192.168.1.1"] }
}
```

### group

```json
{
  "type": "group",
  "tag": "dns-group",
  "servers": ["remote", "local"],
  "mode": "fastest",
  "error_ttl": "30s",
  "win_ttl": "10s"
}
```

Стратегии групп: `stable`, `fastest`, `parallel`. Выбор идёт по скользящей
статистике побед и ошибок, есть аварийный режим выживания.

## Правила DNS

Поддерживаемые условия: `inbound`, `question_type`, `domain`, `domain_suffix`,
`domain_keyword`, `domain_regex`, `ip_cidr`, `source_ip_cidr`, `auth_user`,
`clash_mode`, `network`, `port`, `port_range`, `process_name`, `process_path`,
`package_name`, `rule_set`, `user`, `user_id`, `wifi_ssid`, `wifi_bssid`,
`network_type`, `network_is_expensive`, `network_is_constrained`, `outbound`,
`server`, `disable_cache`, `disable_optimistic_cache`, `rewrite_ttl`,
`client_subnet`, `query_client_subnet`, `query_dnssec`, `remove_client_subnet`,
`answer`, `extra`, `ns`, `rcode`, `speculative`, `invert`, `mode`, `network_list`.

Действия: перенаправление на другой резолвер, отказ (`rcode`), подстановка
ответа (`answer`), перезапись TTL, изменение поведения кэша.

## Перехват DNS

Чтобы весь DNS клиентов попадал в ядро, в `route.rules` добавляют:

```json
{ "action": "hijack-dns", "port": 53 }
```

Для прозрачного режима на роутере это основной способ перехвата запросов.
