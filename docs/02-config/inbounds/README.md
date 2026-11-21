# Входящие подключения (`inbounds`)

Секция `inbounds` в корне конфигурации `tachyon-core` (v0.6.2) задаёт массив входящих обработчиков, принимающих клиентский трафик (системные интерфейсы, прозрачный перехват, локальные прокси и серверные туннели) и передающих его в конвейер маршрутизации.

## Общая структура объекта `inbound`

Каждый элемент массива `inbounds` является JSON-объектом со следующими базовыми полями:

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | обязательное | Тип входящего обработчика (одно из 28 значений в таблице ниже). |
| `tag` | `string` | `""` | Уникальный идентификатор обработчика для правил маршрутизации (`route.rules[].inbound`), логов и статистики. Дубликаты непустых тегов отклоняются при проверке конфигурации. |

Все сетевые инбаунды (кроме `tun` и `cloudflared`) наследуют общие поля прослушивания (`listen`, `listen_port`, `ipv6_only`, `bind_interface`, `routing_mark`, `reuse_addr`, `netns`, `tcp_fast_open`, `tcp_multi_path`, `disable_tcp_keep_alive`, `tcp_keep_alive`, `tcp_keep_alive_interval`, `udp_fragment`, `udp_timeout`, `detour`, `proxy_protocol`, `proxy_protocol_accept_no_header`, `fullcone`, `udp_nat_mode`, `udp_fullcone_max_bindings`, `filter`, `ips_excluded`, `domains_excluded`). Полная спецификация общих объектов приведена в [common-objects.md](../common-objects.md).

> **Примечание об удалённых устаревших полях.** Поля `sniff`, `sniff_override_destination`, `sniff_timeout`, `domain_strategy` и `udp_disable_domain_unmapping` на уровне `inbounds[]` удалены и отклоняются валидатором при любом ненулевом значении. Для определения протокола и разрешения доменных имён используйте действия `sniff` и `resolve` в правилах `route.rules`.

> **Поведение IPv6 dual-stack.** При прослушивании на неопределённом IPv6-адресе (`::`) сокеты TCP и UDP по умолчанию открываются в режиме dual-stack (`IPV6_V6ONLY = 0`), принимая одновременно IPv4 и IPv6. Установка `"ipv6_only": true` ограничивает приём только IPv6.

## Сводная таблица всех типов инбаундов

В `tachyon-core` v0.6.2 валидатор конфигурации распознаёт 28 типов инбаундов: 25 из них полностью работают в рантайме, а 3 (`hysteria`, `cloudflared`, `sudoku`) распознаются только схемой валидации.

### Системные и клиентские инбаунды

Подробная спецификация: [system-and-transparent.md](system-and-transparent.md).

| Тип | Статус | TCP | UDP | TLS / REALITY | Transport | Mux | UoT | Назначение |
|---|---|---|---|---|---|---|---|---|
| `tun` | активен | да | да | нет | нет | нет | нет | Виртуальный L3-интерфейс (Linux `/dev/net/tun`, Windows Wintun, macOS `utun`, внешний `fd` для Android/iOS) на базе pure-Rust стека `smoltcp`. |
| `tproxy` | активен | да | да | нет | нет | нет | нет | Прозрачный перехват Linux (`IP_TRANSPARENT` / `IP_RECVORIGDSTADDR`) для IPv4 и IPv6. |
| `redirect` | активен | да | нет | нет | нет | нет | нет | Прозрачное перенаправление TCP на Linux (`SO_ORIGINAL_DST`, `iptables`/`nftables` REDIRECT). |
| `direct` | активен | да | да | нет | нет | нет | нет | Прямой приём сырого TCP/UDP с опциональной подменой адреса и порта назначения. |
| `mixed` | активен | да | да | TLS | нет | нет | нет | Комбинированный локальный прокси: SOCKS4/4a/5 (CONNECT + UDP ASSOCIATE) и HTTP/HTTPS на одном порту. |
| `socks` | активен | да | да | нет | нет | нет | нет | Прокси SOCKS4/4a/5 (TCP CONNECT и SOCKS5 UDP ASSOCIATE). |
| `http` | активен | да | нет | TLS | нет | нет | нет | HTTP/HTTPS прокси (метод `CONNECT` и обычное HTTP-проксирование). |

### Серверные прокси-протоколы

Подробная спецификация: [proxy-protocols.md](proxy-protocols.md).

| Тип | Статус | TCP | UDP | TLS / REALITY | Transport | Mux | UoT | Назначение |
|---|---|---|---|---|---|---|---|---|
| `vless` | активен | да | да | TLS / REALITY | `ws`, `httpupgrade`, `http`/`h2`, `grpc`, `xhttp` | `h2mux`, `XUDP` | да (v1/v2) | Сервер VLESS с поддержкой `xtls-rprx-vision`, постквантового `decryption` (`mlkem768x25519plus`), `fallback` и `tarpit`. |
| `vmess` | активен | да | да | TLS / REALITY | `ws`, `httpupgrade`, `http`/`h2`, `grpc`, `xhttp` | `h2mux` | да (v1/v2) | Сервер VMess AEAD с защитой от повторов (`±120s`). |
| `trojan` | активен | да | да | TLS / REALITY | `ws`, `httpupgrade`, `http`/`h2`, `grpc`, `xhttp` | `h2mux` | да (v1/v2) | Сервер Trojan (SHA-224), `fallback`, `fallback_for_alpn` и `tarpit`. |
| `shadowsocks` | активен | да | да | TLS | нет | `h2mux` | да (v1/v2) | Сервер Shadowsocks (2022-BLAKE3, AEAD и legacy-шифры): single-user, multi-user и relay (`destinations`). |
| `anytls` | активен | да | через UoT | TLS / REALITY | нет | встроенный | да (v1/v2) | Мультиплексируемый прокси-сервер AnyTLS поверх TLS с аутентификацией SHA-256. |
| `shadowtls` | активен | да | нет | внешний decoy | нет | нет | нет | Сервер ShadowTLS v2/v3 с проверкой HMAC-SHA1 и перенаправлением на внутренний обработчик через `detour`. |
| `naive` | активен | да | через UoT | TLS (обязателен) | HTTP/2, HTTP/3 (QUIC) | HTTP/2, HTTP/3 | да (v1/v2) | Сервер NaiveProxy (HTTP/2 CONNECT и HTTP/3 CONNECT с padding и Basic-аутентификацией). |
| `snell` | активен | да | да | нет | `http`/`tls` obfs (v5) | reuse (`CMD_CONNECT_V2`) | да (v1/v2) | Сервер Snell v5/v6 с поддержкой `CMD_CONNECT_V2` и `CMD_UDP`. |

### QUIC и туннельные инбаунды

Подробная спецификация: [tunnel-and-quic.md](tunnel-and-quic.md).

| Тип | Статус | TCP | UDP | TLS / REALITY | Transport | Mux | UoT | Назначение |
|---|---|---|---|---|---|---|---|---|
| `hysteria2` | активен | да | да | TLS (обязателен) | QUIC (`h3`) | QUIC | нет | Сервер Hysteria2 с управлением полосой, обфускацией Salamander и Gecko. |
| `tuic` | активен | да | да | TLS (обязателен) | QUIC | QUIC | нет | Сервер TUIC v5 с EKM-аутентификацией, UDP datagram и uni-stream режимами. |
| `masque` | активен | да | да | TLS (обязателен) | HTTP/3 QUIC (`h3`) | HTTP/3 | нет | Сервер MASQUE (RFC 9484 CONNECT-IP) с виртуальным стеком `smoltcp` и маршрутизацией UDP. |
| `mieru` | активен | да | да | нет | `tcp` или `udp` | встроенный | да (v1/v2) | Сервер Mieru v3 с поддержкой диапазонов портов (до 256 портов). |
| `tewfai` | активен | да | да | TLS / REALITY | `tcp`, `quic` (`h3`) | встроенный | да (v1/v2) | Мультиплексируемый сервер Tewfai с TCP/QUIC носителями, передачей сессий (`handover`), шейпером и FEC. |
| `fptn` | активен | да | да | TLS / RealityMode2 | WebSocket | пулинг `SessionID` | нет | Сервер FPTN (HTTP API + WebSocket с сериализацией YaFF/Protobuf и L3-терминацией). |
| `mtproto` | активен | да | нет | TLS | `abridged`, `intermediate`, `padded_intermediate`, `full` | нет | нет | Сервер MTProto с 16-байтными секретами и 4 вариантами фрейминга. |
| `openconnect` | активен | да | да (в режиме `ip`) | TLS | CSTP / SSL-VPN / ESP | нет | нет | Сервер OpenConnect с 6 диалектами (`anyconnect`, `gp`, `nc`, `pulse`, `f5`, `fortinet`), потоковым и IP-режимами. |
| `trusttunnel` | активен | да | да (`_udp2`) | TLS (обязателен для QUIC) | HTTP/2, HTTP/3 (QUIC) | HTTP/2, HTTP/3 | да (v1/v2) | Сервер TrustTunnel (HTTP/2 и HTTP/3 CONNECT, UDP-мультиплексор `_udp2`, health-check `_check`). |
| `wdtt` | активен | да (в L3) | да (в L3) | DTLS 1.2 + CID | UDP (RTP WRAP / SRTP) | многопутевые legs | нет | Нативный UDP-сервер WDTT / qWDTT / CSQTT (режимы `wg`, `raw`, `csqtt`, `csqtt_v1`, `all`). |
| `hysteria` | только схема | — | — | TLS (обязателен) | QUIC | — | — | Схема Hysteria v1 принимается `check`, но не реализована в рантайме (используйте `hysteria2`). |
| `cloudflared` | не включён в сборку | — | — | — | — | — | — | Схема проверяется, но отклоняется при `check` (поддержка не включена в сборку). |
| `sudoku` | только схема | — | — | — | — | — | — | Присутствует в списке известных типов валидатора, но серверная часть не реализована. |

## Серверные транспорты, мультиплексирование и UoT

### Поддерживаемые серверные транспорты (`transport`)

Для инбаундов `vless`, `vmess` и `trojan` поддерживаются следующие типы V2Ray-транспорта (подробности полей см. в [common-objects.md](../common-objects.md)):

- `ws` (WebSocket)
- `httpupgrade` (HTTP/1.1 Upgrade `101`)
- `http` / `h2` (HTTP/2)
- `grpc` (gRPC поверх HTTP/2; при включённом `tls` автоматически добавляется ALPN `h2`)
- `xhttp` (режимы `stream-one`, `stream-up`, `packet-up` поверх HTTP/1.1; при включённом `tls` согласуется ALPN `http/1.1`)

Транспорт `quic` на серверных инбаундах V2Ray не поддерживается и отклоняется на этапе проверки конфигурации.

### Мультиплексирование (`multiplex`)

- `h2mux` (`sp.mux.sing-box.arpa:444` или команда `0x7f`) поддерживается на серверных инбаундах `vless`, `vmess`, `trojan` и `shadowsocks` (с опциональным padding версии 0 и 1).
- Протоколы `smux` и `yamux` в секции `inbounds[].multiplex` отклоняются на этапе проверки конфигурации.
- На `vless` дополнительно поддерживается серверная терминация Xray Mux.Cool / XUDP (команда `0x03`, включая сочетание с `xtls-rprx-vision`).

### UDP over TCP (`UoT`)

Любой потоковый прокси-инбаунд, работающий через общий конвейер фреймированных соединений (`shadowsocks`, `naive`, `vless`, `vmess`, `trojan`, `anytls`, `snell`, `mieru`, `tewfai`, `trusttunnel`), автоматически перехватывает обращения к служебным адресам UoT без отдельной настройки:

- **UoT v1**: назначение `sp.udp-over-tcp.arpa` (каждая датаграмма несёт собственный адрес назначения).
- **UoT v2**: назначение `sp.v2.udp-over-tcp.arpa` (поддерживаются оба подрежима: `is_connect = 1` с фиксированным адресом из заголовка и `is_connect = 0` с адресом в каждой датаграмме).

### Горячее обновление пользователей (`reload_in_place`)

При перезагрузке конфигурации без разрыва активных соединений (`reload_in_place`) списки `users` обновляются динамически на следующих серверных инбаундах: `vless`, `vmess`, `trojan`, `anytls`, `hysteria2` и `tuic`. Соединения удалённых или изменённых пользователей завершаются при обновлении таблицы, остальные продолжают работу без пересоздания сокета.

## Навигация по разделам

- [Общие переиспользуемые объекты (`listen`, `tls`, `transport`, `multiplex`, `users`)](../common-objects.md)
- [Системные и клиентские инбаунды (`tun`, `tproxy`, `redirect`, `direct`, `mixed`, `socks`, `http`)](system-and-transparent.md)
- [Серверные прокси-инбаунды (`vless`, `vmess`, `trojan`, `shadowsocks`, `anytls`, `shadowtls`, `naive`, `snell`)](proxy-protocols.md)
- [QUIC и туннельные инбаунды (`hysteria2`, `tuic`, `masque`, `mieru`, `tewfai`, `fptn`, `mtproto`, `openconnect`, `trusttunnel`, `wdtt`, `hysteria`, `cloudflared`, `sudoku`)](tunnel-and-quic.md)
