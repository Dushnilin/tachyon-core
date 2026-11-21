# Исходящие подключения (`outbounds`)

Секция `outbounds` корневой конфигурации `tachyon-core` (v0.6.2) задаёт список исходящих обработчиков трафика: прямых подключений, прокси-клиентов, туннелей, групп балансировки и механизма пакетной десинхронизации.

Каждый элемент массива `outbounds` представляет собой JSON-объект с обязательным полем `type` и, как правило, уникальным строковым идентификатором `tag`, на который ссылаются правила маршрутизации (`route.rules`), группы (`selector`, `urltest`, `chain`), параметры `detour` и контроллер Clash API. Если правило не задаёт `outbound` явно, используется `route.final`, а при его отсутствии — первый элемент `outbounds`.

Общие переиспользуемые блоки, встроенные во многие типы аутбаундов (`dialer`, `tls`, `transport`, `multiplex`, `udp_over_tcp`), описаны отдельно в [Общих объектах конфигурации](../common-objects.md). Сетевые туннели уровня L3 (`wireguard`, `openvpn-client`, `tailscale`) конфигурируются в секции `endpoints` ([Конечные точки (`endpoints`)](../endpoints.md)), но после запуска регистрируются в маршрутизаторе по своему `tag` и могут использоваться в правилах и группах наравне с `outbounds`.

## Разделы справочника

- [Базовые аутбаунды и группы балансировки](core-and-groups.md) — `direct`, `block`, `dns` (удалён), `socks`, `http`, `selector`, `urltest` (12 режимов балансировки), `chain`, `bridge`.
- [Прокси-протоколы](proxy-protocols.md) — `vless`, `vmess`, `trojan`, `shadowsocks`, `anytls`, `shadowtls`, `naive`, `snell`, `ssh`, `tor`, `sudoku`.
- [QUIC и туннельные протоколы](quic-and-tunnels.md) — `hysteria2`, `hysteria`, `tuic`, `masque`, `mieru`, `tewfai`, `fptn`, `mtproto`, `openconnect`, `trusttunnel`, `wdtt`, а также связь с `wireguard`, `openvpn-client` и `tailscale` из секции `endpoints`.
- [Нативная десинхронизация (`desync`)](desync.md) — спецификация полей, пресетов, режимов, сегментации TCP/UDP и адаптивного механизма.

## Сводная таблица всех типов `outbounds`

Обозначения в таблице:
- **Да** — поддерживается и активно в runtime;
- **Обяз.** — требуется (`tls.enabled: true`);
- **Нет** — не поддерживается данным типом;
- **Схема** — принимается командой `tachyon-core check` для совместимости конфигурации, но не реализован в runtime;
- **Удалён** — тип зарезервирован в валидаторе и отклоняется с рекомендацией актуальной замены.

| Тип (`type`) | Статус | TCP | UDP | TLS | Transport | Mux | UoT | Раздел |
|---|---|---|---|---|---|---|---|---|
| `direct` | Активен | Да | Да | Нет | Нет | Нет | Нет | [Базовые и группы](core-and-groups.md#direct) |
| `block` | Активен | Да (отказ) | Да (отказ) | Нет | Нет | Нет | Нет | [Базовые и группы](core-and-groups.md#block) |
| `dns` | Удалён | — | — | — | — | — | — | [Базовые и группы](core-and-groups.md#dns) |
| `socks` | Активен | Да | Да (SOCKS5 / UoT) | Нет | Нет | Нет | Да | [Базовые и группы](core-and-groups.md#socks) |
| `http` | Активен | Да | Нет | Опц. | Нет | Нет | Нет | [Базовые и группы](core-and-groups.md#http) |
| `selector` | Активен | По участнику | По участнику | — | — | — | — | [Базовые и группы](core-and-groups.md#selector) |
| `urltest` | Активен | По участнику | По участнику | — | — | — | — | [Базовые и группы](core-and-groups.md#urltest) |
| `chain` | Активен | По цепочке | По цепочке | — | — | — | — | [Базовые и группы](core-and-groups.md#chain) |
| `bridge` | Схема | — | — | Нет | Нет | Нет | Нет | [Базовые и группы](core-and-groups.md#bridge) |
| `vless` | Активен | Да | Да (`xudp` / `packetaddr` / raw) | Опц. (вкл. REALITY/uTLS) | Да (вкл. `xhttp`) | Да | Нет | [Прокси-протоколы](proxy-protocols.md#vless) |
| `vmess` | Активен | Да | Да (chunk / `xudp` / `packetaddr`) | Опц. | Да (вкл. `xhttp`) | Да | Нет | [Прокси-протоколы](proxy-protocols.md#vmess) |
| `trojan` | Активен | Да | Да | Опц. | Да (вкл. `xhttp`) | Да | Нет | [Прокси-протоколы](proxy-protocols.md#trojan) |
| `shadowsocks` | Активен | Да | Да (нативный / UoT) | Опц. | Нет | Да | Да | [Прокси-протоколы](proxy-protocols.md#shadowsocks) |
| `anytls` | Активен | Да | Да (через встроенный UoT) | Обяз. | Нет | Встроенный пул | Встроенный | [Прокси-протоколы](proxy-protocols.md#anytls) |
| `shadowtls` | Активен (v2/v3) | Да | Да (туннель поверх TCP) | Обяз. | Нет | Нет | Нет | [Прокси-протоколы](proxy-protocols.md#shadowtls) |
| `naive` | Активен (H2/H3) | Да | Да (только при UoT) | Обяз. | Нет | Встроенный (H2/H3) | Да | [Прокси-протоколы](proxy-protocols.md#naive) |
| `snell` | Активен (v4/v5/v6) | Да | Да | Нет (свой слой) | Нет | Пул (`reuse`) | Схема (v4/v5) | [Прокси-протоколы](proxy-protocols.md#snell) |
| `ssh` | Схема | — | — | Нет | Нет | Нет | Нет | [Прокси-протоколы](proxy-protocols.md#ssh) |
| `tor` | Схема | — | — | Нет | Нет | Нет | Нет | [Прокси-протоколы](proxy-protocols.md#tor) |
| `sudoku` | Схема | — | — | — | — | — | — | [Прокси-протоколы](proxy-protocols.md#sudoku) |
| `hysteria2` | Активен | Да | Да (QUIC datagram) | Обяз. | Нет (QUIC/H3) | Встроенный (QUIC) | Нет | [QUIC и туннели](quic-and-tunnels.md#hysteria2) |
| `hysteria` | Схема | — | — | Обяз. | Нет (QUIC) | — | Нет | [QUIC и туннели](quic-and-tunnels.md#hysteria) |
| `tuic` | Активен (v5) | Да | Да (`native` / `quic` / `udp_over_stream`) | Обяз. | Нет (QUIC) | Встроенный (QUIC) | Через `udp_over_stream` | [QUIC и туннели](quic-and-tunnels.md#tuic) |
| `masque` | Активен | Да | Да (IP-туннель) | Опц. / профиль | Нет (H3/H2) | Встроенный | Нет | [QUIC и туннели](quic-and-tunnels.md#masque) |
| `mieru` | Активен (v3) | Да | Да | Нет (свой шифр) | TCP / UDP | Схема | Нет | [QUIC и туннели](quic-and-tunnels.md#mieru) |
| `tewfai` | Активен | Да | Да | Опц. (вкл. REALITY) | TCP / QUIC | Встроенный | Нет | [QUIC и туннели](quic-and-tunnels.md#tewfai) |
| `fptn` | Активен | Да | Да (IP-туннель) | Встроенный | WebSocket | Встроенный | Нет | [QUIC и туннели](quic-and-tunnels.md#fptn) |
| `mtproto` | Активен | Да | Нет | Опц. (авто для `telegram-ws`) | Свой фрейминг / WS | Нет | Нет | [QUIC и туннели](quic-and-tunnels.md#mtproto) |
| `openconnect` | Активен | Да | Да (при `ip: true` / `esp` / `dtls`) | Обяз. | CSTP / DTLS / ESP | Встроенный | Нет | [QUIC и туннели](quic-and-tunnels.md#openconnect) |
| `trusttunnel` | Активен | Да | Да (плюс ICMP) | Обяз. | Нет (H2/H3) | Встроенный (H2/H3) | Нет | [QUIC и туннели](quic-and-tunnels.md#trusttunnel) |
| `wdtt` | Активен | Да | Да (IP-туннель) | DTLS/SRTP/TURN | TURN / WebRTC | Встроенный | Нет | [QUIC и туннели](quic-and-tunnels.md#wdtt) |
| `wireguard` | Удалён (в `outbounds`) | — | — | — | — | — | — | [QUIC и туннели](quic-and-tunnels.md#wireguard-endpoints) |
| `desync` | Активен | Да | Да | Нет | Нет | Нет | Нет | [Десинхронизация (`desync`)](desync.md) |

## Маршрутизируемые типы из секции `endpoints`

Следующие туннельные протоколы описываются в корневом массиве `endpoints`, но регистрируются в таблице маршрутизации как полноценные исходящие теги (поддерживают TCP и UDP и могут указываться в `route.rules`, `selector`, `urltest`, `chain`, `detour`):

| Тип (`endpoints[].type`) | Статус в runtime | TCP | UDP | Подробное описание |
|---|---|---|---|---|
| `wireguard` | Активен (включая AmneziaWG 2.0/3.x) | Да | Да | [Конечные точки (`endpoints`)](../endpoints.md), [заметка о миграции](quic-and-tunnels.md#wireguard-endpoints) |
| `openvpn-client` | Активен (`mode: "static_key"`) | Да | Да | [Конечные точки (`endpoints`)](../endpoints.md), [сводка OpenVPN](quic-and-tunnels.md#openvpn-client) |
| `tailscale` | Активен (userspace mesh + DERP + exit node) | Да | Да | [Конечные точки (`endpoints`)](../endpoints.md), [сводка Tailscale](quic-and-tunnels.md#tailscale) |
| `openconnect` | Схема (в `endpoints`); для работы используйте `outbounds[].type = "openconnect"` | — | — | [OpenConnect](quic-and-tunnels.md#openconnect) |

## Общие поля и строгая валидация

1. **Строгая проверка ключей.** Любое неизвестное поле в объекте аутбаунда приводит к ошибке проверки конфигурации (`tachyon-core check`).
2. **Параметры подключения (`dialer`).** Все сетевые аутбаунды (кроме `block`, `selector`, `urltest`, `chain`, `bridge`) принимают плоские поля диалера: `detour`, `bind_interface`, `inet4_bind_address`, `inet6_bind_address`, `bind_address_no_port`, `protect_path`, `routing_mark`, `reuse_addr`, `netns`, `connect_timeout`, `tcp_fast_open`, `tcp_multi_path`, `disable_tcp_keep_alive`, `tcp_keep_alive`, `tcp_keep_alive_interval`, `udp_fragment`, `domain_resolver`, `network_strategy`, `network_type`, `fallback_network_type`, `fallback_delay`, `domain_strategy`, `tcp_profile`, `ip_ttl`, `tcp_mss`, `tcp_rcvbuf`, `preconnect`, `warm_pool`, `fragment`, `tcp_fragment`, `finalmask`. Полный справочник этих полей приведён в [Общих объектах конфигурации](../common-objects.md).
3. **Общие поля QUIC.** Аутбаунды `hysteria2`, `hysteria`, `tuic`, `trusttunnel` дополнительно принимают плоские параметры QUIC: `idle_timeout`, `keep_alive_period`, `stream_receive_window`, `connection_receive_window`, `max_concurrent_streams`, `initial_packet_size`, `disable_path_mtu_discovery`, `quic_migration`, `quic_rebind_interval`.
4. **Наследование `route.default_mark` и `route.default_interface`.** Если у аутбаунда не заданы собственные `routing_mark` или `bind_interface`, они автоматически наследуются из глобальных настроек секции `route`.
