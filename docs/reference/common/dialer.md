# Поля диалера (аутбаунды)

Общий набор для всех аутбаундов, которым нужно соединение с сервером.
`tproxy`, `redirect`, `tun`, `block`, `selector`, `urltest`, `chain` и
`bridge` эти поля не используют.

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `detour` | string | — | Тег аутбаунда, через который устанавливать соединение с целевым сервером. Основа цепочек. |
| `bind_interface` | string | — | Интерфейс для исходящих соединений. |
| `inet4_bind_address` | string | — | Локальный IPv4-адрес для исходящих соединений. |
| `inet6_bind_address` | string | — | Локальный IPv6-адрес для исходящих соединений. |
| `bind_address_no_port` | boolean | — | Не назначать порт при привязке к адресу. |
| `routing_mark` | uint32 | — | Метка маршрутизации (SO_MARK). |
| `reuse_addr` | boolean | — | SO_REUSEADDR на исходящем сокете. |
| `netns` | string | — | Сетевое пространство имён для исходящих соединений. |
| `protect_path` | string | — | Путь к unix-сокету службы, передающей дескрипторы сокетов через `SCM_RIGHTS`. |
| `connect_timeout` | string | — | Таймаут установления соединения, вида `30s`. |
| `domain_resolver` | string | — | Тег DNS-сервера для разрешения имени целевого сервера. |
| `domain_strategy` | string | — | Стратегия разрешения: `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only`. Пусто — системный резолвер. |
| `network_strategy` | string | — | Стратегия выбора сети: `default`, `hybrid`, `fallback`. |
| `network_type` | string | — | Тип сети: `wifi`, `cellular`, `ethernet`, `other`. |
| `fallback_network_type` | string | — | Запасной тип сети для стратегии `fallback`. |
| `fallback_delay` | string | — | Задержка перед переключением на запасную сеть. |
| `tcp_fast_open` | boolean | — | TCP Fast Open на исходящем сокете. |
| `tcp_multi_path` | boolean | — | Multipath TCP. |
| `tcp_keep_alive` | boolean | — | TCP keep-alive. |
| `disable_tcp_keep_alive` | boolean | — | Отключить TCP keep-alive. |
| `tcp_keep_alive_interval` | string | — | Интервал keep-alive, вида `45s`. |
| `udp_fragment` | boolean | — | Фрагментировать большие UDP-пакеты. |

## Поля маршрутизации без реализации

`route.default_network_strategy`, `route.default_network_type`,
`route.default_fallback_network_type`, `route.default_fallback_delay`,
`route.geoip`, `route.geosite`, `route.override_android_vpn` проходят проверку
конфига, но рантайм печатает `route.<поле> is not implemented yet (ignored)` и
продолжает работу (`crates/core-runtime/src/route/mod.rs:450`).

## Сетевые пространства имён

`netns` работает через дочерний процесс-держатель `CLONE_NEWNET`: ядро создаёт
пространство имён, держит его живым, пока работает, и диалит внутри без
конфликтов с обычной сетевой подсистемой.
