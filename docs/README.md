# Документация tachyon-core

Полная техническая документация сетевого ядра `tachyon-core` (`v0.6.2`): архитектура, справочник схемы конфигурации JSON, спецификации протоколов и форматов, CLI и REST/WebSocket API, руководства по интеграции на всех целевых платформах и проверенные примеры конфигураций.

## Карта документации

### 1. Архитектура

- [Обзор архитектуры](01-architecture/overview.md) — состав компонентов, конвейер обработки соединений, жизненный цикл экземпляра, горячая перезагрузка без разрыва и модель потоков.
- [Криптография и TLS](01-architecture/crypto-and-tls.md) — криптостек на чистом Rust без C/CGO, динамический выбор инструкций CPU (`VAES`/`AVX2`/`AES-NI`/`SSE2`, `ARMv8`/`NEON`, soft-float), ускорение через `AF_ALG`, TLS 1.3, профили uTLS, REALITY (X25519 и постквантовый `X25519MLKEM768`), ECH и QUIC.
- [Память и аппаратная адаптация](01-architecture/memory-and-hardware.md) — автоматическое масштабирование под профили ОЗУ (16–32 MiB MIPS/ARMv6, 50 MiB iOS Jetsam, 64–512 MiB маршрутизаторы, серверы), уровни давления памяти, учёт `cgroup` и защита флеш-памяти от износа.
- [Маршрутизация и DNS](01-architecture/routing-and-dns.md) — порядок вычисления правил, неразрушающий сниффер протоколов, FakeIP (IPv4/IPv6), конвейер DNS (LRU-кэш, RDRC, optimistic, fallback, mDNS), бинарные наборы правил `.trs` (`mmap`) / `.srs` и расписания `time_window`.

### 2. Конфигурация

- [Обзор схемы конфигурации](02-config/schema-overview.md) — корневая структура JSON, `log`, `ntp`, `http_clients`, `network_namespaces`, слияние директорий (`-C`), требования валидации, устаревшие и удалённые поля.
- [Общие объекты](02-config/common-objects.md) — параметры `listen` и `dialer`, клиентский и серверный `tls` (uTLS, REALITY, ECH, провайдеры сертификатов), `transport`, `multiplex`, `udp_over_tcp`, `users`.
- [DNS](02-config/dns.md) — типизированные DNS-серверы (`udp`, `tcp`, `tls`, `https`, `quic`, `h3`, `local`, `hosts`, `fakeip`, `dhcp`, `mdns`, `resolved`, `tailscale`, `openvpn`, `openconnect`, `group`), правила DNS и стратегии разрешения.
- [Маршрутизация и наборы правил](02-config/route-and-rulesets.md) — поля секции `route`, матчеры и действия правил (`route`, `route-options`, `sniff`, `hijack-dns`, `resolve`, `reject`, `bypass`, `direct`), `time_window`, `rule_set` (`inline`, `local`, `remote`), `fullcone` и `smart_queue`.
- [Экспериментальные и сервисные секции](02-config/experimental.md) — `clash_api`, `cache_file` (`bbolt`), хранение FakeIP и RDRC.
- [Туннельные эндпоинты (Endpoints)](02-config/endpoints.md) — `wireguard` (включая параметры AmneziaWG 2.0/3.x и ротацию портов), `tailscale`, `openvpn-client`, `openvpn-server`, `openconnect`.

#### Входящие подключения (`inbounds`)

- [Сводка по инбаундам](02-config/inbounds/README.md) — классификация, общие параметры прослушивания и выбор типа инбаунда.
- [Системные и прозрачные инбаунды](02-config/inbounds/system-and-transparent.md) — `tun` (`smoltcp`, `auto_route`, `auto_redirect`), `tproxy`, `redirect`, `direct`, `mixed`, `socks`, `http`.
- [Серверные прокси-протоколы](02-config/inbounds/proxy-protocols.md) — `vless`, `vmess`, `trojan`, `shadowsocks` (AEAD и 2022), `anytls`, `shadowtls`, `naive`, `snell`.
- [Туннельные и QUIC-инбаунды](02-config/inbounds/tunnel-and-quic.md) — `hysteria2`, `tuic`, `masque`, `mieru`, `fptn`, `tewfai`, `mtproto`, `trusttunnel`, `openconnect`, `wdtt`, `cloudflared`.

#### Исходящие подключения (`outbounds`)

- [Сводка по аутбаундам](02-config/outbounds/README.md) — типы исходящих подключений, порядок выбора и параметры диалера.
- [Базовые аутбаунды, группы и цепочки](02-config/outbounds/core-and-groups.md) — `direct`, `block`, `socks`, `http`, `selector`, `urltest` (нативные режимы балансировки и `balancer`), `chain`, `detour`.
- [Прокси-аутбаунды](02-config/outbounds/proxy-protocols.md) — `vless`, `vmess`, `trojan`, `shadowsocks`, `anytls`, `shadowtls`, `naive`, `snell`.
- [QUIC, туннельные и специализированные аутбаунды](02-config/outbounds/quic-and-tunnels.md) — `hysteria2`, `tuic`, `masque`, `mieru`, `fptn`, `tewfai`, `mtproto`, `trusttunnel`, `openconnect`, `wdtt`.
- [Адаптивная сегментация пакетов (`desync`)](02-config/outbounds/desync.md) — профили `preset: "adaptive"`, ручные стратегии L4/L7-фрагментации TCP/TLS и UDP/QUIC.

### 3. Протоколы и форматы

- [Транспорты и мультиплексирование](03-protocols-and-formats/transports-and-mux.md) — TCP, WebSocket, HTTPUpgrade, HTTP/2, gRPC, QUIC, XHTTP (`stream-one`, `stream-up`, `packet-up`, `xmux`), `h2mux`/`smux`/`yamux` и `UDP-over-TCP` (UoT v1/v2).
- [Проводные спецификации протоколов](03-protocols-and-formats/proxy-wire-specs.md) — детали реализации протоколов, режимы шифрования (`VLESS` post-quantum encryption, `Shadowsocks 2022`, `Vision`, `Salamander`/`Gecko`), совместимость со сторонними клиентами и серверами.
- [Форматы наборов правил](03-protocols-and-formats/ruleset-formats.md) — нативный бинарный формат `.trs` (TSRS v2, zero-copy `mmap`), бинарный `.srs` (SRS v5) и исходный JSON `source`.
- [Подписки и форматы URI](03-protocols-and-formats/subscriptions-and-uris.md) — поддерживаемые провайдеры, URI-схемы, зашифрованные контейнеры (`Happ`, `Amnezia vpn://`), INI WireGuard/AmneziaWG, Clash YAML, Xray JSON и SIP008.

### 4. API, CLI и эксплуатация

- [CLI и параметры рантайма](04-api-and-cli/cli-and-runtime.md) — все команды, флаги, коды возврата, переменные окружения (`TACHYON_*`) и сигналы.
- [Clash API и управление состоянием](04-api-and-cli/clash-and-tachyon-api.md) — эндпоинты REST и WebSocket, авторизация `secret`, выбор узлов, мониторинг соединений, логов, трафика и горячая перезагрузка.
- [Эксплуатация и расчёт ресурсов](04-api-and-cli/operations-and-sizing.md) — профили памяти/CPU по классам устройств, бюджеты размера бинарника, релизные артефакты и диагностика типовых проблем.

### 5. Интеграция с платформами

- [OpenWrt](05-integration/openwrt.md) — установка `.ipk`/`.apk`, настройка `nftables` + `tproxy`/`tun`, `procd`, защита флеш-памяти и интеграция с LuCI.
- [Linux-серверы и Docker](05-integration/linux-and-docker.md) — `systemd`, `CAP_NET_ADMIN`/`CAP_NET_BIND_SERVICE`, тюнинг `sysctl`, сетевые пространства имён (`netns`) и контейнеры.
- [Настольные ОС (Windows и macOS)](05-integration/desktop-windows-macos.md) — запуск с `tun` и `mixed`, права администратора, настройка маршрутов и системного прокси.
- [Мобильные платформы (iOS и Android)](05-integration/mobile-ios-android.md) — `TachyonCore.xcframework` (`NEPacketTunnelProvider`, лимит 50 MiB Jetsam) и Android JNI `libtachyon-*.so` (`VpnService`, `protect_path`, выравнивание страниц 16 KB).
- [Встраивание (Rust и C FFI)](05-integration/embedding-rust-and-c.md) — 8 функций C ABI (`include/tachyon_core.h`), жизненный цикл экземпляра, передача `tun_fd` и Rust API (`BoxInstance`).

### 6. Готовые примеры конфигураций

- [Обзор примеров и проверка валидатором](06-examples/README.md)
- [`01-openwrt-tproxy-router.json`](06-examples/01-openwrt-tproxy-router.json) — маршрутизатор OpenWrt (`tproxy`, DoH/FakeIP, `.trs`, VLESS REALITY PQ, резервный `desync`, `clash_api`, `cache_file`).
- [`02-desktop-tun-client.json`](06-examples/02-desktop-tun-client.json) — настольный клиент (`tun` `smoltcp`, `mixed`, VLESS REALITY + XHTTP `xmux`, `urltest`, split routing).
- [`03-adaptive-desync-split.json`](06-examples/03-adaptive-desync-split.json) — локальная сетевая оптимизация (`mixed` + `tun`, `desync` `adaptive`, расписание `time_window`).
- [`04-server-multiplex.json`](06-examples/04-server-multiplex.json) — мультипротокольный сервер (`vless` REALITY, `hysteria2` Salamander, `tuic` v5, `anytls`, `shadowsocks` 2022, `fptn`).
- [`05-wireguard-awg-tailscale.json`](06-examples/05-wireguard-awg-tailscale.json) — туннельные эндпоинты (`wireguard` + AmneziaWG + port hopping и `tailscale` MagicDNS / Exit Node).
- [`06-chains-and-balancers.json`](06-examples/06-chains-and-balancers.json) — каскады (`detour` и `chain`) + `selector` и `urltest` (`sticky`, `priority` `tiers`).
- [`07-mobile-embedded-tun.json`](06-examples/07-mobile-embedded-tun.json) — компактный профиль для iOS / Android (`tun`, `dns`, `cache_file`).

---

## Быстрый старт

```bash
# Вывод версии ядра
tachyon-core version

# Предстартовая проверка синтаксиса и семантики конфигурации
tachyon-core check -c /etc/tachyon-core/config.json

# Запуск службы с одним файлом или каталогом фрагментов JSON
tachyon-core run -c /etc/tachyon-core/config.json
tachyon-core run -C /etc/tachyon-core/conf.d

# Компиляция, декомпиляция и проверка наборов правил
tachyon-core rule-set compile rules.json -o rules.srs
tachyon-core rule-set decompile rules.srs -o rules.json
tachyon-core rule-set match rules.srs example.com
tachyon-core rule-set upgrade rules.srs
```

Для генерации ключей и сертификатов без внешних утилит доступны команды `tachyon-core generate reality-keypair`, `wg-keypair`, `tls-keypair`, `uuid`, `rand`. Подробнее см. [CLI и параметры рантайма](04-api-and-cli/cli-and-runtime.md).

---

## Сводная матрица поддерживаемых протоколов

В таблице отражены протоколы, реализованные в рабочем конвейере данных (`run`) и поддерживаемые валидатором (`check`).

| Протокол / Тип | Outbound / Endpoint | Inbound | TCP | UDP | Примечания |
|:---|:---:|:---:|:---:|:---:|:---|
| `direct` | Outbound | Да | Да | Да | Прямой выход и проброс портов |
| `block` | Outbound | Нет | — | — | Сброс соединений |
| `desync` | Outbound | Нет | Да | Да | Адаптивная L4/L7-сегментация TCP/TLS и UDP/QUIC |
| `selector` / `urltest` | Outbound | Нет | Да | Да | Группы, `auto_failover`, нативные балансировщики |
| `chain` | Outbound | Нет | Да | Да | Декларативные многоступенчатые цепочки |
| `tproxy` | Нет | Да | Да | Да | Linux `IP_TRANSPARENT` (IPv4/IPv6) |
| `redirect` | Нет | Да | Да | Нет | Linux NAT redirect (`SO_ORIGINAL_DST`) |
| `tun` | Нет | Да | Да | Да | Стек `smoltcp`, `auto_route`, GSO, таблица `2022` |
| `mixed` | Нет | Да | Да | Да | Единый порт SOCKS4/4a/5 (`UDP ASSOCIATE`) и HTTP `CONNECT` |
| `socks` | Outbound | Да | Да | Да | SOCKS4/4a/5, поддержка `UoT` |
| `http` | Outbound | Да | Да | Нет | HTTP/HTTPS `CONNECT`, Basic Auth |
| `vless` | Outbound | Да | Да | Да | `xtls-rprx-vision`, `xudp`, REALITY (X25519 / `X25519MLKEM768`), шифрование `mlkem768x25519plus`, XHTTP/WS/gRPC/H2/HTTPUpgrade |
| `vmess` | Outbound | Да | Да | Да | AEAD (и legacy client), `h2mux`, WS/gRPC/H2/HTTPUpgrade |
| `trojan` | Outbound | Да | Да | Да | SHA-224, `fallback`, WS/gRPC/H2 |
| `shadowsocks` | Outbound | Да | Да | Да | AEAD и 2022-BLAKE3 (multi-user), `UoT`, опциональный TLS |
| `hysteria2` | Outbound | Да | Да | Да | QUIC (BBR/Cubic), `salamander`, `gecko`/`finalmask`, port hopping |
| `tuic` | Outbound | Да | Да | Да | TUIC v5 поверх QUIC, нативный и `quic` UDP relay |
| `anytls` | Outbound | Да | Да | Да (UoT) | TLS-мультиплексирование с `padding_scheme`, UDP через UoT |
| `naive` | Outbound | Да | Да | Да (UoT) | HTTP/2 и HTTP/3 QUIC, `padding`, UDP через UoT |
| `shadowtls` | Outbound | Да | Да | Да (outbound) | ShadowTLS v2/v3, сквозная передача, wildcard SNI (inbound TCP-only) |
| `snell` | Outbound | Да | Да | Да | Snell v4 / v5 / v6 (outbound v4–v6, inbound v5–v6; TCP + UDP) |
| `masque` | Outbound | Да | Да | Да | RFC 9484 `CONNECT-IP` поверх HTTP/3 (совместимость с WARP) |
| `mieru` | Outbound | Да | Да | Да | TCP и UDP транспорты, многопортовые привязки |
| `fptn` | Outbound | Да | Да | Да | WebSocket + TLS 1.3, декодер токенов `fptn:`/`fptnb:` |
| `tewfai` | Outbound | Да | Да | Да | Мультитранспортный туннель (TCP/TLS/QUIC) |
| `trusttunnel` | Outbound | Да | Да | Да | TCP, UDP и ICMP echo поверх TLS/QUIC |
| `wdtt` | Outbound | Да | Да | Да | Туннель TCP/UDP с обфускацией |
| `mtproto` | Outbound | Да | Да | Нет | Проксирование MTProto (TCP) |
| `openconnect` | Outbound | Да | Да | Да | Клиентский аутбаунд и серверный инбаунд OpenConnect |
| `wireguard` | Endpoint | Да (peer) | Да | Да | WireGuard + AmneziaWG 2.0/3.x (`jc`/`s1`–`s4`/`h1`–`h4`/`i1`–`i5`), port hopping |
| `tailscale` | Endpoint | Да (mesh) | Да | Да | Встроенный узел Tailscale, Exit Node, MagicDNS |
| `openvpn-client` | Endpoint | Нет | Да | Да | Клиентский эндпоинт OpenVPN (UDP/TCP, `static_key`, LZO) |

> [!NOTE]
> Валидатор схемы (`tachyon-core check -c`) дополнительно проверяет поля совместимости для типов `hysteria` (v1), `tor`, `ssh`, `bridge`, `dns` (устаревший outbound), `cloudflared`, `sudoku`, `openvpn-server` и `openconnect` (в секции `endpoints`), которые зарезервированы для проверки схемы и не запускаются в конвейере данных текущей версии.

---

## Сводная матрица целевых платформ

Официальные релизные артефакты собираются автоматически для всех перечисленных платформ без внешних C/OpenSSL-зависимостей (подробнее о бюджетах и упаковке см. [Эксплуатация и расчёт ресурсов](04-api-and-cli/operations-and-sizing.md)):

| Имя сборки | Target triple | Типовые устройства и ОС | Артефакты релиза | Лимит бинарника |
|:---|:---|:---|:---|:---:|
| `x86_64` | `x86_64-unknown-linux-musl` | x86_64 OpenWrt, мини-ПК, контейнеры Alpine / static Linux | `.tar.gz`, `.ipk`, `.apk` | 14 MiB |
| `i386_pentium4` | `i686-unknown-linux-musl` | 32-битные маршрутизаторы x86 OpenWrt (`x86/generic`) | `.tar.gz`, `.ipk`, `.apk` | 14 MiB |
| `aarch64` | `aarch64-unknown-linux-musl` | Filogic 820/830/880, IPQ807x/60xx/50xx, NanoPi, RPi 4/5 | `.tar.gz`, `.ipk`, `.apk` | 14 MiB |
| `armv7` | `armv7-unknown-linux-musleabihf` | IPQ4019, MT7622/MT7623, Armada 385, маршрутизаторы ARMv7 | `.tar.gz`, `.ipk`, `.apk` | 14 MiB |
| `armv6` | `arm-unknown-linux-musleabi` | BCM2835, Raspberry Pi Zero / 1, встраиваемые ARMv6 | `.tar.gz`, `.ipk`, `.apk` | 14 MiB |
| `riscv64` | `riscv64gc-unknown-linux-musl` | StarFive VisionFive 2, Milk-V, платы RISC-V | `.tar.gz`, `.ipk`, `.apk` | 14 MiB |
| `mipsel` | `mipsel-unknown-linux-musl` (`+soft-float`) | MT7621, MT7628, RT305x/RT5350 (`ramips`, без FPU) | `.tar.gz`, `.ipk`, `.apk` | 16 MiB |
| `mips` | `mips-unknown-linux-musl` (`+soft-float`) | AR71xx, AR934x, QCA95xx (`ath79` Big-Endian, без FPU) | `.tar.gz`, `.ipk`, `.apk` | 16 MiB |
| `linux-amd64` | `x86_64-unknown-linux-gnu` | Серверы и VPS на Debian, Ubuntu, Fedora, Arch, Proxmox | `.tar.gz` | 16 MiB |
| `windows-amd64` | `x86_64-pc-windows-msvc` | Windows 10/11 и Windows Server (x64) | `.zip` | 20 MiB |
| `darwin-arm64` | `aarch64-apple-darwin` | macOS на Apple Silicon (M1–M4) | `.tar.gz` | 16 MiB |
| `darwin-amd64` | `x86_64-apple-darwin` | macOS на процессорах Intel | `.tar.gz` | 16 MiB |
| `ios-arm64` | `aarch64-apple-ios` (+ `aarch64-apple-ios-sim`) | iOS `NEPacketTunnelProvider` (CLI-бинарник + C-FFI `TachyonCore.xcframework`) | `.tar.gz`, `xcframework.tar.gz` | 16 MiB |
| `aarch64-linux-android` | `aarch64-linux-android` (API 24+, 16 KB) | Android `arm64-v8a` (CLI + JNI `libtachyon-arm64-v8a.so`) | `.tar.gz`, `libtachyon-arm64-v8a.so` | 16 MiB |
| `armv7-linux-androideabi` | `armv7-linux-androideabi` (API 24+, 16 KB) | Android `armeabi-v7a` (CLI + JNI `libtachyon-armeabi-v7a.so`) | `.tar.gz`, `libtachyon-armeabi-v7a.so` | 16 MiB |
| `x86_64-linux-android` | `x86_64-linux-android` (API 24+, 16 KB) | Android `x86_64` (эмуляторы и планшеты x86, CLI + JNI `libtachyon-x86_64.so`) | `.tar.gz`, `libtachyon-x86_64.so` | 16 MiB |
