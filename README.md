<div align="center">

![Tachyon Core Banner](assets/readme/hero.svg)

[![Stars](https://img.shields.io/github/stars/Dushnilin/tachyon-core?style=for-the-badge&color=00F0FF)](https://github.com/Dushnilin/tachyon-core/stargazers)
[![Rust](https://img.shields.io/badge/Rust-1.89+_(2024)-DEA584?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Binary Size](https://img.shields.io/badge/Binary-10.0_--_12.8_MiB-38BDF8?style=for-the-badge&logo=target)](https://github.com/Dushnilin/tachyon-core/releases/tag/v0.0.1)
[![RAM RSS](https://img.shields.io/badge/RAM_RSS-4.2_MiB_idle-10B981?style=for-the-badge&logo=speedtest)](https://github.com/Dushnilin/tachyon-core)
[![Benchmarks](https://img.shields.io/badge/Benchmarks-36%2F39_Wins-10B981?style=for-the-badge&logo=speedtest)](BENCHMARK.md)
[![Interactive Report](https://img.shields.io/badge/Dashboard-HTML_Report-6366F1?style=for-the-badge&logo=html5&logoColor=white)](BENCHMARK.html)
[![OpenWrt](https://img.shields.io/badge/OpenWrt-23.05_%7C_24.10_%7C_25.x_%7C_SNAPSHOT-10B981?style=for-the-badge&logo=openwrt)](https://openwrt.org/)
[![License](https://img.shields.io/badge/License-GPL--3.0-FF6B4A?style=for-the-badge)](LICENSE)

[**🇷🇺 Русский**](README.md) | [**🇬🇧 English**](README.en.md) | [**📊 Свежий бенчмарк**](BENCHMARK.md) | [**🌐 Интерактивный HTML**](BENCHMARK.html)

</div>

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## ⚡ О проекте

**tachyon-core** — прокси-ядро для роутеров и встраиваемых систем, написанное с нуля на чистом **Rust**. Берёт **тот же JSON-конфиг** и **тот же CLI**, что и sing-box, но без рантайма Go: тот же файл `/etc/sing-box/config.json`, те же `check -c` / `version` / `run`, тот же бинарник, который при установке под именем `sing-box` отдаёт совместимую версию.

Поддерживается весь набор [sing-box-lx](https://github.com/Leadaxe/sing-box-lx): XHTTP, AmneziaWG 2.0/3.x, MASQUE/WARP, uTLS, REALITY, ShadowTLS, DNS-группы, постквантовое шифрование, нативный Tailscale и zero-copy mmap rule-sets.

Замеры — на реальных статических musl-сборках против эталонных Go-ядер (`sing-box-lx` 1.14.2-lx.12, `Xray-core`, `Mihomo`) и модульного C-стека `steer`, в одноядерном роутерном профиле (1 worker, CPU pinning). Полные графики: **[BENCHMARK.md](BENCHMARK.md)** и **[BENCHMARK.html](BENCHMARK.html)**.

**Средние цифры по всем целевым архитектурам:**

| | tachyon-core | Go-ядра (sing-box-lx / Xray / Mihomo) | Преимущество |
|---|:---:|:---:|:---:|
| **Размер бинарника** | **10.0–12.8 MiB** (4.7–5.3 МБ в архиве) | ~70 MiB | **в ~6.5× меньше** |
| **RAM в простое** | **4.2 MiB** | ~41 MiB | **в ~10× меньше** |
| **RAM под нагрузкой** | **~10 MiB** | ~65 MiB | **в ~6 раз меньше** |
| **Паузы GC** | **0.00 ms** | 2–15 ms | **нет джиттера вообще** |
| **Холодный старт** | **22 ms** | ~210 ms | **в 7–12 раз быстрее** |
| **Зависимости от C / CGO** | **0** | CGO / BoringSSL | **собирается под любой MIPS** |

> **Прямое преимущество №1 — память.** ~10× меньше в простое на роутере с 128 МБ — это разница между «OOM-киллер в неподходящий момент» и запасом для conntrack, Wi-Fi и LuCI.
>
> **Прямое преимущество №2 — флеш.** 10.0–12.8 MiB (4.7–5.3 МБ в архиве) против ~70 MiB: ядро ставится во внутреннюю память `/usr/bin/` роутера с 16/32/128 МБ, без USB-накопителя и extroot. Go-бинарник туда физически не влезает.

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## ⚔️ Почему Rust, а не Go

| | sing-box / sing-box-lx / Xray (Go) | tachyon-core (Rust) |
|---|---|---|
| **Сборщик мусора** | Непрерывный обход кучи + STW-фазы: всплески нагрузки и **паузы 2–15 мс** на слабых CPU роутера. Видны как микрофризы в VoIP и скачки пинга в играх | Сборщика нет. RAII освобождает память детерминированно, в момент выхода сокета из области видимости. **0.00 ms пауз**, плоский график задержек |
| **Планировщик и пулы** | Внутренние пулы потоков, стеки горутин, резерв через `mheap`: ~41 MiB в полном простое, под 10k соединений — за 100 MiB и срабатывание OOM-Killer | Ничего не резервируется про запас. 4.2 MiB в простое, ~10 MiB в пике |
| **Криптография на MIPS** | BoringSSL/CGO ломает сборку под 32-битный softfloat MIPS (MediaTek MT7621, ath79), а `gc` выдаёт неоптимальный код | Криптопровайдер целиком на чистом RustCrypto (`aes-gcm`, `chacha20poly1305`, `sha2`, `x25519-dalek`, `ml-kem`, `blake3`). Ни одного внешнего C-файла, никакого `libssl.so` |
| **Конвейер данных** | Копирования в userspace между клиентским сокетом и туннелем | Пул буферов `bytes::Bytes` + `splice` и драйвер `drive_transparent` — перенаправление без промежуточных копий |

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 📊 Производительность

<div align="center">

![Tachyon Speed Pipeline](assets/readme/tachyon_speed.svg)

</div>

### Сквозной тест маршрутизации (SOCKS5 Inbound → Direct Outbound), 1 ядро CPU

| Ядро | Бинарник | Холодный старт | RAM (Idle / Peak) | Задержка p50 / p99 | Пропускная | CPU |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **tachyon-core** | **11.61 MiB** | **22.3 ms** 🥇 | **4.2 / 4.6 MiB** 🥇 | **170.0 / 221.4 µs** 🥇 | **51.7 Gbps** | 0.163 s/G |
| `steer` (C, 3 процесса) | 1.76 MiB | 141.9 ms | 5.1 / 5.4 MiB | 173.6 / 221.7 µs | 8.0–9.6 Gbps | 1.067 s/G |
| `xray-core` (Go, XTLS) | 34.88 MiB | 161.1 ms | 25.0 / 25.6 MiB | 183.9 / 233.4 µs | 53.1 Gbps | 0.158 s/G |
| `mihomo` (Go, Clash Meta) | 59.12 MiB | 211.3 ms | 32.9 / 33.9 MiB | 188.5 / 251.3 µs | 48.2 Gbps | 0.174 s/G |
| `sing-box-lx` (Go, эталон) | 76.01 MiB | 268.2 ms | 39.9 / 40.8 MiB | 182.6 / 232.8 µs | 51.5 Gbps | 0.166 s/G |

> **Прямое преимущество №3 — холодный старт.** 22 ms против ~210 ms: на роутере, где сервис поднимается при каждой перезагрузке или рестарте сети, это разница между «работает» и «минута ожидания».
>
> На чистом loopback по пропускной способности `xray-core` ушёл вперёд (53.1 против 51.7 Gbps) — разница в пределах шума. Реальное преимущество tachyon здесь не в гигабайтах в секунду, а в памяти, старте и латентности: **самая низкая p50 и p99 среди всех пяти ядер** при 4.2 MiB вместо 25–41 MiB.

### Мульти-протокольный бенчмарк

**36 побед из 39 протоколов, 3 ничьи, 0 поражений.** Средние по 1s/8s, Gbit/s:

| Протокол | Tachyon | Sing-box-lx | Xray | Mihomo | Steer | Преимущество |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Hysteria 2 (QUIC)** | **3.2 / 4.2** | 1.8 / 1.8 | — | 2.3 / 1.9 | 1.8 / 1.8 | **в ~2.3×** |
| **NaiveProxy (H2)** | **2.4 / 4.2** | 1.4 / 2.1 | — | — | — | **в ~2×** |
| **TUIC v5 (QUIC)** | **3.9 / 4.6** | 2.5 / 1.9 | — | 2.4 / 2.0 | — | **в ~2×** |
| Mieru (TCP) | — | 2.1 / 2.5 | — | 2.1 / 2.4 | — | есть, клиент и сервер; проверено против настоящих mieru и mita, скорость не мерили |
| **WireGuard** | **7.2 / 8.5** | 4.1 / 4.8 | 3.8 / 4.2 | 3.9 / 4.4 | — | **в ~1.8×** |
| **AmneziaWG** | **7.0 / 8.1** | 4.0 / 4.6 | 3.6 / 4.1 | 3.8 / 4.2 | — | **в ~1.8×** |
| **MASQUE (WARP)** | **4.8 / 6.4** | 3.1 / 3.9 | — | — | — | **в ~1.6×** |
| **ShadowTLS v3** | **5.6 / 7.1** | 3.8 / 4.6 | — | 3.4 / 4.1 | — | **в ~1.5×** |
| **VLESS + gRPC + TLS** | **2.6 / 4.6** | 1.6 / 2.5 | 1.7 / 2.8 | 1.7 / 3.2 | 1.4 / 1.7 | **в ~1.4×** |
| **VMess + WS + TLS** | **4.3 / 5.6** | 3.0 / 3.3 | 2.0 / 2.0 | 2.1 / 2.2 | 2.0 / 2.1 | **в ~1.7×** |
| VLESS (Plain) | 23.3 / 31.9 | 24.7 / 33.5 | 8.2 / 9.1 | — | 8.2 / 8.7 | паритет |
| VLESS + TLS + Vision | 3.4 / 3.7 | 3.2 / 3.5 | 2.2 / 2.8 | 3.3 / 3.5 | 2.7 / 3.1 | паритет |

> **Прямое преимущество №4 — QUIC-протоколы.** Hysteria2 и TUIC — единственные, где отрыв самый заметный: ~2–2.3× по скорости при вдвое меньшем пиковом RSS (12–25 MiB против 50–53 MiB).
>
> **Прямое преимущество №5 — XHTTP.** Встроенный пул соединений `H2Pool` убирает повторные TLS-рукопожатия на каждый стрим. Задержка первого байта: **408 µs против ~30 ms** у Go-ядер — **в ~75 раз быстрее**. На мультиплексированных стримах — 4.4+ Gbit/s.
>
> Полные 39 протоколов, p50/p99 и RSS по каждому: **[BENCHMARK.md](BENCHMARK.md)**.

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 🌐 Возможности ядра

<div align="center">

![Tachyon Core Architecture](assets/readme/architecture.svg)

</div>

**Инбаунды.** Прозрачный перехват трафика: Linux **TProxy** (IPv4/IPv6) через `IP_TRANSPARENT` с извлечением реального адреса через OOB `IP_RECVORIGDSTADDR`; **Redirect** (NAT) через `SO_ORIGINAL_DST`; **Mixed SOCKS/HTTP** с полным CONNECT, SOCKS4/4a/5, UDP ASSOCIATE, 407 и keep-alive; **Direct**; **TUN** (`/dev/net/tun`, userspace-стек TCP на `smoltcp`, GSO-сегментация, policy routing в отдельной таблице 2022). Серверный стек: VLESS, Trojan, VMess (AEAD), Shadowsocks (AEAD), AnyTLS, Naive, Hysteria2, TUIC — с собственным TLS 1.3 на чистом Rust и UDP поверх того же TCP.

Схема всех полей — **[docs/reference/](docs/reference/README.md)**: типы инбаундов и аутбаундов, общие блоки (listen, dialer, TLS, транспорты, мультиплексирование), значения по умолчанию и ограничения.

**Аутбаунды.** `direct`, `block`, `socks`, `http`. Shadowsocks (все AEAD-шифры, спецификация 2022, UoT, TLS-транспорт). VLESS (`flow: xtls-rprx-vision`, все `packet_encoding`, `h2mux`, uTLS). VMess (AEAD и legacy, `h2mux`). Trojan (SHA224). Hysteria2 (движок на `quinn`, обфускация salamander и gecko, BBR и Cubic). TUIC v5. AnyTLS. Naive (HTTP/2 и HTTP/3, `Padding`, `-connect-authority`, блоки `[len:u16][pad:u8]`). Snell v4/v6. ShadowTLS v3. MASQUE (WARP). FPTN. Диспетчеризация: `urltest` и `selector` (`round_robin`, `least_test`, `least_ping`).

**Эндпоинты туннелей.** AmneziaWG 2.0/3.x и WireGuard — полный конвейер с мусорными пакетами в начале сессии (`jc`, `jmin`, `jmax`, `s1–s4`, `h1–h4`) и маскировкой инициализации под DNS, STUN, SIP и QUIC Initial. OpenVPN-клиент: `static_key` поверх UDP и TCP, сжатие и фрагментация.

**Транспорты и маскировка от DPI.** TCP, WebSocket (`max_early_data`), HTTPUpgrade, gRPC, HTTP/2, QUIC/HTTP-3. **XHTTP**: HTTP/1.1 chunked, `stream-up`, `packet-up`, `stream-one` и пул `H2Pool` до 4 параллельных сокетов с балансировкой least-loaded, расширенные окна потока (4 MiB stream / 16 MiB connection), валидация против серверов Xray 26.9+. **Pure-Rust uTLS**: 13 байт-точных браузерных профилей и собственный ClientHello. **Pure-Rust REALITY** со сквозным `splice`. **Постквантовая криптография**: гибридный обмен ключами ML-KEM-768 (`X25519MLKEM768`) против атак «Store Now, Decrypt Later».

**Smart DNS.** `udp`, `tcp`, `tls` (DoT), `https` (DoH), `quic` (DoQ), `h3` (DoH3), `fakeip`, `local`, `hosts` (файл и инлайн), `mdns`. DNS-группы (`group`) со стратегиями `stable` / `fastest` / `parallel` на скользящей статистике и аварийным режимом. `dns.reverse_mapping` для правил по домену к обращениям по IP. `dns.client_subnet` (EDNS0). LRU-кэш на `Arc<str>` с оптимистичной отдачей устаревших записей и пул FakeIP `198.18.0.0/15`.

**Роутер и инспекция.** Матчеры правил: `inbound`, `network`, `protocol`, домен (suffix, keyword, regex, exact), `ip_cidr`, `ip_is_private`, `source_*`, `port`, `port_range`, `process_name`, `process_path`, `process_path_regex`, `user`, `user_id` (через `/proc/net/*` и дескрипторы сокетов), `clash_mode`, `rule_set`, `rule_set_ipcidr_match_source`. Таблица соседей и DHCP (`find_neighbor`) для `source_mac_address` и `source_hostname`. Сниффер PeekStream: TLS SNI, HTTP Host, QUIC SNI, DNS, BitTorrent, SSH, RDP — без потери начальных байт. Бинарные правила SRS v5: компиляция, декомпиляция, проверка совпадений и удалённая синхронизация списков.

**Системный диалер.** Netns с дочерним процессом-держателем `CLONE_NEWNET` и бесконфликтным dial. `protect_path` — передача дескрипторов сокетов VPN-демонам через `SCM_RIGHTS`. Multipath TCP, Happy Eyeballs RFC 6555, fwmark (`routing_mark`), привязка к интерфейсу (`bind_interface`), защита от шторма пакетов при сбросе соединений.

**API и состояние.** Clash REST API: `/version`, `/proxies`, `/connections`, `/rules`, `/configs`, `/logs`, `/traffic`, `/providers/*`, WebSocket-трафик, secret-токен, CORS, `clash_mode` и встроенная раздача панелей Yacd / Metacubexd по `/ui`. Файл `cache.db` — честный B+tree на чистом Rust, побайтово совместимый с Go bbolt. Встроенный NTP-клиент и реестр HTTP-клиентов `http_clients`.

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 🧭 Drop-In совместимость с sing-box

<div align="center">

![Tachyon Core CLI Showcase](assets/readme/cli_showcase.svg)

</div>

```bash
tachyon-core check -c /etc/sing-box/config.json                    # проверка конфига (247/0 по корпусу тестов)
tachyon-core version                                              # версия в upstream-совместимом формате
tachyon-core run -c /etc/sing-box/config.json                     # запуск
tachyon-core rule-set compile rules.json -o rules.srs            # SRS v5, оба направления
```

| Команда | Назначение | Статус |
|---|---|:---:|
| `check -c <path>` | Предстартовая проверка конфига в `watchdog.uc` | **Готово** |
| `version` | Определение версии в `generator.uc` | **Готово** |
| `run -c <path>` | Запуск рабочего процесса службы | **Готово** |
| `rule-set compile\|decompile` | Бинарные правила `.srs` (SRS v5) | **Готово** |
| `rule-set match\|format` | Проверка правил и форматирование | **Готово** |
| `api` | Управление и мониторинг через Clash API | **Готово** |
| `generate reality-keypair` | Ключи REALITY | Запланировано |
| `generate wg-keypair` | Ключи WireGuard / AmneziaWG | Запланировано |

> Совместимость с форматом конфигурации sing-box — **временная мера для миграции**, см. дорожную карту ниже.

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 🚀 Сборка

Требуется Rust 1.89+ (редакция 2024).

```bash
# Сборка релизного бинарника (все протоколы, Clash API, DNS-группы, Tailscale, mmap, ~11 MiB)
cargo build --workspace --release

# Проверка лимитов размера (<= 12 MiB) и запуск тестов
bash scripts/size.sh
cargo test --workspace

# Кросс-компиляция статических musl-бинарников
cargo install cargo-zigbuild
cargo zigbuild --target aarch64-unknown-linux-musl --release     # ARM64: NanoPi R3S/R4S, Flint 2, RPi 4/5
cargo zigbuild --target armv7-unknown-linux-musleabihf --release # ARMv7: IPQ4019, AX1800, Keenetic Hopper
cargo zigbuild --target x86_64-unknown-linux-musl --release      # Мини-ПК, Proxmox, x86-роутеры
```

Символы вырезаются автоматически (`strip = "symbols"`): **10.0–12.8 MiB** (в архиве 4.7–5.3 МБ).

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 🗺️ Дорожная карта

Функционал разбит на фазы с автоматическим дифференциальным тестированием против эталонного `sing-box-lx`.

| Фаза | Область | Статус |
|:---:|---|:---:|
| **F0** | Фундамент: дифференциальные тесты `check` и `version` по всему корпусу (247/0) | **Завершено** |
| **F1** | Data Plane v1: инбаунды tproxy/redirect/mixed/direct, аутбаунды socks/ss/vless/trojan/vmess, Smart DNS + FakeIP + LRU, роутер и сниффер | **Завершено** |
| **F2** | Тяжёлые протоколы: Hysteria2, TUIC, WireGuard + AmneziaWG, XHTTP, uTLS/REALITY, Naive, Snell, AnyTLS, ShadowTLS | **Завершено** |
| **F3** | Правила SRS v5 и удалённые обновления списков | **Завершено** |
| **F4** | Экспериментальный стек: Clash API (Yacd, secret, WebSocket), `cache.db` (bbolt r/w) | **Завершено** |
| **F5** | Серверная часть: серверные инбаунды VLESS, Trojan, VMess, Shadowsocks с собственным TLS 1.3 и UDP | **Завершено** |
| **F6** | TUN-подсистема: userspace-стек на `smoltcp`, TCP-прокси, UDP NAT, routing table 2022 + fwmark, GRO/virtio_net_hdr | **Завершено** |
| **F7** | lx daemon и метрики: совместимость со службой Windows и демоном `lxd`, расширенная телеметрия | Запланировано |
| **F8** | libbox / Android: UniFFI/JNI биндинги | Запланировано |
| **F9** | MIPS-спайк: таргеты `mipsel`/`mips` softfloat musl через `-Zbuild-std` | **В разработке** (сборка в CI есть) |
| **F10** | Интеграция в Tachyon: автоинсталлятор, переключение ядра в LuCI в 1 клик, мониторинг маршрутов | **Завершено** (Tachyon 1.5.0) |
| **F11** | **Собственная система конфигурации и хранения данных на флеше** | **Декабрь 2026** |
| **F12** | **Отказ от совместимости с конфигами sing-box** | **1 января 2027** |

### Переход на собственный формат конфигурации

**Декабрь 2026 — родной формат и своё хранилище.** Вместо того чтобы разбирать чужую схему и тащить её ограничения, ядро получает собственный формат конфигурации, рассчитанный под задачи роутера, и собственное хранилище состояния на флеше (`/etc/tachyon/`) вместо разрозненных файлов и внешних путей. Правила, списки и кэши переезжают в один предсказуемый формат, который не тащит за собой ни чужие соглашения, ни лишние зависимости.

**Новый год — совместимость с sing-box убрана.** Чтение конфигов sing-box перестаёт поддерживаться. Чтобы переход не ломал существующие установки, **автоматическая миграция отдаётся вместе с F11, до 1 января**: при первом запуске новой версии конфиг на старом формате один раз конвертируется на месте, с резервной копией и проверкой результата. После этого ядро читает только свой формат, и зависимость от чужой схемы исчезает совсем.

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 📜 Лицензия

**[GPL-3.0-only](LICENSE)**, унаследована от sing-box и sing-box-lx. `tachyon-core` — независимая разработка сообщества Tachyon, не аффилированная с SagerNet или Leadaxe. Авторские права на протоколы и спецификации sing-box принадлежат их законным авторам.

<p align="center">
  <img src="assets/readme/footer_tachyon.svg" width="100%" alt="Tachyon Community Footer" />
</p>