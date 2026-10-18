<div align="center">

![Tachyon Core Banner](assets/readme/hero.svg)

[![Stars](https://img.shields.io/github/stars/Dushnilin/tachyon-core?style=for-the-badge&color=00F0FF)](https://github.com/Dushnilin/tachyon-core/stargazers)
[![Release](https://img.shields.io/github/v/release/Dushnilin/tachyon-core?style=for-the-badge&color=C084FC&logo=github)](https://github.com/Dushnilin/tachyon-core/releases/latest)
[![Rust](https://img.shields.io/badge/Rust-1.89+_(2024)-DEA584?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Binary Size](https://img.shields.io/badge/Binary-6.9_--_10.2_MiB_(3.7_MiB_tar.gz)-38BDF8?style=for-the-badge&logo=target)](https://github.com/Dushnilin/tachyon-core/releases/latest)
[![RAM RSS](https://img.shields.io/badge/RAM_RSS-4.2_MiB_idle-10B981?style=for-the-badge&logo=speedtest)](https://github.com/Dushnilin/tachyon-core)
[![Benchmarks](https://img.shields.io/badge/Benchmarks-36%2F39_Wins-10B981?style=for-the-badge&logo=speedtest)](BENCHMARK.md)
[![Interactive Report](https://img.shields.io/badge/Dashboard-HTML_Report-6366F1?style=for-the-badge&logo=html5&logoColor=white)](BENCHMARK.html)
[![OpenWrt](https://img.shields.io/badge/OpenWrt-23.05_%7C_24.10_%7C_25.x_%7C_SNAPSHOT-10B981?style=for-the-badge&logo=openwrt)](https://openwrt.org/)
[![License](https://img.shields.io/badge/License-Proprietary-FF6B4A?style=for-the-badge)](LICENSE)

[**🇷🇺 Русский**](README.md) | [**🇬🇧 English**](README.en.md) | [**📦 Скачать билды (Releases)**](https://github.com/Dushnilin/tachyon-core/releases/latest) | [**📊 Свежий бенчмарк**](BENCHMARK.md) | [**🌐 Интерактивный HTML**](BENCHMARK.html)

</div>

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

> [!IMPORTANT]
> **📦 Формат публикаций начиная с версии `0.1.3` (Builds-Only Releases)**
>
> Исходный код в этом публичном репозитории (`Dushnilin/tachyon-core`) **заморожен на историческом выпуске `v0.1.2`**.
> Начиная с релиза **`v0.1.3`**, разработка нового исходного кода ведётся в закрытом приватном репозитории, а сюда через GitHub Actions автоматически подтягиваются и публикуются **только готовые релизные сборки (статические бинарники под 11 архитектур), контрольные суммы `SHA256SUMS`, документация, список изменений и отчёты бенчмарков**.

## ⚡ О проекте

**tachyon-core** — независимое высокопроизводительное сетевое ядро маршрутизации и туннелирования для роутеров, серверов и встраиваемых систем, написанное с нуля на 100% чистом **Rust** без единой строчки кода на Go или C/C++. Ядро поддерживает стандартный синтаксис JSON-конфигураций и командный интерфейс (`check -c` / `version` / `run` / `generate` / `rule-set`) для бесшовной работы в существующих окружениях OpenWrt без рантайма Go и сборщика мусора.

Реализован полный стек современных сетевых и транспортных протоколов: XHTTP (`H2Pool` + `HTTP/1.1`), AmneziaWG 2.0/3.x (с многопоточным пулом `WgPool`, расширенными заголовками `H1–H4` и фреймингом `I1–I5`), MASQUE/WARP (RFC 9484), Mieru (TCP/UDP), Hysteria2, TUIC v5, AnyTLS, Naive, ShadowTLS v3, uTLS (13 профилей TLS ClientHello), REALITY (с поддержкой сертификатов X.509v1 и пиннинга ключей), DNS-группы, постквантовый обмен ключами `X25519MLKEM768`, нативный Tailscale, zero-copy mmap rule-sets и **адаптивный аппаратный движок `HardwareProfile`**, который в реальном времени подстраивает потоки, окна QUIC/TCP и буферы под объём и давление ОЗУ роутера.

Замеры выполнены на реальных статических musl-сборках в сравнении с популярными Go-ядрами (`Xray-core`, `Mihomo`, `sing-box`) и модульным C-стеком `steer` в одноядерном роутерном профиле (1 worker, CPU pinning). Полные результаты по всем 39 протоколам: **[BENCHMARK.md](BENCHMARK.md)** и **[BENCHMARK.html](BENCHMARK.html)**.

**Средние цифры по всем целевым архитектурам:**

| | tachyon-core | Сетевые ядра на Go | Преимущество |
|---|:---:|:---:|:---:|
| **Размер бинарника** | **6.9–10.2 MiB** (3.2–4.2 MiB в `.tar.gz`) | 35–76 MiB | **в ~8–10× меньше** |
| **RAM в простое** | **4.2 MiB** | 25–41 MiB | **в ~10× меньше** |
| **RAM под нагрузкой** | **~10 MiB** | 48–85 MiB | **в ~6 раз меньше** |
| **Паузы GC** | **0.00 ms** | 2–15 ms | **нет джиттера вообще** |
| **Холодный старт** | **22 ms** | 160–270 ms | **в 7–12 раз быстрее** |
| **Адаптивный профиль** | **4 профиля RAM + 3 уровня давления** | фиксированные буферы | **авто-тюнинг от 64 МБ до 8+ ГБ** |
| **Зависимости от C / CGO** | **0** | CGO / BoringSSL | **собирается под любой MIPS / ARMv6** |

> **Прямое преимущество №1 — память.** ~10× меньше в простое на роутере с 64–128 МБ — это разница между «OOM-киллер в неподходящий момент» и запасом для conntrack, Wi-Fi и LuCI.
>
> **Прямое преимущество №2 — флеш.** 6.9–10.2 MiB в распакованном виде (3.2–4.2 MiB в `.tar.gz`) против 35–76 MiB: ядро ставится во внутреннюю память `/usr/bin/` роутера с 16/32/128 МБ, без USB-накопителя и extroot.

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## ⚔️ Почему Rust, а не Go

| | Сетевые ядра на Go | tachyon-core (Rust) |
|---|---|---|
| **Сборщик мусора** | Непрерывный обход кучи + STW-фазы: всплески нагрузки и **паузы 2–15 мс** на слабых CPU роутера. Видны как микрофризы в VoIP и скачки пинга в играх | Сборщика нет. RAII освобождает память детерминированно, в момент выхода сокета из области видимости. **0.00 ms пауз**, плоский график задержек |
| **Планировщик и пулы** | Внутренние пулы потоков, стеки горутин, резерв через `mheap`: 25–41 MiB в полном простое, под 10k соединений — за 100 MiB и срабатывание OOM-Killer | Ничего не резервируется про запас. 4.2 MiB в простое, ~10 MiB в пике + живой мониторинг `/proc/meminfo` с автоматическим сжатием кэшей и буферов |
| **Криптография на MIPS** | BoringSSL/CGO ломает сборку под 32-битный softfloat MIPS (MediaTek MT7621, ath79), а `gc` выдаёт неоптимальный код | Криптопровайдер целиком на чистом Rust (`oxitls` + `AF_ALG`, `aes-gcm`, `chacha20poly1305`, `sha2`, `x25519-dalek`, `ml-kem`, `blake3`) с аппаратным NEON/AES-NI. Ни одного внешнего C-файла, никакого `libssl.so` |
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
| **tachyon-core** | **6.99–10.2 MiB** | **22.3 ms** 🥇 | **4.2 / 4.6 MiB** 🥇 | **170.0 / 221.4 µs** 🥇 | **51.7 Gbps** | 0.163 s/G |
| `steer` (C, 3 процесса) | 1.76 MiB | 141.9 ms | 5.1 / 5.4 MiB | 173.6 / 221.7 µs | 8.0–9.6 Gbps | 1.067 s/G |
| `xray-core` (Go, XTLS) | 34.88 MiB | 161.1 ms | 25.0 / 25.6 MiB | 183.9 / 233.4 µs | 53.1 Gbps | 0.158 s/G |
| `mihomo` (Go, Clash Meta) | 59.12 MiB | 211.3 ms | 32.9 / 33.9 MiB | 188.5 / 251.3 µs | 48.2 Gbps | 0.174 s/G |
| `sing-box` (Go) | 76.01 MiB | 268.2 ms | 39.9 / 40.8 MiB | 182.6 / 232.8 µs | 51.5 Gbps | 0.166 s/G |

> **Прямое преимущество №3 — холодный старт.** 22 ms против ~210 ms: на роутере, где сервис поднимается при каждой перезагрузке или рестарте сети, это разница между «работает» и «минута ожидания».
>
> На чистом loopback по пропускной способности `xray-core` ушёл вперёд (53.1 против 51.7 Gbps) — разница в пределах шума. Реальное преимущество tachyon здесь не в гигабайтах в секунду, а в памяти, старте и латентности: **самая низкая p50 и p99 среди всех пяти ядер** при 4.2 MiB вместо 25–41 MiB.

### Мульти-протокольный бенчмарк (замер от 14.10.2026)

**36 побед из 39 протоколов (39/39 в статусе `OK`), 3 паритета, 0 поражений.** Скорость (1 стрим / 8 стримов), Gbit/s:

| Протокол | Tachyon | Sing-box | Xray | Mihomo | Steer | Преимущество |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Shadowsocks AES-128-GCM** | **6.95 / 16.60** | 2.59 / 4.79 | 5.71 / 11.17 | 2.49 / 5.03 | 0.01 / 0.11 | **в ~3.5×** |
| **AnyTLS (H2MUX TLS)** | **6.16 / 14.86** | 5.52 / 10.95 | — | — | — | **в ~1.4×** |
| **Mieru (TCP / UDP)** | **6.46 / 13.01** | — | — | 5.20 / 5.71 | — | **в ~2.3×** (клиент + сервер) |
| **VMess + HTTP/2 + TLS** | **2.48 / 11.31** | 1.58 / 2.09 | — | 1.21 / 3.06 | — | **в ~5.4×** |
| **VLESS + HTTP/2 + TLS** | **2.38 / 10.51** | 1.45 / 2.04 | — | 1.46 / 7.52 | — | **в ~5.2×** |
| **NaiveProxy (HTTP/2 TLS)** | **2.80 / 10.47** | 2.49 / 2.41 | — | — | — | **в ~4.3×** |
| **Trojan + gRPC + TLS** | **2.80 / 10.45** | 1.40 / 1.92 | 1.55 / 2.47 | 1.45 / 2.23 | 1.63 / 2.09 | **в ~5.4×** |
| **VLESS + gRPC + TLS** | **2.78 / 9.99** | 1.74 / 2.22 | 1.68 / 2.62 | 1.54 / 2.06 | 1.75 / 2.16 | **в ~4.5×** |
| **VLESS + XHTTP + TLS** | **1.36 / 9.33** | 1.08 / 9.14 | 0.99 / 2.38 | — | 1.21 / 1.57 | **p50 в ~73× ниже** (`408 µs`) |
| **VMess + WS + TLS** | **3.47 / 7.87** | 3.18 / 6.55 | 2.07 / 4.28 | 2.16 / 4.45 | 2.85 / 2.91 | **в ~1.2–1.8×** |
| **TUIC v5 (QUIC)** | **4.03 / 7.64** | 3.52 / 2.76 | — | 3.08 / 2.72 | — | **в ~2.8×** |
| **Hysteria 2 (QUIC)** | **3.30 / 6.84** | 2.59 / 3.21 | — | 3.19 / 3.88 | 1.22 / 0.55 | **в ~2.1×** |
| **VLESS + TLS + Vision** | **3.23 / 7.22** | 3.31 / 6.78 | 2.26 / 5.63 | 3.24 / 6.98 | 3.91 / 4.36 | **лидер на 8s** (`7.1M` RSS) |
| **ShadowTLS v3** | **48.47 / 45.53** | — | — | — | — | **zero-copy splice** (`5.8M` RSS) |
| **VLESS (Plain)** | **25.31 / 30.97** | 25.25 / 30.89 | 8.66 / 16.90 | — | 4.24 / 5.27 | **лидер** (`5.4M` против `42.4M` RSS) |

> **Прямое преимущество №4 — HTTP/2, gRPC и QUIC.** На мультиплексированных транспортах (`HTTP/2`, `gRPC`, `NaiveProxy`, `Hysteria2`, `TUIC v5`) отрыв достигает **2.1–5.4×** по пропускной способности при кратно меньшем потреблении памяти (7–22 MiB на QUIC/TLS против 48–55 MiB у Go-ядер).
>
> **Прямое преимущество №5 — XHTTP.** Встроенный пул соединений `H2Pool` (XMUX) убирает повторные TLS-рукопожатия на каждый запрос в режимах `packet-up` и `stream-up`. Задержка первого байта: **408 µs против ~29 800 µs** у Go-ядер — **в ~73 раза быстрее**, скорость на 8 потоках — **9.33 Gbit/s**.
>
> Полная таблица из 39 протоколов с задержками p50/p99 и пиковым RSS: **[BENCHMARK.md](BENCHMARK.md)** и **[BENCHMARK.html](BENCHMARK.html)**.

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 🌐 Возможности ядра

<div align="center">

![Tachyon Core Architecture](assets/readme/architecture.svg)

</div>

**Инбаунды (клиентские и серверные).** Прозрачный перехват трафика: Linux **TProxy** (IPv4/IPv6) через `IP_TRANSPARENT` с извлечением реального адреса через OOB `IP_RECVORIGDSTADDR`; **Redirect** (NAT) через `SO_ORIGINAL_DST`; **Mixed SOCKS/HTTP** с полным CONNECT, SOCKS4/4a/5, UDP ASSOCIATE, 407 и keep-alive; **Direct**; **TUN** (`/dev/net/tun`, userspace-стек TCP на `smoltcp` с адаптивным окном `TACHYON_SMOL_TCP_BUF`, GSO-сегментация, policy routing в отдельной таблице 2022). Полный серверный стек (**12 протоколов**): **VLESS**, **Trojan**, **VMess** (AEAD), **Shadowsocks** (AEAD, 2022, multi-user relay), **AnyTLS**, **Naive**, **Hysteria2** (полная совместимость с клиентами hy2, заголовки `Hysteria-CC-RX`/`Hysteria-Padding`, UDP-сессии), **TUIC v5**, **ShadowTLS v3**, **MASQUE** (RFC 9484 CONNECT-IP over HTTP/3), **Mieru** (TCP/UDP), **AmneziaWG / WireGuard** responder и **FPTN** — с собственным TLS 1.3 на чистом Rust.

Схема всех полей — **[docs/reference/](docs/reference/README.md)**: типы инбаундов и аутбаундов, общие блоки (listen, dialer, TLS, транспорты, мультиплексирование), значения по умолчанию и ограничения.

**Аутбаунды.** `direct`, `block`, `socks`, `http`. **Shadowsocks** (все AEAD-шифры, спецификация 2022, UoT, TLS-транспорт). **VLESS** (`flow: xtls-rprx-vision`, все `packet_encoding`, `h2mux`, uTLS). **VMess** (AEAD и legacy, `h2mux`). **Trojan** (SHA224). **Hysteria2** (движок на `quinn`, алгоритмы BBR и Cubic, `routing_mark`/`bind_interface`). **TUIC v5** (с автоматическим выселением неактивных UDP-сессий). **AnyTLS**. **Naive** (HTTP/2 и HTTP/3, `Padding`, `-connect-authority`, блоки `[len:u16][pad:u8]`). **Snell v4/v6**. **ShadowTLS v3**. **MASQUE (WARP)**. **Mieru** (TCP и UDP). **FPTN**. **Tor**, **SSH**, **Desync** (сегментация TCP-потока), **Chain** (`detour`-цепочки). Диспетчеризация: `urltest` и `selector` (`round_robin`, `least_test`, `least_ping`).

**Эндпоинты туннелей.** **AmneziaWG 2.0/3.x** и **WireGuard** — многопоточный пул воркеров `WgPool` с хешированием потоков (5-tuple) без блокировок, расширенными параметрами заголовков сессии (`jc`, `jmin`, `jmax`, `s1–s4`, `h1–h4`) и генератором пакетов инициализации `i1–i5`. **Tailscale** (`tsnet` endpoint). **OpenVPN-клиент**: `static_key` поверх UDP и TCP, сжатие и фрагментация.

**Транспортный уровень и криптография.** TCP, WebSocket (`max_early_data`), HTTPUpgrade, gRPC, HTTP/2, QUIC/HTTP-3. **XHTTP**: HTTP/1.1 chunked, `stream-up`, `packet-up`, `stream-one` и пул `H2Pool` (XMUX) с мультиплексированием HTTP/2-потоков, балансировкой least-loaded и расширенными окнами потока (16 MiB stream / 64 MiB connection). **Pure-Rust uTLS**: 13 байт-точных профилей TLS ClientHello и настраиваемый шаблон рукопожатий. **Pure-Rust REALITY** со сквозным `splice`, поддержкой сертификатов X.509v1 и проверкой `PinVerifier`. **Постквантовая криптография**: гибридный обмен ключами ML-KEM-768 (`X25519MLKEM768`).

**Адаптивный аппаратный движок (`HardwareProfile`).** При старте ядро автоматически определяет объём ОЗУ и число ядер CPU, выбирая один из 4 аппаратных профилей (`Constrained ≤128 MB`, `Router 129–512 MB`, `Midrange 513–2048 MB`, `DesktopServer >2048 MB`), а в рантайме отслеживает `/proc/meminfo` (`MemAvailable`) и лимиты `cgroup`. На лету масштабируются число воркеров Tokio, размеры буферов `splice` и TCP/UDP-релея, окна потоков и соединений HTTP/2 и QUIC (`Hysteria2`, `TUIC`, `MASQUE`), лимиты таблиц UDP NAT, ёмкость кэша DNS и буферы `smoltcp`.

**Smart DNS.** `udp`, `tcp`, `tls` (DoT), `https` (DoH), `quic` (DoQ), `h3` (DoH3), `fakeip`, `local`, `hosts` (файл и инлайн), `mdns`. DNS-группы (`group`) со стратегиями `stable` / `fastest` / `parallel` на скользящей статистике и аварийным режимом. `dns.reverse_mapping` для правил по домену к обращениям по IP. `dns.client_subnet` (EDNS0). LRU-кэш на `Arc<str>` с оптимистичной отдачей устаревших записей и пул FakeIP `198.18.0.0/15`.

**Роутер и инспекция.** Матчеры правил: `inbound`, `network`, `protocol`, домен (suffix, keyword, regex, exact), `ip_cidr`, `ip_is_private`, `source_*`, `port`, `port_range`, `process_name`, `process_path`, `process_path_regex`, `user`, `user_id` (через `/proc/net/*` и дескрипторы сокетов), `clash_mode`, `rule_set`, `rule_set_ipcidr_match_source`. Таблица соседей и DHCP (`find_neighbor`) для `source_mac_address` и `source_hostname`. Сниффер PeekStream: TLS SNI, HTTP Host, QUIC SNI, DNS, BitTorrent, SSH, RDP — без потери начальных байт. Бинарные правила SRS v5: компиляция, декомпиляция, проверка совпадений и удалённая синхронизация списков.

**Системный диалер.** Netns с дочерним процессом-держателем `CLONE_NEWNET` и бесконфликтным dial. `protect_path` — передача дескрипторов сокетов демонам через `SCM_RIGHTS`. Multipath TCP, Happy Eyeballs RFC 6555, fwmark (`routing_mark`), привязка к интерфейсу (`bind_interface`), неблокирующий `connect` с контролем таймаута и защита от шторма пакетов при сбросе соединений.

**API и состояние.** Clash REST API: `/version`, `/proxies`, `/connections`, `/rules`, `/configs`, `/logs`, `/traffic`, `/providers/*`, корректная обработка URL-кодированных слэшей (`%2F`) в именах прокси и групп, WebSocket-трафик, secret-токен, CORS, `clash_mode` и встроенная раздача панелей Yacd / Metacubexd по `/ui`. Файл `cache.db` — B+tree на чистом Rust, побайтово совместимый с форматом bbolt. Встроенный NTP-клиент и реестр HTTP-клиентов `http_clients`.

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 🧭 Командный интерфейс (CLI) и обратная совместимость

<div align="center">

![Tachyon Core CLI Showcase](assets/readme/cli_showcase.svg)

</div>

```bash
tachyon-core check -c /etc/sing-box/config.json                    # проверка конфигурации
tachyon-core version                                              # вывод версии ядра
tachyon-core run -c /etc/sing-box/config.json                     # запуск службы
tachyon-core rule-set compile rules.json -o rules.srs            # компиляция правил SRS v5
tachyon-core generate reality-keypair                             # генерация ключей X25519 для REALITY
tachyon-core generate wg-keypair                                  # генерация ключей WireGuard / AmneziaWG
tachyon-core generate tls-keypair example.com -m 12               # самоподписанный сертификат ECDSA P-256 (PEM)
```

| Команда | Назначение | Статус |
|---|---|:---:|
| `check -c <path>` | Предстартовая проверка конфига в `watchdog.uc` | **Готово** |
| `version` | Определение версии в `generator.uc` | **Готово** |
| `run -c <path>` | Запуск рабочего процесса службы | **Готово** |
| `format -c <path>` / `merge` | Форматирование и слияние JSON-конфигов | **Готово** |
| `rule-set compile\|decompile\|upgrade` | Бинарные правила `.srs` (SRS v5) и обновление списков | **Готово** |
| `rule-set match\|format` | Проверка правил и форматирование | **Готово** |
| `api` | Управление и мониторинг через Clash API | **Готово** |
| `generate reality-keypair` | Ключи X25519 для REALITY | **Готово** |
| `generate wg-keypair` | Ключи WireGuard / AmneziaWG | **Готово** |
| `generate tls-keypair <sni> [-m <months>]` | Генерация TLS-сертификата и ключа ECDSA P-256 на чистом Rust | **Готово** |
| `generate uuid` / `generate rand` | Генерация UUID v4 и случайных ключей (`--hex` / `--base64`) | **Готово** |
| `tools synech` / `tools fptn-decode` | Генерация ECH ConfigList и декодер токенов FPTN | **Готово** |

> Обратная совместимость со сторонним JSON-форматом конфигурации — **временная мера для плавной миграции**, см. дорожную карту ниже.

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 📦 Релизные сборки и установка

> [!NOTE]
> **Только готовые билды с версии `0.1.3`:** этот публичный репозиторий служит официальным каналом доставки релизных бинарников `tachyon-core`. Исходный код хранится и собирается в закрытом приватном репозитории, откуда сборки автоматически публикуются сюда через GitHub Actions вместе с `SHA256SUMS`.

Готовые статические сборки без внешних зависимостей (`musl`, `strip = "symbols"`) доступны в разделе **[Releases](https://github.com/Dushnilin/tachyon-core/releases/latest)** под все популярные роутерные и серверные платформы:

| Архитектура (Ассет) | Таргет | Целевые устройства | Размер архива |
|---|---|---|:---:|
| **`aarch64`** | `aarch64-unknown-linux-musl` | MediaTek Filogic 820/830/880, Flint 2, NanoPi R3S/R4S/R6S, IPQ807x/60xx/50xx, RPi 4/5 | **~3.7 MiB** |
| **`armv7`** | `armv7-unknown-linux-musleabihf` | Qualcomm IPQ4019, MediaTek MT7622/MT7623, Marvell Armada 385, Keenetic Hopper/Peak | **~3.8 MiB** |
| **`armv6`** | `arm-unknown-linux-musleabi` | Raspberry Pi Zero / 1, Broadcom BCM2835 | **~3.9 MiB** |
| **`mipsel`** | `mipsel-unknown-linux-musl` (`+soft-float`) | MediaTek MT7621, MT7628, Ralink RT305x/RT5350, Keenetic Extra/Viva/Giga/Speedster | **~4.2 MiB** |
| **`mips`** | `mips-unknown-linux-musl` (`+soft-float`) | Qualcomm Atheros AR71xx / AR934x / QCA95xx (`ath79` Big-Endian) | **~4.2 MiB** |
| **`riscv64`** | `riscv64gc-unknown-linux-musl` | StarFive VisionFive 2, Milk-V, SiFive | **~3.9 MiB** |
| **`x86_64` / `linux-amd64`** | `x86_64-unknown-linux-musl` | Мини-ПК (Intel N100/N5105), Proxmox, x86 OpenWrt, VPS и выделенные серверы | **~3.9 MiB** |
| **`windows-amd64`** | `x86_64-pc-windows-msvc` | Настольные системы и серверы Windows x64 | **~3.4 MiB** |
| **`darwin-arm64` / `amd64`** | `aarch64` / `x86_64-apple-darwin` | macOS (Apple Silicon M1–M4 и Intel) | **~3.2–3.5 MiB** |

Быстрая установка или обновление на роутере OpenWrt (или Linux-сервере):

```bash
# Пример для ARM64 (aarch64): скачивание, распаковка и установка
ARCH="aarch64"
VER="v0.1.3"
wget -O /tmp/tachyon-core.tar.gz "https://github.com/Dushnilin/tachyon-core/releases/download/${VER}/tachyon-core-${ARCH}-${VER}.tar.gz"
tar -xzf /tmp/tachyon-core.tar.gz -C /usr/bin/
mv -f "/usr/bin/tachyon-core-${ARCH}-${VER}" /usr/bin/tachyon-core
chmod +x /usr/bin/tachyon-core
/usr/bin/tachyon-core version
```

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 🗺️ Дорожная карта

| Фаза | Область | Статус |
|:---:|---|:---:|
| **F0** | Фундамент: валидатор схемы конфигурации `check` и CLI `version` (247/0 тестов) | **Завершено** |
| **F1** | Data Plane v1: инбаунды tproxy/redirect/mixed/direct, аутбаунды socks/ss/vless/trojan/vmess, Smart DNS + FakeIP + LRU, роутер и сниффер | **Завершено** |
| **F2** | Транспортные протоколы: Hysteria2, TUIC, WireGuard + AmneziaWG, XHTTP, uTLS/REALITY, Naive, Snell, AnyTLS, ShadowTLS | **Завершено** |
| **F3** | Правила SRS v5 и удалённые обновления списков | **Завершено** |
| **F4** | Экспериментальный стек: Clash API (Yacd, secret, WebSocket), `cache.db` (bbolt r/w) | **Завершено** |
| **F5** | Серверная часть: все 12 серверных инбаундов (VLESS, Trojan, VMess, SS, Hy2, TUIC, AnyTLS, Naive, ShadowTLS, MASQUE, Mieru, AWG) с собственным TLS 1.3 и UDP | **Завершено** |
| **F6** | TUN-подсистема: userspace-стек на `smoltcp`, TCP-прокси, UDP NAT, routing table 2022 + fwmark, GRO/virtio_net_hdr | **Завершено** |
| **F7** | Системный демон и метрики: совместимость со службой Windows и демоном, расширенная телеметрия | Запланировано |
| **F8** | Мобильные платформы: UniFFI/JNI биндинги | Запланировано |
| **F9** | MIPS softfloat musl: статические сборки `mipsel` и `mips` (`+soft-float`) через `-Zbuild-std` | **Завершено** |
| **F10** | Интеграция в Tachyon + адаптивный движок `HardwareProfile` (4 профиля RAM, 3 уровня давления памяти) и переход на поставку готовых билдов (`v0.1.3+`) | **Завершено** |
| **F11** | **Собственная система конфигурации и хранения данных на флеше** | **Декабрь 2026** |
| **F12** | **Полный переход на нативный формат конфигурации Tachyon** | **1 января 2027** |

### Переход на собственный формат конфигурации

**Декабрь 2026 — родной формат и своё хранилище.** Ядро получает собственный формат конфигурации, спроектированный специально под задачи роутера, и собственное хранилище состояния на флеше (`/etc/tachyon/`) вместо разрозненных файлов и внешних путей. Правила, списки и кэши переезжают в единый компактный формат.

**1 января 2027 — завершение миграции.** Чтобы переход не ломал существующие установки, **автоматическая миграция отдаётся вместе с F11, до 1 января**: при первом запуске новой версии существующий конфиг один раз конвертируется на месте с резервной копией и проверкой результата. После этого ядро работает исключительно со своим родным форматом.

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 📜 Лицензия

Начиная с версии **`v0.1.3`**, программное обеспечение **tachyon-core** распространяется в виде готовых исполняемых сборок на условиях проприетарной лицензии **[TACHYON CORE BINARY LICENSE v1.0](LICENSE)** (`Copyright (c) 2026 Dushnilin. All rights reserved.`).

- Разрешается бесплатная загрузка, установка и использование неизменённых официальных бинарных сборок в личных некоммерческих целях и во внутренней сетевой инфраструктуре.
- **Запрещается** копирование, переупаковка, повторное распространение в составе сторонних прошивок/пакетов, коммерческое использование, продажа, декомпиляция, модификация, создание производных продуктов или удаление уведомлений об авторских правах без предварительного письменного разрешения правообладателя.
- Исторические выпуски до версии `v0.1.2` включительно остаются доступными на условиях лицензии GPL-3.0-only, действовавшей на момент их публикации.

## ⚖️ Правовая информация и отказ от ответственности

1. **Назначение программного обеспечения.** `tachyon-core` является универсальным техническим средством маршрутизации сетевого трафика, балансировки нагрузки, диагностики сетевых соединений, обеспечения информационной безопасности и построения защищённых корпоративных и личных каналов связи (VPN).
2. **Соблюдение законодательства.** Программное обеспечение **не создавалось, не предназначено и не распространяется** для целей нарушения законодательства Российской Федерации (включая ФЗ № 149-ФЗ «Об информации, информационных технологиях и о защите информации») или законодательства любой иной юрисдикции, а равно для неправомерного получения доступа к информационным ресурсам, доступ к которым ограничен в соответствии с законом.
3. **Использование на собственный страх и риск.** Автор и правообладатель не предоставляют никаких прокси/VPN-серверов, узлов связи, подписок, ключей доступа или готовых списков маршрутизации. Программное обеспечение поставляется по принципу «КАК ЕСТЬ» (`AS IS`). Любая установка, настройка и эксплуатация программы осуществляются пользователем исключительно по собственной инициативе, **на свой страх и риск** и под свою полную единоличную ответственность. Правообладатель не несёт ответственности за действия пользователя, выбранные им конфигурации и любые последствия использования программного обеспечения.

<p align="center">
  <img src="assets/readme/footer_tachyon.svg" width="100%" alt="Tachyon Community Footer" />
</p>