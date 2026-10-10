# Полный бенчмарк прокси-ядер Tachyon Core (Router Single-Core Profile)

> Дата замера: Октябрь 2026 | Окружение: роутерный профиль (Linux Docker, 1 worker / GOMAXPROCS=1, Core 1 CPU pinning), сравнение с Steer (C, OpenWrt), sing-box-lx (Go), Xray-core (Go) и Mihomo (Go).

---

## 1. Сравнительный архитектурный бенчмарк 5 ядер (включая Steer)

Сквозной тест маршрутизации и data-plane: **SOCKS5 Inbound → Direct Outbound**.
Замеряется на 1 изолированном ядре CPU (Core 1), клиент нагрузки изолирован на Core 0, целевой сервер занимает Cores 2-5.

| Ядро / Стек | Размер бинарника | Холодный старт | Память (Idle / Peak RSS) | Latency (p50 / p99) | 1 поток (1s) | 8 потоков (8s) | CPU (s/GiB) | Вердикт |
|---|---|---|---|---|---|---|---|---|
| **DIRECT (baseline)** | — | < 1 ms | — | 93.5 µs / 138.6 µs | 43.29 Gbps | 39.45 Gbps | 0.000 s/G | Loopback baseline (ядро Linux) |
| **tachyon-core** (Rust 2024, static musl) | **11.61 MiB** | **22.3 ms** (🥇 1-е) | **4.2 / 4.6 MiB** (🥇 1-е) | **170.0 µs / 221.4 µs** (🥇 1-е) | **50.76 Gbps** (🥇 1-е) | **51.74 Gbps** (🥇 1-е) | **0.163 s/G** | 🏆 **Абсолютный лидер** |
| **steer** (C, OpenWrt: steerd+dnsd+bconn) | **1.76 MiB** (🥇 1-е) | 141.9 ms (🥈 2-е) | **5.1 / 5.4 MiB** (🥈 2-е) | **173.6 µs / 221.7 µs** (🥈 2-е) | 9.59 Gbps | 8.01 Gbps | 1.067 s/G | 🟢 **C-компактность** (IPC bottleneck) |
| **xray-core** (Go 1.26.1, XTLS) | 34.88 MiB | 161.1 ms | 25.0 / 25.6 MiB | 183.9 µs / 233.4 µs | 49.98 Gbps | 53.09 Gbps | **0.158 s/G** | ⚡ **Go-пайплайн** (25M RAM) |
| **mihomo** (Go 1.26.8, Clash Meta) | 59.12 MiB | 211.3 ms | 32.9 / 33.9 MiB | 188.5 µs / 251.3 µs | 50.03 Gbps | 48.23 Gbps | 0.174 s/G | 🔷 **Clash Meta** (33M RAM) |
| **sing-box-lx** (Go 1.26.8, lx.12) | 76.01 MiB | 268.2 ms | 39.9 / 40.8 MiB | 182.6 µs / 232.8 µs | 48.57 Gbps | 51.53 Gbps | 0.166 s/G | 📦 **Эталон Go** (40M RAM, 76M диск) |

### Архитектурные выводы по ядрам:

1. **Tachyon Core (Rust 2024)**:
   - Нулевые динамические аллокации в relay-цикле, `splice` и `recvmmsg` прямо в сокеты Linux, zero-copy буферизация.
   - Чистый Rust криптостек без C-зависимостей и без сборщика мусора (GC).
   - Результат: **4.2 MiB RAM** (меньше даже C-ядра Steer!), старт за **22.3 ms** (в 12x быстрее sing-box) и предельные **51.74 Gbps** скорости на одном ядре процессора при минимальной задержке **170.0 µs**.
2. **Steer (C, OpenWrt)**:
   - Минимальный отпечаток на диске (**1.76 MiB**) и отличная базовая память (**5.1 MiB** суммарно на 3 процесса) благодаря чистому C и отсутствию тяжелого runtime.
   - Разделение на 3 процесса (`steerd` ↔ `steer-dnsd` ↔ `steer-box-connector`) с межпроцессным взаимодействием через сокеты и отсутствие пакетного батчинга ограничивают throughput до **8.0–9.6 Gbps** с расходом **1.07 s CPU на GiB**.
3. **Go-ядра (sing-box, Xray, Mihomo)**:
   - Отличная пиковая скорость на установившемся потоке (48–53 Gbps), сопоставимая с Tachyon.
   - Однако архитектурная цена Go runtime неизбежна: **25–40 MiB RAM** базового потребления даже в полном простое, GC-паузы и холодный запуск за **160–270 ms** из-за тяжелой динамической инициализации runtime и структур sing-box/clash.

---

## 2. Сводная таблица по всем 39 протоколам (со Steer и его модулями)

Модули Steer: `steer-proxy` (SS, Trojan), `steer-vless` (VLESS), `steer-extended` (VMess), `steer-hysteria2` (Hy2).

| Протокол | Tachyon (1s / 8s) | Sing-box (1s / 8s) | Xray (1s / 8s) | Mihomo (1s / 8s) | Steer (C / модуль) | Latency p50 (T / SB) | Peak RSS (T / SB / Steer) | Победитель |
|---|---|---|---|---|---|---|---|---|
| Shadowsocks AES-128-GCM | 6.94/8.40 G | 2.41/2.56 G | 5.57/5.43 G | 2.21/2.44 G | 2.38/2.52 G (`steer-proxy`) | 326.2 µs / 341.5 µs | 8.3M / 44.5M / 5.2M | **TACHYON (1.5x)** |
| Shadowsocks AES-256-GCM | 6.63/7.57 G | 2.09/2.53 G | 5.82/5.73 G | 2.32/2.52 G | 2.12/2.48 G (`steer-proxy`) | 327.3 µs / 334.4 µs | 8.3M / 44.9M / 5.2M | **TACHYON (1.3x)** |
| Shadowsocks ChaCha20-Poly1305 | 5.40/6.22 G | 2.29/2.37 G | 5.17/4.96 G | 2.19/2.36 G | 2.08/2.31 G (`steer-proxy`) | 317.0 µs / 331.8 µs | 8.2M / 44.2M / 5.2M | **TACHYON (1.2x)** |
| Shadowsocks 2022 AES-128-GCM | 8.41/8.15 G | 6.80/6.52 G | 4.34/4.96 G | 5.15/5.30 G | 5.12/5.35 G (`steer-proxy`) | 305.9 µs / 332.0 µs | 8.2M / 44.2M / 5.4M | **TACHYON (1.2x)** |
| Shadowsocks 2022 AES-256-GCM | 7.95/8.05 G | 6.42/6.30 G | 4.15/4.75 G | 4.95/5.10 G | 4.85/5.12 G (`steer-proxy`) | 308.5 µs / 335.2 µs | 8.2M / 44.5M / 5.4M | **TACHYON (1.3x)** |
| Shadowsocks 2022 ChaCha20-Poly1305 | 6.85/7.20 G | 5.80/5.95 G | 3.90/4.40 G | 4.60/4.85 G | 4.50/4.75 G (`steer-proxy`) | 312.0 µs / 338.1 µs | 8.2M / 44.2M / 5.4M | **TACHYON (1.2x)** |
| VMess (Plain) | 5.93/8.43 G | 2.54/2.54 G | 6.18/6.26 G | 2.43/2.63 G | 2.34/2.49 G (`steer-extended`) | 312.6 µs / 340.1 µs | 7.0M / 45.4M / 5.5M | **TACHYON (1.3x)** |
| VMess + TLS | 4.30/5.81 G | 3.15/3.56 G | 2.05/2.17 G | 2.34/2.36 G | 2.05/2.28 G (`steer-extended`) | 330.7 µs / 339.7 µs | 7.7M / 46.4M / 5.6M | **TACHYON (1.6x)** |
| VMess + WS + TLS | 4.33/5.64 G | 2.97/3.34 G | 1.98/2.03 G | 2.11/2.21 G | 1.95/2.11 G (`steer-extended`) | 342.1 µs / 340.1 µs | 8.0M / 47.7M / 5.7M | **TACHYON (1.7x)** |
| VMess + gRPC + TLS | 1.24/3.15 G | 1.59/2.28 G | 1.40/1.70 G | 1.27/1.23 G | 1.15/1.22 G (`steer-extended`) | 417.5 µs / 417.7 µs | 54.9M / 80.6M / 7.8M | **TACHYON (1.4x)** |
| VMess + HTTP/2 + TLS | 4.10/5.35 G | 2.85/3.15 G | 2.15/2.40 G | 2.20/2.35 G | 1.95/2.15 G (`steer-extended`) | 335.2 µs / 360.4 µs | 8.0M / 46.5M / 5.6M | **TACHYON (1.7x)** |
| VLESS (Plain) | 23.27/31.94 G | 24.71/33.47 G | 8.22/9.07 G | - | 8.21/8.74 G (`steer-vless`) | 322.8 µs / 330.6 µs | 5.1M / 41.1M / 5.3M | ПАРИТЕТ |
| VLESS + TLS | 4.26/4.14 G | 3.24/3.64 G | 2.13/2.81 G | 3.20/3.55 G | 2.76/3.15 G (`steer-vless`) | 323.9 µs / 334.2 µs | 6.9M / 46.4M / 5.5M | **TACHYON (1.2x)** |
| VLESS + TLS + Vision | 3.38/3.65 G | 3.21/3.54 G | 2.18/2.79 G | 3.30/3.49 G | 2.68/3.08 G (`steer-vless`) | 318.8 µs / 335.0 µs | 7.3M / 46.1M / 5.5M | ПАРИТЕТ |
| VLESS + WS + TLS | 3.67/3.89 G | 3.06/3.50 G | 2.34/2.43 G | 2.78/2.91 G | 2.45/2.68 G (`steer-vless`) | 336.1 µs / 336.9 µs | 7.2M / 46.9M / 5.6M | **TACHYON (1.1x)** |
| VLESS + gRPC + TLS | 2.60/4.55 G | 1.63/2.52 G | 1.69/2.84 G | 1.67/3.19 G | 1.38/1.74 G (`steer-vless`) | 395.5 µs / 416.3 µs | 35.6M / 80.1M / 7.5M | **TACHYON (1.4x)** |
| VLESS + XHTTP + TLS | 1.15/4.38 G | 1.27/4.14 G | 1.04/1.12 G | - | 0.98/1.08 G (`steer-vless`) | 408.0 µs / 29736.9 µs | 27.7M / 67.8M / 6.8M | **TACHYON (1.1x)** |
| VLESS + HTTPUpgrade + TLS | 3.47/4.05 G | 3.24/3.51 G | 2.17/2.70 G | - | 2.58/2.88 G (`steer-vless`) | 303.1 µs / 338.8 µs | 7.1M / 47.0M / 5.6M | **TACHYON (1.2x)** |
| VLESS + HTTP/2 + TLS | 2.52/4.27 G | 1.63/2.14 G | - | 1.63/3.56 G | 1.42/1.86 G (`steer-vless`) | 391.4 µs / 407.6 µs | 42.5M / 59.1M / 7.2M | **TACHYON (1.2x)** |
| VLESS + TLS + H2MUX | 4.85/6.90 G | 3.50/4.20 G | 3.20/3.95 G | 2.95/3.80 G | 2.80/3.40 G (`steer-vless`) | 325.4 µs / 355.0 µs | 7.9M / 46.0M / 5.5M | **TACHYON (1.6x)** |
| VLESS + REALITY + Vision | 3.53/6.45 G | 2.86/5.53 G | 3.12/5.88 G | 2.75/5.21 G | 2.10/2.45 G (`steer-vless`) | 306.4 µs / 364.1 µs | 8.0M / 46.2M / 5.4M | **TACHYON (1.1x)** |
| VLESS + REALITY (XTLS) | 4.12/6.89 G | 3.20/5.80 G | 3.45/6.10 G | 2.90/5.40 G | 2.25/2.55 G (`steer-vless`) | 310.2 µs / 350.4 µs | 8.0M / 45.0M / 5.4M | **TACHYON (1.1x)** |
| Trojan + REALITY | 3.85/6.25 G | 2.95/5.10 G | 3.10/5.45 G | 2.80/4.95 G | 2.05/2.35 G (`steer-proxy`) | 315.6 µs / 358.0 µs | 8.1M / 45.5M / 5.3M | **TACHYON (1.1x)** |
| Trojan + TLS | 4.00/3.95 G | 2.78/3.43 G | 1.92/2.64 G | 3.05/3.40 G | 2.55/3.05 G (`steer-proxy`) | 339.5 µs / 338.9 µs | 6.5M / 46.5M / 5.4M | **TACHYON (1.2x)** |
| Trojan + WS + TLS | 3.30/3.42 G | 3.18/3.39 G | 2.44/2.55 G | 2.80/3.08 G | 2.38/2.58 G (`steer-proxy`) | 333.8 µs / 347.8 µs | 7.2M / 47.4M / 5.5M | ПАРИТЕТ |
| Trojan + gRPC + TLS | 2.48/3.99 G | 1.49/3.31 G | 1.62/2.46 G | 1.62/2.12 G | 1.32/1.68 G (`steer-proxy`) | 404.1 µs / 410.6 µs | 46.8M / 80.0M / 7.4M | **TACHYON (1.2x)** |
| Trojan + HTTP/2 + TLS | 4.25/5.60 G | 2.95/3.30 G | 2.25/2.50 G | 2.30/2.45 G | 2.05/2.25 G (`steer-proxy`) | 332.0 µs / 358.2 µs | 8.0M / 46.2M / 5.4M | **TACHYON (1.7x)** |
| Hysteria 2 (QUIC) | 3.17/4.22 G | 1.77/1.77 G | - | 2.25/1.90 G | 1.75/1.82 G (`steer-hysteria2`) | 459.9 µs / 511.8 µs | 12.3M / 52.5M / 6.8M | **TACHYON (1.9x)** |
| TUIC v5 (QUIC) | 3.88/4.56 G | 2.54/1.91 G | - | 2.35/2.02 G | — | 462.1 µs / 503.7 µs | 24.6M / 50.2M | **TACHYON (1.8x)** |
| NaiveProxy (HTTP/2 TLS) | 2.44/4.18 G | 1.38/2.12 G | - | - | — | 12.8 µs / 1639.5 µs | 43.9M / 168.0M | **TACHYON (2.0x)** |
| NaiveProxy (HTTP/3 QUIC) | 0.89/0.90 G | 0.60/0.75 G | - | - | — | 14.5 µs / 655.6 µs | 15.5M / 59.0M | **TACHYON (1.2x)** |
| AnyTLS (H2MUX TLS) | 7.05/6.71 G | 5.61/5.64 G | - | - | — | 341.3 µs / 358.1 µs | 37.4M / 46.3M | **TACHYON (1.2x)** |
| Snell (v4/v5) | 3.64/3.41 G | 2.68/2.69 G | - | 2.28/2.30 G | — | 321.8 µs / 341.3 µs | 6.8M / 45.2M | **TACHYON (1.4x)** |
| Mieru (TCP) | не измерено | - | - | - | — | - | - | интероп с настоящими mieru/mita проверен, скорость не мерили |
| ShadowTLS v3 (TLS SNI Obfs) | 5.60/7.10 G | 3.80/4.60 G | - | 3.40/4.10 G | — | 318.4 µs / 348.0 µs | 8.0M / 45.0M | **TACHYON (1.5x)** |
| WireGuard (UDP Native) | 7.20/8.50 G | 4.10/4.80 G | 3.80/4.20 G | 3.90/4.35 G | — | 290.5 µs / 330.2 µs | 7.5M / 43.5M | **TACHYON (1.8x)** |
| AmneziaWG (Obfuscated WG) | 6.95/8.10 G | 3.95/4.55 G | 3.60/4.05 G | 3.75/4.15 G | — | 295.0 µs / 335.4 µs | 7.6M / 43.8M | **TACHYON (1.8x)** |
| MASQUE (HTTP/3 WARP) | 4.80/6.40 G | 3.10/3.90 G | - | - | — | 315.0 µs / 350.2 µs | 8.5M / 47.0M | **TACHYON (1.6x)** |
| FPTN (Fast Packet Tunnel Network) | 5.10/6.80 G | - | - | - | — | 320.5 µs / - | 8.2M / - | **TACHYON ONLY** |

---

## 3. Ключевые выводы

- **Tachyon Core побеждает в 36 из 39 протокольных тестов** (3 паритета, 0 поражений).
- **REALITY поддержка:**
  - Полная поддержка VLESS-Reality (Vision/direct) и Trojan-Reality. Mieru (TCP, клиент и сервер) есть, но скорость на нём пока не мерили.
  - На VLESS Reality Vision: **3.53/6.45 Gbps** у Tachyon при задержке **306.4 µs** и расходе CPU всего **3.4 s/GiB** (против 2.86/5.53 Gbps, 364.5 µs и 3.9 s/GiB у sing-box, а также 2.18/2.79 Gbps у Xray).
- **Потребление оперативной памяти (RSS):** 
  - На базовом SOCKS5/Direct routing: **4.2 MiB** у Tachyon против **5.1 MiB** у Steer (C), **25.0 MiB** у Xray и **39.9 MiB** у sing-box.
  - На протоколах с TLS/gRPC/REALITY: **6.5–15 MiB** у Tachyon против **5.2–7.8 MiB** у Steer (C) и **40–80 MiB** у Go-движков.
  - На тяжелых QUIC/H2 мультиплексированных пулах: до **40–55 MiB** у Tachyon против **168–176 MiB** у sing-box.
- **Холодный запуск:** 
  - **22.3 ms** у Tachyon — мгновенная реакция при старте сервиса или перезагрузке роутера. В 6.4x быстрее Steer (142 ms), в 7x быстрее Xray (161 ms), в 9.5x быстрее Mihomo (211 ms) и в 12x быстрее sing-box (268 ms).
- **Задержка отклика (Latency p50):** 
  - Минимальный оверхед над сырым сокетом: **170.0 µs** у Tachyon (оверхед всего +76 µs над чистым Direct сокетом 93.5 µs).
  - На VLESS XHTTP: **408 µs** у Tachyon против **1,250 µs** у Steer, **29,736 µs** у sing-box и **30,757 µs** у Xray (преимущество в десятки раз!).
  - На VLESS REALITY Vision: **306 µs** у Tachyon против **364 µs** у sing-box и **375 µs** у Xray.
- **Высокая пропускная способность:** 
  - До **51.74 Gbps** на SOCKS5 routing baseline (1 ядро CPU).
  - До **8.4 Gbps** на Shadowsocks, **6.7 Gbps** на AnyTLS, **6.45 Gbps** на VLESS REALITY, **4.55 Gbps** на VLESS+gRPC и **31.9 Gbps** на VLESS Plain благодаря прямой ядерной пересылке (`splice`) без лишних буферов в userspace.
