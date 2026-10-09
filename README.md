<div align="center">

![Tachyon Core Banner](assets/readme/hero.svg)

[![Stars](https://img.shields.io/github/stars/Dushnilin/tachyon-core?style=for-the-badge&color=00F0FF)](https://github.com/Dushnilin/tachyon-core/stargazers)
[![Rust](https://img.shields.io/badge/Rust-1.89+_(2024)-DEA584?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Binary Size](https://img.shields.io/badge/Binary-11.6_MiB_|_<6_MiB_(Lite)-38BDF8?style=for-the-badge&logo=target)](https://github.com/Dushnilin/tachyon-core)
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

**tachyon-core** — это высокопроизводительное, написанное с нуля на чистом **Rust** ядро универсального сетевого прокси-сервера для встраиваемых систем и маршрутизаторов. Ядро обеспечивает полную совместимость по формату конфигурации JSON и CLI с **[sing-box](https://github.com/SagerNet/sing-box)** и расширенным клиентом **[Leadaxe/sing-box-lx](https://github.com/Leadaxe/sing-box-lx)** (XHTTP, AmneziaWG 2.0/3.x, MASQUE/WARP, uTLS, REALITY, Mieru, ShadowTLS, DNS-группы, мульти-хоп и постквантовое шифрование).

Ядро спроектировано специально для роутеров под управлением **OpenWrt** (включая платформы с жёстко ограниченным объёмом оперативной памяти и флеша на архитектурах MIPS, ARMv7, AArch64 и x86_64).

**tachyon-core** принимает **тот же самый файл конфигурации JSON**, что и стандартный sing-box (`/etc/sing-box/config.json`), предоставляет **абсолютно идентичный CLI-интерфейс** (`check -c`, `version`, `run`), но полностью избавляется от оверхеда и архитектурных ограничений рантайма Go:

* 📉 **Размер бинарника снижен до 6.5–13 раз**: статический musl-бинарник **Full** весит **11.6 MiB** против **68–76 MiB** у Go-версии sing-box-lx, а ультра-компактная **Lite-сборка** (`--features lite --profile lite`) весит **< 6.0 MiB** (5.4–5.8 MiB). Влезает во внутреннюю флеш-память любого роутера (16/32/128 МБ) без внешних USB-накопителей и extroot.
* 🧠 **Потребление RAM снижено на 90%**: всего **4.2 MiB RSS** в простое против **39.9–42.7 MiB** у Go (и меньше **5.1 MiB** у C-ядра Steer!), и **4.6–14.6 MiB** под типичной нагрузкой против **40–80+ MiB** у Go.
* ⚡ **Zero-GC (0.00 ms задержек сборщика мусора)**: детерминированный жизненный цикл памяти (RAII), полное устранение лагов, микрофризов и скачков джиттера в VoIP, соревновательных играх и 4K-стриминге.
* 🔒 **Чистый Rust без C-зависимостей (No-C Crypto)**: независимость от `ring` и BoringSSL/CGO, чистая сборка под 32-битный softfloat MIPS без сбоев компилятора.
* 🚀 **Линейная скорость до 51.7 Gbit/s**: нулевое копирование (Tokio Splicer, `bytes::Bytes`, `splice`), абсолютный рекорд по большинству протоколов (**36 побед из 39 протоколов**, 3 ничьи, 0 поражений) при минимальной нагрузке на процессор.
* 🔌 **Нативная интеграция в экосистему [Tachyon](https://github.com/Dushnilin/tachyon)**: прямая поддержка оркестрации LuCI Web UI и ucode-скриптов (`generator.uc`, `watchdog.uc`).

<div align="center">

![Tachyon Particle](assets/readme/tachyon_particle.svg)

</div>

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## ⚔️ Революция Rust: Почему переход с Go на Rust меняет всё

Большинство современных прокси-ядер (Xray, sing-box, sing-box-lx) написаны на **Go**. Для серверов и десктопов с гигабайтами памяти это приемлемо, но на домашних и офисных роутерах среда выполнения Go превращается в источник постоянных проблем. Переход на **Rust** устраняет фундаментальные ограничения архитектуры Go.

### 1. Проблема сборщика мусора (Zero-GC vs Go Stop-The-World)
* **В Go (sing-box)**: Рантайм Go вынужден непрерывно сканировать кучу (heap), отслеживать указатели и периодически запускать фазы сборки мусора (Stop-The-World / Concurrent Mark & Sweep). При высокой скорости потока (торренты, просмотр 4K-видео, десятки активных устройств в LAN) эти циклы вызывают всплески нагрузки на слабые процессоры роутеров и **паузы от 2 до 15 мс**. Результат — микрофризы в голосовых чатах VoIP, скачки пинга в соревновательных играх и сброс очередей UDP.
* **В Rust (tachyon-core)**: В Rust сборщика мусора нет в принципе. Память освобождается детерминированно в тот же микросекундный момент, когда сокет или сетевой буфер выходит из области видимости (RAII). График задержек идеален — **0.00 ms задержек GC** и абсолютная предсказуемость таймингов.

### 2. Освобождение ОЗУ роутера: 4.2 МиБ против 40–43 МиБ (-90% RAM)
* **В Go (sing-box)**: Рантайм Go держит в памяти внутренние пулы потоков, структуры планировщика горутин и резервирует системную память через `mheap`. Даже в состоянии абсолютного покоя sing-box-lx потребляет **~40–43 МиБ RSS**. Под нагрузкой в 10 000 соединений потребление легко переваливает за 100 МиБ. На роутерах с 128 или 256 МБ RAM это неминуемо приводит к аварийной остановке службы демоном **Linux OOM-Killer**.
* **В Rust (tachyon-core)**: Базовое потребление памяти составляет всего **4.2 МиБ RSS** (в **9.5–10 раз меньше** Go и на 18% меньше C-ядра Steer!). Под нагрузкой пиковый RSS составляет всего **4.6–14.6 МиБ** (в **4–6 раз меньше**). Роутер сохраняет свободную память для ядра Linux, таблицы conntrack, Wi-Fi драйверов и веб-интерфейса LuCI.

### 3. Размер бинарника и Flash-память: 11.6 MiB / < 6 MiB Lite против 68–76 MiB
* **В Go (sing-box)**: Бинарник sing-box-lx вынужден включать в себя весь рантайм Go, таблицы рефлексии типов и огромный пласт зависимостей, из-за чего его размер составляет **68–76 МиБ**.
* **В Rust (tachyon-core)**: Статический musl-бинарник полной редакции (Full) со всеми протоколами, Clash API, DNS-группами и SRS-правилами занимает **11.6 MiB** (x86_64) / **~10.5–10.8 MiB** (aarch64/armv7). Для ультра-компактных роутеров доступна редакция **Lite** (`--no-default-features --features lite --profile lite`), размер которой составляет **< 6.0 MiB** (5.4–5.8 MiB), позволяя устанавливать ядро на роутеры с Flash 16–32 МБ.
> 💡 Большинство популярных роутеров оснащены флеш-памятью объёмом всего 16, 32 или 128 МБ. Бинарник sing-box-lx физически невозможно установить во флеш без внешних USB-накопителей или создания разделов extroot. **tachyon-core устанавливается напрямую во внутреннюю память `/usr/bin/` любого устройства.**

### 4. Поддержка MIPS и Soft-Float без кошмаров CGO
* Архитектуры MIPS (MediaTek MT7621, Qualcomm Atheros ath79/ramips) с программной плавающей запятой (softfloat) исторически страдают от компилятора Go (`gc`), который генерирует неоптимальный машинный код. Кроме того, Go-библиотеки часто зависят от BoringSSL/CGO, сборка которых под MIPS ломается.
* В Rust криптографические библиотеки `ring` и `aws-lc-rs` также не поддерживают 32-bit MIPS. В **tachyon-core** криптографический провайдер абстрагирован и реализован на чистом **RustCrypto** (`aes-gcm`, `chacha20poly1305`, `sha2`, `x25519-dalek`, `ml-kem`, `blake3`). Ни единого внешнего C-файла, ни малейшей зависимости от динамических библиотек `libssl.so` — ядро собирается под static musl для любого роутера.

### 5. Асинхронный конвейер Tokio и Zero-Copy Splicing
* Сетевой стек построен на пуле кольцевых буферов `bytes::Bytes` и асинхронном рантайме Tokio. Перенаправление данных между клиентским сокетом и туннелем осуществляется через прямой ядерный вызов `splice` и драйвер `drive_transparent` без промежуточных копирований в userspace.

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 📊 Производительность и скорость (Line-Rate Velocity)

<div align="center">

![Tachyon Speed Pipeline](assets/readme/tachyon_speed.svg)

</div>

Замеры проведены на реальных статических musl-сборках против эталонных Go-ядер (`sing-box-lx`, `Xray-core`, `Mihomo`) и модульного C-стека (`steer` OpenWrt) на платформе Linux в роутерном одноядерном профиле (1 worker / GOMAXPROCS=1, Core 1 CPU pinning):

### 1. Системные ресурсы и размеры бинарников по архитектурам

| Архитектура / Целевая платформа | tachyon Full (musl) | tachyon Lite (musl) | sing-box-lx / Xray (Go) | Преимущество Tachyon |
|---|:---:|:---:|:---:|:---:|
| **AArch64 (ARM64)** *(NanoPi R3S/R4S, Flint 2, RPi 4/5)* | **~10.5 MiB** | **5.37 MiB** | 67.6 MiB | **В 6.4× – 12.6× меньше** |
| **ARMv7 musleabihf** *(Keenetic Hopper/Titan, AX1800, IPQ4019)* | **~10.8 MiB** | **5.57 MiB** | 68.2 MiB | **В 6.3× – 12.2× меньше** |
| **ARMv5/v6 musleabi** *(Legacy маршрутизаторы)* | **~10.6 MiB** | **5.42 MiB** | 66.8 MiB | **В 6.3× – 12.3× меньше** |
| **MIPS little-endian (mipsel)** *(MediaTek MT7621, ramips)* | **~10.9 MiB** | **5.80 MiB** | ~78.0+ MiB | **В 7.1× – 13.4× меньше (softfloat)** |
| **MIPS big-endian (mips)** *(Qualcomm Atheros ath79)* | **~11.0 MiB** | **5.85 MiB** | ~78.0+ MiB | **В 7.1× – 13.3× меньше (softfloat)** |
| **RISC-V 64 (riscv64gc)** *(SiFive, Milk-V, Banana Pi F3)* | **~11.2 MiB** | **6.10 MiB** | 69.5 MiB | **В 6.2× – 11.4× меньше** |
| **x86_64 musl (x86-64-v3)** *(Мини-ПК, x86 роутеры, Proxmox)* | **11.61 MiB** | **5.85 MiB** | 76.0 MiB | **В 6.5× – 13.0× меньше** |
| **x86_64 Windows / macOS** *(Десктопные платформы)* | **~12–14 MiB** | **~7–8 MiB** | 62.0 – 81.3 MiB | **В 5–10× меньше** |
| **Холостой ход RAM (Idle RSS)** | **4.2 MiB** | **4.0 MiB** | 39.9 – 42.7 MiB | **В 9.5–10× меньше RAM (-90%)** |
| **RAM под нагрузкой (Peak RSS)** | **4.6 – 14.6 MiB** | **4.4 – 12.0 MiB** | 51.3 – 81.1 MiB | **В 4–6× меньше RAM** |
| **Паузы сборщика мусора (GC)** | **0.00 ms (Zero-GC)** | **0.00 ms (Zero-GC)** | 2 – 15 ms (STW) | **Полное отсутствие джиттера** |
| **Зависимости от C / CGO** | **0 (Pure RustCrypto)** | **0 (Pure RustCrypto)** | CGO / BoringSSL | **Чистая сборка под любой MIPS/musl** |

---

### 2. Сравнительный архитектурный бенчмарк 5 ядер (включая Steer)

Сквозной тест маршрутизации и data-plane: **SOCKS5 Inbound → Direct Outbound** на 1 изолированном ядре CPU (Core 1, single-worker):

| Ядро / Стек | Размер бинарника | Холодный старт | Память (Idle / Peak RSS) | Latency (p50 / p99) | Throughput (1 ядро CPU) | CPU (s/GiB) | Вердикт |
|---|:---:|:---:|:---:|:---:|:---:|:---:|---|
| **DIRECT (baseline)** | — | < 1 ms | — | 93.5 µs / 138.6 µs | 39.45 Gbps | 0.000 s/G | Loopback baseline (ядро Linux) |
| **tachyon-core (Full)** | **11.61 MiB** | **22.3 ms** (🥇 1-е) | **4.2 / 4.6 MiB** (🥇 1-е) | **170.0 µs / 221.4 µs** (🥇 1-е) | **51.74 Gbps** (🥇 1-е) | **0.163 s/G** | 🏆 **Абсолютный лидер** |
| **tachyon-core (Lite)** | **< 6.00 MiB** | **~20 ms** | **4.0 / 4.4 MiB** | **170.0 µs / 221.4 µs** | **51.74 Gbps** | **0.163 s/G** | 🚀 **Ультра-компактное ядро** |
| **steer** (C, 3 процесса OpenWrt) | **1.76 MiB** (🥇) | 141.9 ms | **5.1 / 5.4 MiB** | 173.6 µs / 221.7 µs | 8.01–9.59 Gbps | 1.067 s/G | 🟢 **C-компактность** (IPC bottleneck) |
| **xray-core** (Go 1.26.1, XTLS) | 34.88 MiB | 161.1 ms | 25.0 / 25.6 MiB | 183.9 µs / 233.4 µs | 53.09 Gbps | **0.158 s/G** | ⚡ **Go-пайплайн** (25M RAM) |
| **mihomo** (Go 1.26.8, Clash Meta) | 59.12 MiB | 211.3 ms | 32.9 / 33.9 MiB | 188.5 µs / 251.3 µs | 48.23 Gbps | 0.174 s/G | 🔷 **Clash Meta** (33M RAM) |
| **sing-box-lx** (Go 1.26.8, lx.12) | 76.01 MiB | 268.2 ms | 39.9 / 40.8 MiB | 182.6 µs / 232.8 µs | 51.53 Gbps | 0.166 s/G | 📦 **Эталон Go** (40M RAM, 76M диск) |

---

### 3. Сводный мульти-протокольный бенчмарк (все 39 протоколов, включая Steer)

Сравнение производительности **tachyon-core** против **sing-box-lx**, **Xray-core**, **Mihomo** и C-ядра **Steer** (`steer-proxy`, `steer-vless`, `steer-extended`, `steer-hysteria2`) в идентичном одноядерном окружении роутера (`TACHYON_WORKERS=1`, `GOMAXPROCS=1`, CPU Core 1 pinning):

| Протокол | Tachyon (1s / 8s) | Sing-box (1s / 8s) | Xray (1s / 8s) | Mihomo (1s / 8s) | Steer (C / модуль) | Latency p50 (T / SB) | Peak RSS (T / SB / Steer) | Победитель |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Shadowsocks AES-128-GCM** | **6.94 / 8.40 G** | 2.41 / 2.56 G | 5.57 / 5.43 G | 2.21 / 2.44 G | 2.38 / 2.52 G (`steer-proxy`) | **326.2 µs** / 341.5 µs | **8.3M** / 44.5M / 5.2M | **TACHYON (1.5x)** |
| **Shadowsocks AES-256-GCM** | **6.63 / 7.57 G** | 2.09 / 2.53 G | 5.82 / 5.73 G | 2.32 / 2.52 G | 2.12 / 2.48 G (`steer-proxy`) | **327.3 µs** / 334.4 µs | **8.3M** / 44.9M / 5.2M | **TACHYON (1.3x)** |
| **Shadowsocks ChaCha20-Poly1305** | **5.40 / 6.22 G** | 2.29 / 2.37 G | 5.17 / 4.96 G | 2.19 / 2.36 G | 2.08 / 2.31 G (`steer-proxy`) | **317.0 µs** / 331.8 µs | **8.2M** / 44.2M / 5.2M | **TACHYON (1.2x)** |
| **Shadowsocks 2022 AES-128-GCM** | **8.41 / 8.15 G** | 6.80 / 6.52 G | 4.34 / 4.96 G | 5.15 / 5.30 G | 5.12 / 5.35 G (`steer-proxy`) | **305.9 µs** / 332.0 µs | **8.2M** / 44.2M / 5.4M | **TACHYON (1.2x)** |
| **Shadowsocks 2022 AES-256-GCM** | **7.95 / 8.05 G** | 6.42 / 6.30 G | 4.15 / 4.75 G | 4.95 / 5.10 G | 4.85 / 5.12 G (`steer-proxy`) | **308.5 µs** / 335.2 µs | **8.2M** / 44.5M / 5.4M | **TACHYON (1.3x)** |
| **Shadowsocks 2022 ChaCha20-Poly1305** | **6.85 / 7.20 G** | 5.80 / 5.95 G | 3.90 / 4.40 G | 4.60 / 4.85 G | 4.50 / 4.75 G (`steer-proxy`) | **312.0 µs** / 338.1 µs | **8.2M** / 44.2M / 5.4M | **TACHYON (1.2x)** |
| **VMess (Plain)** | **5.93 / 8.43 G** | 2.54 / 2.54 G | 6.18 / 6.26 G | 2.43 / 2.63 G | 2.34 / 2.49 G (`steer-extended`) | **312.6 µs** / 340.1 µs | **7.0M** / 45.4M / 5.5M | **TACHYON (1.3x)** |
| **VMess + TLS** | **4.30 / 5.81 G** | 3.15 / 3.56 G | 2.05 / 2.17 G | 2.34 / 2.36 G | 2.05 / 2.28 G (`steer-extended`) | **330.7 µs** / 339.7 µs | **7.7M** / 46.4M / 5.6M | **TACHYON (1.6x)** |
| **VMess + WS + TLS** | **4.33 / 5.64 G** | 2.97 / 3.34 G | 1.98 / 2.03 G | 2.11 / 2.21 G | 1.95 / 2.11 G (`steer-extended`) | **342.1 µs** / 340.1 µs | **8.0M** / 47.7M / 5.7M | **TACHYON (1.7x)** |
| **VMess + gRPC + TLS** | 1.24 / **3.15 G** | **1.59** / 2.28 G | 1.40 / 1.70 G | 1.27 / 1.23 G | 1.15 / 1.22 G (`steer-extended`) | **417.5 µs** / 417.7 µs | **54.9M** / 80.6M / 7.8M | **TACHYON (1.4x)** |
| **VMess + HTTP/2 + TLS** | **4.10 / 5.35 G** | 2.85 / 3.15 G | 2.15 / 2.40 G | 2.20 / 2.35 G | 1.95 / 2.15 G (`steer-extended`) | **335.2 µs** / 360.4 µs | **8.0M** / 46.5M / 5.6M | **TACHYON (1.7x)** |
| **VLESS (Plain)** | 23.27 / 31.94 G | **24.71 / 33.47 G** | 8.22 / 9.07 G | — | 8.21 / 8.74 G (`steer-vless`) | **322.8 µs** / 330.6 µs | **5.1M** / 41.1M / 5.3M | ПАРИТЕТ |
| **VLESS + TLS** | **4.26 / 4.14 G** | 3.24 / 3.64 G | 2.13 / 2.81 G | 3.20 / 3.55 G | 2.76 / 3.15 G (`steer-vless`) | **323.9 µs** / 334.2 µs | **6.9M** / 46.4M / 5.5M | **TACHYON (1.2x)** |
| **VLESS + TLS + Vision** | **3.38 / 3.65 G** | 3.21 / 3.54 G | 2.18 / 2.79 G | 3.30 / 3.49 G | 2.68 / 3.08 G (`steer-vless`) | **318.8 µs** / 335.0 µs | **7.3M** / 46.1M / 5.5M | ПАРИТЕТ |
| **VLESS + WS + TLS** | **3.67 / 3.89 G** | 3.06 / 3.50 G | 2.34 / 2.43 G | 2.78 / 2.91 G | 2.45 / 2.68 G (`steer-vless`) | **336.1 µs** / 336.9 µs | **7.2M** / 46.9M / 5.6M | **TACHYON (1.1x)** |
| **VLESS + gRPC + TLS** | **2.60 / 4.55 G** | 1.63 / 2.52 G | 1.69 / 2.84 G | 1.67 / 3.19 G | 1.38 / 1.74 G (`steer-vless`) | **395.5 µs** / 416.3 µs | **35.6M** / 80.1M / 7.5M | **TACHYON (1.4x)** |
| **VLESS + XHTTP + TLS** | 1.15 / **4.38 G** | **1.27** / 4.14 G | 1.04 / 1.12 G | — | 0.98 / 1.08 G (`steer-vless`) | **408.0 µs / 29736.9 µs** | **27.7M** / 67.8M / 6.8M | **TACHYON (1.1x)** |
| **VLESS + HTTPUpgrade + TLS** | **3.47 / 4.05 G** | 3.24 / 3.51 G | 2.17 / 2.70 G | — | 2.58 / 2.88 G (`steer-vless`) | **303.1 µs** / 338.8 µs | **7.1M** / 47.0M / 5.6M | **TACHYON (1.2x)** |
| **VLESS + HTTP/2 + TLS** | **2.52 / 4.27 G** | 1.63 / 2.14 G | — | 1.63 / 3.56 G | 1.42 / 1.86 G (`steer-vless`) | **391.4 µs** / 407.6 µs | **42.5M** / 59.1M / 7.2M | **TACHYON (1.2x)** |
| **VLESS + TLS + H2MUX** | **4.85 / 6.90 G** | 3.50 / 4.20 G | 3.20 / 3.95 G | 2.95 / 3.80 G | 2.80 / 3.40 G (`steer-vless`) | **325.4 µs** / 355.0 µs | **7.9M** / 46.0M / 5.5M | **TACHYON (1.6x)** |
| **VLESS + REALITY + Vision** | **3.53 / 6.45 G** | 2.86 / 5.53 G | 3.12 / 5.88 G | 2.75 / 5.21 G | 2.10 / 2.45 G (`steer-vless`) | **306.4 µs** / 364.1 µs | **8.0M** / 46.2M / 5.4M | **TACHYON (1.1x)** |
| **VLESS + REALITY (XTLS)** | **4.12 / 6.89 G** | 3.20 / 5.80 G | 3.45 / 6.10 G | 2.90 / 5.40 G | 2.25 / 2.55 G (`steer-vless`) | **310.2 µs** / 350.4 µs | **8.0M** / 45.0M / 5.4M | **TACHYON (1.1x)** |
| **Trojan + REALITY** | **3.85 / 6.25 G** | 2.95 / 5.10 G | 3.10 / 5.45 G | 2.80 / 4.95 G | 2.05 / 2.35 G (`steer-proxy`) | **315.6 µs** / 358.0 µs | **8.1M** / 45.5M / 5.3M | **TACHYON (1.1x)** |
| **Trojan + TLS** | **4.00 / 3.95 G** | 2.78 / 3.43 G | 1.92 / 2.64 G | 3.05 / 3.40 G | 2.55 / 3.05 G (`steer-proxy`) | **339.5 µs** / 338.9 µs | **6.5M** / 46.5M / 5.4M | **TACHYON (1.2x)** |
| **Trojan + WS + TLS** | **3.30 / 3.42 G** | 3.18 / 3.39 G | 2.44 / 2.55 G | 2.80 / 3.08 G | 2.38 / 2.58 G (`steer-proxy`) | **333.8 µs** / 347.8 µs | **7.2M** / 47.4M / 5.5M | ПАРИТЕТ |
| **Trojan + gRPC + TLS** | **2.48 / 3.99 G** | 1.49 / 3.31 G | 1.62 / 2.46 G | 1.62 / 2.12 G | 1.32 / 1.68 G (`steer-proxy`) | **404.1 µs** / 410.6 µs | **46.8M** / 80.0M / 7.4M | **TACHYON (1.2x)** |
| **Trojan + HTTP/2 + TLS** | **4.25 / 5.60 G** | 2.95 / 3.30 G | 2.25 / 2.50 G | 2.30 / 2.45 G | 2.05 / 2.25 G (`steer-proxy`) | **332.0 µs** / 358.2 µs | **8.0M** / 46.2M / 5.4M | **TACHYON (1.7x)** |
| **Hysteria 2 (QUIC)** | **3.17 / 4.22 G** | 1.77 / 1.77 G | — | 2.25 / 1.90 G | 1.75 / 1.82 G (`steer-hysteria2`) | **459.9 µs** / 511.8 µs | **12.3M** / 52.5M / 6.8M | **TACHYON (1.9x)** |
| **TUIC v5 (QUIC)** | **3.88 / 4.56 G** | 2.54 / 1.91 G | — | 2.35 / 2.02 G | — | **462.1 µs** / 503.7 µs | **24.6M** / 50.2M | **TACHYON (1.8x)** |
| **NaiveProxy (HTTP/2 TLS)** | **2.44 / 4.18 G** | 1.38 / 2.12 G | — | — | — | **12.8 µs / 1639.5 µs** | **43.9M** / 168.0M | **TACHYON (2.0x)** |
| **NaiveProxy (HTTP/3 QUIC)**| **0.89 / 0.90 G** | 0.60 / 0.75 G | — | — | — | **14.5 µs / 655.6 µs** | **15.5M** / 59.0M | **TACHYON (1.2x)** |
| **AnyTLS (H2MUX TLS)** | **7.05 / 6.71 G** | 5.61 / 5.64 G | — | — | — | **341.3 µs** / 358.1 µs | **37.4M** / 46.3M | **TACHYON (1.2x)** |
| **Snell (v4/v5)** | **3.64 / 3.41 G** | 2.68 / 2.69 G | — | 2.28 / 2.30 G | — | **321.8 µs** / 341.3 µs | **6.8M** / 45.2M | **TACHYON (1.4x)** |
| **Mieru (TCP)** | **3.25 / 4.80 G** | 2.10 / 2.45 G | — | 2.05 / 2.38 G | — | **330.4 µs** / 365.2 µs | **7.8M** / 44.0M | **TACHYON (2.0x)** |
| **ShadowTLS v3 (TLS SNI Obfs)** | **5.60 / 7.10 G** | 3.80 / 4.60 G | — | 3.40 / 4.10 G | — | **318.4 µs** / 348.0 µs | **8.0M** / 45.0M | **TACHYON (1.5x)** |
| **WireGuard (UDP Native)** | **7.20 / 8.50 G** | 4.10 / 4.80 G | 3.80 / 4.20 G | 3.90 / 4.35 G | — | **290.5 µs** / 330.2 µs | **7.5M** / 43.5M | **TACHYON (1.8x)** |
| **AmneziaWG (Obfuscated WG)** | **6.95 / 8.10 G** | 3.95 / 4.55 G | 3.60 / 4.05 G | 3.75 / 4.15 G | — | **295.0 µs** / 335.4 µs | **7.6M** / 43.8M | **TACHYON (1.8x)** |
| **MASQUE (HTTP/3 WARP)** | **4.80 / 6.40 G** | 3.10 / 3.90 G | — | — | — | **315.0 µs** / 350.2 µs | **8.5M** / 47.0M | **TACHYON (1.6x)** |
| **FPTN (Packet Tunnel Network)**| **5.10 / 6.80 G** | — | — | — | — | **320.5 µs** / — | **8.2M** / — | **TACHYON ONLY** |

> 🏆 **Итоги бенчмарка**:
> * **36 побед из 39 протоколов** (3 ничьи: `vless`, `vless-tls-vision`, `trojan-ws-tls`, 0 поражений!).
> * **REALITY & Mieru поддержка**: VLESS REALITY Vision выдает **3.53 / 6.45 Gbps** при минимальной задержке **306.4 µs** (против 2.86 / 5.53 Gbps и 364.5 µs у sing-box). Trojan REALITY и Mieru также на борту.
> * **Прорыв в XHTTP (SplitHTTP)**: встроенный пул соединений `H2Pool` исключил повторные TLS-рукопожатия на каждый стрим. Задержка первого байта снизилась с **29.7 мс** (sing-box) и **30.8 мс** (Xray) до **408 µs (0.41 мс)** — **в 75–80 раз быстрее!**
> * **Холодный запуск**: **22.3 ms** у Tachyon — в 6.4x быстрее Steer (142 ms), в 7x быстрее Xray (161 ms), в 9.5x быстрее Mihomo (211 ms) и в 12x быстрее sing-box (268 ms).
> * **Минимальная память (RSS)**: **4.2 MiB** в простое и **4.6–14.6 MiB** под нагрузкой.
> * Подробные графики и интерактивная фильтрация доступны в **[BENCHMARK.md](BENCHMARK.md)** и **[BENCHMARK.html](BENCHMARK.html)**.

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 🌐 Архитектура ядра и возможности

<div align="center">

![Tachyon Core Architecture](assets/readme/architecture.svg)

</div>

Конвейер обработки трафика **tachyon-core** оптимизирован для минимизации переключений контекста ядра Linux и работы на линейной скорости роутера:

### 1. Входящие подключения (Inbounds)
* **Клиентские интерфейсы перехвата трафика**:
  * **Linux TProxy (IPv4 / IPv6)**: Прозрачный перехват UDP и TCP через `IP_TRANSPARENT` и сокеты `socket2` с извлечением реального адреса назначения через OOB-сообщения `IP_RECVORIGDSTADDR`.
  * **Redirect Inbound (NAT)**: Перехват TCP через `SO_ORIGINAL_DST` getsockopt.
  * **Mixed SOCKS / HTTP Inbound**: Полноценный HTTP CONNECT и SOCKS4/4a/5 с поддержкой UDP ASSOCIATE, Proxy-Authorization (Basic 407), keep-alive и прозрачной перезаписью абсолютных URI.
  * **Direct Inbound**: Транзитный инбаунд для интеграции со стеком маршрутизации Tachyon.
* **Серверные интерфейсы (F5 Server Stack)**:
  * Входные серверные точки для **VLESS**, **Trojan**, **VMess** (AEAD) и **Shadowsocks** (AEAD 128/256/chacha20).
  * Собственный асинхронный сервер **TLS 1.3** на чистом Rust (X25519, cipher suites, ALPN) поверх любого потока `AsyncRead + AsyncWrite`.
  * Поддержка UDP-команд поверх того же TCP-соединения (`[len:u16][payload]`).

### 2. Исходящие протоколы (Outbounds)
* **Стандартные и легковесные**: `direct`, `block`, `socks` (SOCKS5 с UDP ASSOCIATE), `http`.
* **Shadowsocks**: все шифры AEAD (`aes-128-gcm`, `aes-256-gcm`, `chacha20-poly1305`), спецификация **Shadowsocks 2022** (blake3), поддержка `udp_over_tcp` (UoT v1/v2) и TLS-транспорта.
* **VLESS**: поддержка `flow: xtls-rprx-vision`, всех форматов `packet_encoding` (`packetaddr`, `xudp`), мультиплексирования `h2mux` и uTLS-маскировки.
* **VMess**: заголовки AEAD и legacy, мультиплексирование сессий `h2mux`.
* **Trojan**: чистая реализация с ключом SHA224 и нулевым оверхедом.
* **Продвинутые и UDP/QUIC транспорты**:
  * **Hysteria2**: производительный QUIC-движок на базе `quinn`, обфускация salamander и gecko, алгоритмы BBR и Cubic.
  * **TUIC**: протокол TUIC v5 поверх QUIC с поддержкой `udp_over_stream`.
  * **AnyTLS**: поддержка `udp_over_tcp` с пулом буферов.
  * **Naive**: туннелирование по HTTP/2 и HTTP/3 (QUIC), заголовки `Padding` и `-connect-authority`, обрамление блоков `[len:u16][pad:u8]`.
  * **Snell**: поддержка протокола Snell версий v4 и v6 в чистом Rust.
  * **Mieru**: протокол обфускации TCP и UDP с защитой от активного зондирования.
  * **ShadowTLS**: поддержка ShadowTLS v3 с TLS SNI маскировкой под легитимные домены.
  * **MASQUE**: CONNECT-IP туннелирование UDP через HTTP-прокси, поддержка Cloudflare WARP.
  * **FPTN**: расширение Tachyon с распаковкой токенов и интеграцией в API.
  * **Диспетчеризация**: `urltest` и `selector` (стратегии `round_robin`, `least_test`, `least_ping`).

### 3. Эндпоинты туннелей (Endpoints)
* **AmneziaWG 2.0 & 3.x / WireGuard**:
  * Полный конвейер WireGuard с защитой от блокировок по сигнатурам DPI.
  * Мусорные пакеты в начале сессии (`jc`, `jmin`, `jmax`), рандомизация заголовков и диапазонов (`s1–s4`, `h1–h4`), паддинг полезной нагрузки.
  * Многопрофильная маскировка пакетов инициализации под **DNS**, **STUN**, **SIP** и **QUIC Initial**.
* **OpenVPN-Client**:
  * Режим `static_key` поверх UDP и TCP с поддержкой сжатия и фрагментации.

### 4. Транспорты и средства маскировки от DPI
* **Транспортные уровни**: TCP, WebSocket (`ws` с поддержкой `max_early_data`), HTTPUpgrade, gRPC (поверх HTTP/2 streams), HTTP/2, QUIC/HTTP/3.
* **XHTTP (SplitHTTP)**: полная реализация спецификаций HTTP/1.1 chunked, `stream-up`, `packet-up` и `stream-one` со встроенным пулом соединений HTTP/2 (`H2Pool` до 4 параллельных TCP/TLS сокетов с балансировкой стримов least-loaded). Исключает повторные TLS-рукопожатия на каждый запрос, снижая p50 задержку до **408 µs** (в **75–80× быстрее** Go-ядер с их 30 мс). Расширенные окна потока (4 MiB stream / 16 MiB connection) гарантируют скорость **4.4+ Gbit/s** на мультиплексированных стримах. Полная валидация против серверов **Xray 26.9+**.
* **Pure-Rust uTLS**: 13 байт-точных профилей популярных браузеров (Chrome, Firefox, Safari, Edge...), кастомный генератор ClientHello и собственный TLS-хендшейк без привлечения внешних C-библиотек.
* **Pure-Rust REALITY**: прямая поддержка протокола REALITY в чистом Rust со сквозным `splice`; проверенная работа с живыми серверами.
* **Post-Quantum Cryptography**: поддержка гибридного постквантового обмена ключами **ML-KEM-768** (`X25519MLKEM768`) в чистом Rust для защиты от атак "Store Now, Decrypt Later".

### 5. Smart DNS резолвер и подсистема FakeIP
* **Поддерживаемые транспорты DNS**: `udp`, `tcp`, `tls` (DoT), `https` (DoH поверх HTTP/2 и HTTP/1.1), `quic` (DoQ), `h3` (DoH3 поверх HTTP/3), `fakeip`, `local` (системный резолвер), `hosts` (`/etc/hosts` и инлайн-записи `predefined`), `mdns` (мультикаст-обнаружение в локальной сети LAN).
* **DNS Groups (`group`)**: lx-группы резолверов с поддержкой стратегий `stable`, `fastest` и `parallel` на основе скользящей статистики побед/ошибок, плюс аварийный режим выживания.
* **Reverse Mapping (`dns.reverse_mapping`)**: сопоставление `IP → домен` с сохранением в течение TTL записи, позволяющее применять доменные правила к прямым обращениям по IP.
* **Client Subnet (`dns.client_subnet`)**: проброс клиентских подсетей EDNS0 на внешние резолверы.
* **Кэширование**: производительный LRU-кэш на базе `Arc<str>` с обслуживанием устаревших записей (optimistic serving) и пул FakeIP (`198.18.0.0/15`).

### 6. Движок маршрутизации и инспекции пакетов (Zero-Alloc Router)
* **Матчеры правил**: `inbound`, `network`, `protocol`, домен (suffix, keyword, regex, exact), `ip_cidr`, `ip_is_private`, `source_*`, `port`, `port_range`, `process_name`, `process_path`, `process_path_regex`, `user`, `user_id` (через интроспекцию `/proc/net/*` и дескрипторов сокетов), `clash_mode`, `rule_set`, `rule_set_ipcidr_match_source`.
* **Таблица соседей и DHCP (`find_neighbor`)**: автоматическое сопоставление устройств в локальной сети по MAC-адресам (`source_mac_address`) и именам хостов (`source_hostname`) из файлов аренды DHCP.
* **Сниффер протоколов (PeekStream)**: буферизированный сниффинг TLS SNI, HTTP Host, QUIC SNI, DNS, BitTorrent, SSH, RDP без потери начальных байт.
* **Бинарные правила Rule-Set (SRS v5)**: быстрая компиляция, декомпиляция, проверка совпадений и автоматическая удаленная синхронизация списков правил.

### 7. Системный диалер и сетевой стек
* **Linux Network Namespaces (`netns`)**: встроенное управление сетевыми пространствами имен с дочерним процессом-держателем `CLONE_NEWNET`, изоляцией потоков ОС и бесконфликтным dial.
* **Защита сокетов (`protect_path`)**: передача дескрипторов сокетов системным службам и VPN-демонам через вспомогательные unix-сообщения `SCM_RIGHTS`.
* **Опции диалера**: поддержка Multipath TCP (`tcp_multi_path`), Happy Eyeballs RFC 6555 (`domain_strategy` + `fallback_delay`), маркеры fwmark (`routing_mark`), привязка к сетевым интерфейсам (`bind_interface`) и защита от шторма пакетов при сбросе соединений.

### 8. API управления и кэширование состояния
* **Clash REST API**: полная реализация endpoints `/version`, `/proxies`, `/connections`, `/rules`, `/configs`, `/logs`, `/traffic`, `/providers/*`, поддержка WebSocket-трафика, secret token аутентификация, CORS, переключение режимов `clash_mode` и встроенная раздача внешних панелей управления (Yacd, Metacubexd) по пути `/ui`.
* **Файл кэша `cache.db` (bbolt)**: честный B+tree читатель и писатель на чистом Rust, побайтово совместимый с оригинальным Go bbolt (бакеты `rule_set`, `selected`, `group_expand`, `clash_mode`, `rdrc2`, `dns_cache`, `fakeip`, `chain_disabled_lx`).
* **Вспомогательные сервисы**: встроенный NTP-клиент синхронизации времени и централизованный реестр HTTP-клиентов `http_clients`.

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 🧭 100% Drop-In Совместимость с sing-box

<div align="center">

![Tachyon Core CLI Showcase](assets/readme/cli_showcase.svg)

</div>

`tachyon-core` спроектирован как прозрачная прямая замена бинарника sing-box. При установке в систему под именем `/usr/bin/sing-box`, он отвечает на все стандартные вызовы:

```bash
# Валидация файла конфигурации (строгая проверка JSON-схемы)
tachyon-core check -c /etc/sing-box/config.json

# Вывод версии в upstream-совместимом формате для парсеров ucode
tachyon-core version

# Запуск рабочего сервиса
tachyon-core run -c /etc/sing-box/config.json

# Компиляция и декомпиляция бинарных правил .srs (SRS v5)
tachyon-core rule-set compile rules.json -o rules.srs
tachyon-core rule-set decompile rules.srs -o rules.json
```

### Матрица совместимости CLI

| Команда | Назначение в Tachyon / OpenWrt | Статус в tachyon-core |
|---|---|:---:|
| `check -c <path>` | Предстартовая проверка конфига в `watchdog.uc` | **Готово** (дифференциал 247/0 по корпусу) |
| `version` | Определение версии в `generator.uc` | **Готово** (upstream regex совместимость) |
| `run -c <path>` | Запуск рабочего процесса службы | **Готово** (Tokio async runtime) |
| `rule-set compile\|decompile` | Бинарные правила `.srs` (SRS v5) | **Готово** (оба направления) |
| `rule-set match\|format` | Проверка правил и форматирование | **Готово** |
| `api` | Управление и мониторинг через Clash API | **Готово** (REST / WebSockets) |
| `generate reality-keypair` | Генерация ключей REALITY | Запланировано |
| `generate wg-keypair` | Генерация ключей WireGuard / AmneziaWG | Запланировано |

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 🚀 Сборка и кросс-компиляция

### Локальная сборка на хосте
Для сборки требуется компилятор Rust 1.89+ (редакция 2024):

```bash
# Стандартная полная сборка (Full: все протоколы, Clash API, DNS-группы, SRS v5, ~11.6 MiB)
cargo build --workspace --release

# Ультра-компактная Lite-сборка (< 6.0 MiB для роутеров с 16-32 МБ Flash/RAM)
cargo build -p core-cli --release --profile lite --no-default-features --features lite

# Проверка лимитов размеров бинарников (Full <= 12 MiB, Lite <= 6 MiB)
bash scripts/size.sh

# Запуск полного набора модульных и интеграционных тестов (1081+ тестов)
cargo test --workspace
```

### Кросс-компиляция под роутеры через `cargo-zigbuild`
Для получения компактных статических бинарников без динамических зависимостей:

```bash
# Установка инструмента zigbuild
cargo install cargo-zigbuild

# Сборка Full под AArch64 (ARM64: NanoPi R3S/R4S, GL.iNet Flint 2, Raspberry Pi 4/5)
cargo zigbuild --target aarch64-unknown-linux-musl --release

# Сборка Lite (< 6.0 MiB) под AArch64
cargo zigbuild -p core-cli --target aarch64-unknown-linux-musl --release --profile lite --no-default-features --features lite

# Сборка Full под ARMv7 (Cortex-A7: IPQ4019, Xiaomi AX1800, Keenetic Hopper/Titan)
cargo zigbuild --target armv7-unknown-linux-musleabihf --release

# Сборка Lite (< 6.0 MiB) под ARMv7
cargo zigbuild -p core-cli --target armv7-unknown-linux-musleabihf --release --profile lite --no-default-features --features lite

# Сборка Full под x86_64 (мини-ПК, серверы, Proxmox/ESXi)
cargo zigbuild --target x86_64-unknown-linux-musl --release

# Сборка Lite (< 6.0 MiB) под x86_64
cargo zigbuild -p core-cli --target x86_64-unknown-linux-musl --release --profile lite --no-default-features --features lite
```

Финальный бинарник автоматически оптимизируется и очищается от отладочных символов (`strip = "symbols"`), достигая размера ~11.6 MiB (Full) или < 6.0 MiB (Lite).

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 🗺️ Дорожная карта разработки

Реализация функционала разбита на последовательные фазы с автоматическим дифференциальным тестированием против эталонного `sing-box-lx`:

| Фаза | Область функционала | Критерий готовности | Статус |
|:---:|---|---|:---:|
| **F0** | **Фундамент** | Прохождение дифференциальных тестов `check` и `version` по всему корпусу тестов (247/0) | **Завершено** |
| **F1** | **Data Plane v1** | Inbounds: tproxy, redirect, mixed, direct. Outbounds: socks, shadowsocks, vless, trojan, vmess. Smart DNS + FakeIP + LRU. Роутер и сниффер. | **Завершено** |
| **F2** | **Тяжёлые протоколы** | Hysteria2 (quinn), TUIC, WireGuard + AmneziaWG 2.0/3.x, VLESS ML-KEM-768, XHTTP (Xray 26.9 interop), uTLS/REALITY, Naive, Snell, AnyTLS, Mieru, ShadowTLS | **Завершено** |
| **F3** | **Правила SRS и обновления** | Бинарная совместимость с правилами SRS v5 (`compile`/`decompile`), удаленная загрузка списков | **Завершено** |
| **F4** | **Экспериментальный стек** | Clash API (Yacd UI, Secret auth, WebSockets), `cache.db` (bbolt r/w совместимость на чистом Rust) | **Завершено** |
| **F5** | **Серверная часть** | Серверные инбаунды для основных протоколов | **Завершено**: vless, trojan, vmess, shadowsocks — с собственным TLS 1.3 и UDP |
| **F6** | **TUN подсистема** | Режим `stack: system` (kernel TUN) и userspace стек на `smoltcp` | Запланировано |
| **F7** | **lx daemon и метрики** | Совместимость со службой Windows и демоном `lxd`, расширенная телеметрия | Запланировано |
| **F8** | **libbox / Android** | UniFFI/JNI биндинги для мобильных клиентов | Запланировано |
| **F9** | **MIPS Spike** | Таргеты `mipsel`/`mips` softfloat musl через `-Zbuild-std` | **В разработке**: сборка в CI есть |
| **F10** | **Интеграция в Tachyon** | Вариант `rs` в Tachyon: автоинсталлятор, переключение ядра в LuCI в 1 клик, поддержка Lite-сборки (< 6 МБ) | Запланировано |

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 📜 Лицензия и копирайты

Проект распространяется под лицензией **[GPL-3.0-only](LICENSE)**, унаследованной от sing-box и sing-box-lx.

* `tachyon-core` является независимой разработкой сообщества **Tachyon** и не аффилирован с SagerNet или Leadaxe.
* Все оригинальные авторские права на протоколы и спецификации sing-box принадлежат их законным авторам.

<p align="center">
  <img src="assets/readme/footer_tachyon.svg" width="100%" alt="Tachyon Community Footer" />
</p>
