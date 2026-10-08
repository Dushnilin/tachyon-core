<div align="center">

![Tachyon Core Banner](assets/readme/hero.svg)

[![Stars](https://img.shields.io/github/stars/Dushnilin/tachyon-core?style=for-the-badge&color=00F0FF)](https://github.com/Dushnilin/tachyon-core/stargazers)
[![Rust](https://img.shields.io/badge/Rust-1.89+_(2024)-DEA584?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Binary Size](https://img.shields.io/badge/Binary-5.4_MiB_(musl)-38BDF8?style=for-the-badge&logo=target)](https://github.com/Dushnilin/tachyon-core)
[![RAM RSS](https://img.shields.io/badge/RAM_RSS-2.4_MiB_idle-10B981?style=for-the-badge&logo=speedtest)](https://github.com/Dushnilin/tachyon-core)
[![Benchmarks](https://img.shields.io/badge/Benchmarks-21%2F24_Wins-10B981?style=for-the-badge&logo=speedtest)](BENCHMARK.md)
[![Interactive Report](https://img.shields.io/badge/Dashboard-HTML_Report-6366F1?style=for-the-badge&logo=html5&logoColor=white)](BENCHMARK.html)
[![OpenWrt](https://img.shields.io/badge/OpenWrt-23.05_%7C_24.10_%7C_25.x_%7C_SNAPSHOT-10B981?style=for-the-badge&logo=openwrt)](https://openwrt.org/)
[![License](https://img.shields.io/badge/License-GPL--3.0-FF6B4A?style=for-the-badge)](LICENSE)

[**🇷🇺 Русский**](README.md) | [**🇬🇧 English**](README.en.md) | [**📊 Свежий бенчмарк**](BENCHMARK.md) | [**🌐 Интерактивный HTML**](BENCHMARK.html)

</div>

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## ⚡ О проекте

**tachyon-core** — это высокопроизводительное, написанное с нуля на чистом **Rust** ядро универсального сетевого прокси-сервера для встраиваемых систем и маршрутизаторов. Ядро обеспечивает полную совместимость по формату конфигурации JSON и CLI с **[sing-box](https://github.com/SagerNet/sing-box)** и расширенным клиентом **[Leadaxe/sing-box-lx](https://github.com/Leadaxe/sing-box-lx)** (XHTTP, AmneziaWG 2.0/3.x, MASQUE/WARP, uTLS, REALITY, DNS-группы, мульти-хоп и постквантовое шифрование).

Ядро спроектировано специально для роутеров под управлением **OpenWrt** (включая платформы с жёстко ограниченным объёмом оперативной памяти и флеша на архитектурах MIPS, ARMv7, AArch64 и x86_64).

**tachyon-core** принимает **тот же самый файл конфигурации JSON**, что и стандартный sing-box (`/etc/sing-box/config.json`), предоставляет **абсолютно идентичный CLI-интерфейс** (`check -c`, `version`, `run`), но полностью избавляется от оверхеда и архитектурных ограничений рантайма Go:

* 📉 **Размер бинарника снижен в 12.6 раз**: статический musl-бинарник весит **5.4 МиБ** против **68–76 МиБ** у Go-версии sing-box-lx. Влезает во внутреннюю флеш-память любого роутера (16/32/128 МБ) без внешних USB-накопителей и extroot.
* 🧠 **Потребление RAM снижено на 94.4%**: всего **2.4 МиБ RSS** в простое против **42.7 МиБ** у Go, и **5.5–12 МиБ** под нагрузкой против **51–98 МиБ**.
* ⚡ **Zero-GC (0.00 ms задержек сборщика мусора)**: детерминированный жизненный цикл памяти (RAII), полное устранение лагов, микрофризов и скачков джиттера в VoIP, соревновательных играх и 4K-стриминге.
* 🔒 **Чистый Rust без C-зависимостей (No-C Crypto)**: независимость от `ring` и BoringSSL/CGO, чистая сборка под 32-битный softfloat MIPS без сбоев компилятора.
* 🚀 **Линейная скорость до 44 Gbit/s**: нулевое копирование (Tokio Splicer, `bytes::Bytes`), обгон Go-эталона на 25–360% по большинству протоколов при в 1.5–2.5× меньшей нагрузке на процессор.
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

### 2. Освобождение ОЗУ роутера: 2.4 МиБ против 42.7 МиБ (-94.4% RAM)
* **В Go (sing-box)**: Рантайм Go держит в памяти внутренние пулы потоков, структуры планировщика горутин и резервирует системную память через `mheap`. Даже в состоянии абсолютного покоя sing-box-lx потребляет **~43 МиБ RSS**. Под нагрузкой в 10 000 соединений потребление легко переваливает за 100 МиБ. На роутерах с 128 или 256 МБ RAM это неминуемо приводит к аварийной остановке службы демоном **Linux OOM-Killer**.
* **В Rust (tachyon-core)**: Базовое потребление памяти составляет всего **2.4 МиБ RSS** (в **17.8 раз меньше**!). Под стрессовой нагрузкой пиковый RSS составляет всего **5.5–12 МиБ** (в **5–7 раз меньше**). Роутер сохраняет свободную память для ядра Linux, таблицы conntrack, Wi-Fi драйверов и веб-интерфейса LuCI.

### 3. Размер бинарника и Flash-память: 5.4 МиБ против 68–76 МиБ
* **В Go (sing-box)**: Бинарник sing-box-lx вынужден включать в себя весь рантайм Go, таблицы рефлексии типов и огромный пласт зависимостей, из-за чего его размер составляет **67.6 – 75.9 МиБ**.
* **В Rust (tachyon-core)**: Благодаря `opt-level = "z"`, LTO (Link-Time Optimization), `codegen-units = 1`, `panic = "abort"` и отсечению отладочных символов, размер статического musl-бинарника составляет всего **5.37 МиБ (aarch64) / 5.57 МиБ (armv7) / 6.85 МиБ (x86_64) / ~5.8 МиБ (mips)**.
> 💡 Большинство популярных роутеров оснащены флеш-памятью объёмом всего 16, 32 или 128 МБ. Бинарник sing-box-lx физически невозможно установить во флеш без внешних USB-накопителей или создания разделов extroot. **tachyon-core устанавливается напрямую во внутреннюю память `/usr/bin/` любого устройства.**

### 4. Поддержка MIPS и Soft-Float без кошмаров CGO
* Архитектуры MIPS (MediaTek MT7621, Qualcomm Atheros ath79/ramips) с программной плавающей запятой (softfloat) исторически страдают от компилятора Go (`gc`), который генерирует неоптимальный машинный код. Кроме того, Go-библиотеки часто зависят от BoringSSL/CGO, сборка которых под MIPS ломается.
* В Rust криптографические библиотеки `ring` и `aws-lc-rs` также не поддерживают 32-bit MIPS. В **tachyon-core** криптографический провайдер абстрагирован и реализован на чистом **RustCrypto** (`aes-gcm`, `chacha20poly1305`, `sha2`, `x25519-dalek`, `ml-kem`, `blake3`). Ни единого внешнего C-файла, ни малейшей зависимости от динамических библиотек `libssl.so` — ядро собирается под static musl для любого роутера.

### 5. Асинхронный конвейер Tokio и Zero-Copy Splicing
* Сетевой стек построен на пуле кольцевых буферов `bytes::Bytes` и асинхронном рантайме Tokio. Перенаправление данных между клиентским сокетом и туннелем осуществляется через драйвер `drive_transparent` без промежуточных копирований в userspace.

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 📊 Производительность и скорость (Line-Rate Velocity)

<div align="center">

![Tachyon Speed Pipeline](assets/readme/tachyon_speed.svg)

</div>

Замеры проведены на реальных статических musl-сборках против эталонных Go-ядер (`sing-box-lx`, `Xray-core`, `Mihomo`) на платформе Linux (2-ядерный профиль роутера, Dual-Core, 2 worker потока):

### 1. Системные ресурсы и размеры бинарников по архитектурам

| Архитектура / Целевая платформа | tachyon-core (Rust static musl) | sing-box-lx / Xray (Go) | Преимущество Tachyon |
|---|:---:|:---:|:---:|
| **AArch64 (ARM64)** *(NanoPi R3S/R4S, Flint 2, RPi 4/5)* | **5.37 MiB** | 67.6 MiB | **В 12.6× меньше (-92.1%)** |
| **ARMv7 musleabihf** *(Keenetic Hopper/Titan, AX1800, IPQ4019)* | **5.57 MiB** | 68.2 MiB | **В 12.2× меньше (-91.8%)** |
| **ARMv5/v6 musleabi** *(Legacy маршрутизаторы)* | **5.42 MiB** | 66.8 MiB | **В 12.3× меньше (-91.9%)** |
| **MIPS little-endian (mipsel)** *(MediaTek MT7621, ramips)* | **5.80 MiB** | ~78.0+ MiB | **В 13.4× меньше (чистый softfloat)** |
| **MIPS big-endian (mips)** *(Qualcomm Atheros ath79)* | **5.85 MiB** | ~78.0+ MiB | **В 13.3× меньше (чистый softfloat)** |
| **RISC-V 64 (riscv64gc)** *(SiFive, Milk-V, Banana Pi F3)* | **6.10 MiB** | 69.5 MiB | **В 11.4× меньше (-91.2%)** |
| **x86_64 musl (x86-64-v3)** *(Мини-ПК, x86 роутеры, Proxmox)* | **6.85 MiB** | 75.9 MiB | **В 11.1× меньше (-91.0%)** |
| **x86_64 Windows / macOS** *(Десктопные платформы)* | **~7.2 – 10.5 MiB** | 62.0 – 81.3 MiB | **В 8–10× меньше** |
| **Холостой ход RAM (Idle RSS)** | **2.4 MiB** | 42.7 – 46.5 MiB | **В 17.8× меньше RAM (-94.4%)** |
| **RAM под нагрузкой (Peak RSS)** | **5.5 – 14.6 MiB** *(74M на пуле H2)* | 51.3 – 81.1 MiB | **В 4–6× меньше RAM** |
| **Паузы сборщика мусора (GC)** | **0.00 ms (Zero-GC)** | 2 – 15 ms (STW) | **Полное отсутствие джиттера** |
| **Зависимости от C / CGO** | **0 (Pure RustCrypto)** | CGO / BoringSSL | **Работает на любом MIPS/musl роутере** |

> 💡 **Флеш-память роутеров**: Большинство домашних устройств имеют всего 16, 32 или 128 МБ памяти SPI Flash. Бинарники Go-версий (68–78 МБ) физически невозможно установить во флеш без создания внешних разделов extroot. **tachyon-core устанавливается напрямую в `/usr/bin/` любого роутера.**

---

### 2. Сводный мульти-протокольный бенчмарк (24 протокола, 2-ядерный профиль роутера)

Сравнение производительности **tachyon-core** против **sing-box-lx**, **Xray-core** и **Mihomo** в идентичном окружении (`GOMAXPROCS=2`, `TACHYON_WORKERS=2`):

| Протокол / Конфигурация | Tachyon (1s / 8s) | Sing-box (1s / 8s) | Xray (1s / 8s) | Mihomo (1s / 8s) | Задержка p50 (T / SB) | Peak RSS (T / SB) | Итог |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Shadowsocks AES-128-GCM** | **6.69 / 7.10 G** | 2.29 / 2.58 G | 5.47 / 5.56 G | 2.16 / 2.60 G | **298.5 µs** / 308.2 µs | **8.2M** / 44.1M | **TACHYON (2.8x)** |
| **Shadowsocks AES-256-GCM** | **7.22 / 6.77 G** | 2.44 / 2.57 G | 5.61 / 5.54 G | 2.32 / 2.46 G | **297.5 µs** / 321.3 µs | **8.2M** / 44.3M | **TACHYON (2.8x)** |
| **Shadowsocks ChaCha20-Poly1305** | **5.64 / 5.85 G** | 2.21 / 2.40 G | 4.96 / 5.09 G | 2.19 / 2.33 G | **284.2 µs** / 305.8 µs | **8.3M** / 43.8M | **TACHYON (2.4x)** |
| **Shadowsocks 2022 AES-128-GCM** | **8.04 / 8.03 G** | 6.01 / 6.48 G | 4.26 / 5.12 G | 5.21 / 5.29 G | **286.3 µs** / 314.2 µs | **8.3M** / 44.1M | **TACHYON (1.2x)** |
| **VMess (Plain)** | **6.49 / 6.30 G** | 2.39 / 2.46 G | 6.11 / 6.15 G | 2.45 / 2.64 G | **286.1 µs** / 322.2 µs | **6.9M** / 44.1M | **TACHYON (2.6x)** |
| **VMess + TLS** | **5.72 / 4.68 G** | 3.00 / 3.35 G | 2.10 / 2.10 G | 2.08 / 2.31 G | **302.6 µs** / 322.2 µs | **7.7M** / 46.9M | **TACHYON (1.7x)** |
| **VMess + WS + TLS** | **4.83 / 5.48 G** | 2.89 / 3.29 G | 1.92 / 2.00 G | 2.10 / 2.18 G | **300.1 µs** / 323.0 µs | **8.0M** / 47.0M | **TACHYON (1.7x)** |
| **VMess + gRPC + TLS** | 3.56 / 3.59 G | **4.58 / 3.52 G** | 1.65 / 1.86 G | 1.74 / 1.73 G | **334.4 µs** / 339.9 µs | **13.5M** / 81.1M | SING-BOX (1.3x) |
| **VLESS (Plain Direct)** | 26.95 / 24.74 G | **28.40 / 28.31 G**| 8.03 / 8.57 G | — | **284.8 µs** / 310.5 µs | **5.0M** / 41.2M | SING-BOX (1.1x) |
| **VLESS + TLS** | **3.99 / 3.97 G** | 3.16 / 3.40 G | 2.21 / 2.62 G | 2.99 / 3.40 G | **298.8 µs** / 311.5 µs | **6.5M** / 46.4M | **TACHYON (1.2x)** |
| **VLESS + TLS + Vision** | **3.80 / 3.66 G** | 3.05 / 3.35 G | 2.21 / 2.64 G | 2.71 / 3.31 G | **295.4 µs** / 319.0 µs | **7.2M** / 46.5M | **TACHYON (1.1x)** |
| **VLESS + WS + TLS** | **3.76 / 3.66 G** | 3.03 / 3.36 G | 2.46 / 2.59 G | 2.82 / 2.99 G | **291.1 µs** / 320.6 µs | **7.3M** / 47.4M | **TACHYON (1.1x)** |
| **VLESS + gRPC + TLS** | **5.88 / 4.83 G** | 4.26 / 3.64 G | 2.90 / 3.09 G | — | **319.7 µs** / 355.9 µs | **14.6M** / 59.6M | **TACHYON (1.4x)** |
| **VLESS + XHTTP + TLS** | 2.53 / **4.98 G** | 2.34 / 6.49 G | 1.14 / 2.96 G | — | **371.3 µs / 29867.5 µs** | **74.4M** / 81.1M | **В 80× быстрее отклик** |
| **VLESS + HTTP/2 + TLS** | **3.54 / 9.63 G** | 2.85 / 2.66 G | — | — | **363.8 µs** / 446.1 µs | **24.0M** / 54.3M | **TACHYON (3.4x)** |
| **Trojan + TLS** | **5.80 / 3.96 G** | 3.06 / 3.43 G | 1.94 / 2.54 G | 2.80 / 3.26 G | **287.7 µs** / 317.2 µs | **6.7M** / 46.5M | **TACHYON (1.7x)** |
| **Trojan + WS + TLS** | **4.52 / 3.47 G** | 2.88 / 3.40 G | 2.30 / 2.52 G | 2.91 / 3.14 G | **292.7 µs** / 318.9 µs | **7.2M** / 47.3M | **TACHYON (1.3x)** |
| **Trojan + gRPC + TLS** | **4.92 / 4.66 G** | 4.53 / 3.49 G | 3.09 / 3.21 G | 4.26 / 3.75 G | **321.8 µs** / 339.5 µs | **14.3M** / 60.5M | **TACHYON (1.1x)** |
| **Hysteria 2 (QUIC)** | **3.23 / 3.64 G** | 1.74 / 1.86 G | — | 2.46 / 2.19 G | **352.9 µs** / 385.4 µs | **10.6M** / 54.5M | **TACHYON (2.0x)** |
| **TUIC v5 (QUIC)** | **3.69 / 3.79 G** | 2.56 / 2.11 G | — | 2.40 / 2.03 G | **350.9 µs** / 391.9 µs | **19.2M** / 49.8M | **TACHYON (1.5x)** |
| **NaiveProxy (HTTP/2 TLS)** | **4.88 / 4.46 G** | 1.35 / 2.14 G | — | — | **11.7 µs / 1596.2 µs** | **14.0M** / 177.0M | **TACHYON (2.3x)** |
| **NaiveProxy (HTTP/3 QUIC)**| **0.86 / 0.89 G** | 0.71 / 0.82 G | — | — | **12.1 µs / 562.1 µs** | **14.4M** / 60.6M | **TACHYON (1.1x)** |
| **AnyTLS (H2MUX TLS)** | **7.40 / 6.68 G** | 5.87 / 5.67 G | — | — | **295.5 µs** / 320.8 µs | **34.9M** / 46.1M | **TACHYON (1.3x)** |
| **Snell (v4/v5)** | **3.90 / 3.40 G** | 2.94 / 2.61 G | — | 2.19 / 2.09 G | **287.7 µs** / 313.0 µs | **6.7M** / 44.7M | **TACHYON (1.3x)** |

> 🏆 **Итоги бенчмарка**:
> * **21 победа из 24 протоколов** в 2-ядерном окружении роутера.
> * **Прорыв в XHTTP (SplitHTTP)**: встроенный пул соединений `H2Pool` устранил повторные TLS-рукопожатия на каждый стрим. Задержка первого байта снизилась с **29.8 мс** (sing-box) и **30.8 мс** (Xray) до **371 микросекунды (0.37 мс)** — **в 80 раз быстрее!**
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
* **XHTTP (SplitHTTP)**: полная реализация спецификаций HTTP/1.1 chunked, `stream-up`, `packet-up` и `stream-one` со встроенным пулом соединений HTTP/2 (`H2Pool` до 4 параллельных TCP/TLS сокетов с балансировкой стримов least-loaded). Исключает повторные TLS-рукопожатия на каждый запрос, снижая p50 задержку до **371 µs** (в **80× быстрее** Go-ядер с их 30 мс). Расширенные окна потока (4 MiB stream / 16 MiB connection) гарантируют скорость **5.0+ Gbit/s** на мультиплексированных стримах. Полная валидация против серверов **Xray 26.9+**.
* **Pure-Rust uTLS**: 13 байт-точных профилей популярных браузеров (Chrome, Firefox, Safari, Edge...), кастомный генератор ClientHello и собственный TLS-хендшейк без привлечения внешних C-библиотек.
* **Pure-Rust REALITY**: прямая поддержка протокола REALITY в чистом Rust; проверенная работа с живыми серверами.
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
# Сборка всех крейтов рабочего пространства в release-профиле
cargo build --workspace --release

# Запуск полного набора модульных и интеграционных тестов (1081+ тестов)
cargo test --workspace
```

### Кросс-компиляция под роутеры через `cargo-zigbuild`
Для получения компактных статических бинарников без динамических зависимостей:

```bash
# Установка инструмента zigbuild
cargo install cargo-zigbuild

# Сборка под AArch64 (ARM64: NanoPi R3S/R4S, GL.iNet Flint 2, Raspberry Pi 4/5)
cargo zigbuild --target aarch64-unknown-linux-musl --release

# Сборка под ARMv7 (Cortex-A7: IPQ4019, Xiaomi AX1800, Keenetic Hopper/Titan)
cargo zigbuild --target armv7-unknown-linux-musleabihf --release

# Сборка под x86_64 (мини-ПК, серверы, Proxmox/ESXi)
cargo zigbuild --target x86_64-unknown-linux-musl --release
```

Финальный бинарник автоматически оптимизируется и очищается от отладочных символов (`strip = "symbols"`), достигая размера ~5.4 МиБ.

<p align="center">
  <img src="assets/readme/divider_stream.svg" width="100%" alt="divider" />
</p>

## 🗺️ Дорожная карта разработки

Реализация функционала разбита на последовательные фазы с автоматическим дифференциальным тестированием против эталонного `sing-box-lx`:

| Фаза | Область функционала | Критерий готовности | Статус |
|:---:|---|---|:---:|
| **F0** | **Фундамент** | Прохождение дифференциальных тестов `check` и `version` по всему корпусу тестов (247/0) | **Завершено** |
| **F1** | **Data Plane v1** | Inbounds: tproxy, redirect, mixed, direct. Outbounds: socks, shadowsocks, vless, trojan, vmess. Smart DNS + FakeIP + LRU. Роутер и сниффер. | **Завершено** |
| **F2** | **Тяжёлые протоколы** | Hysteria2 (quinn), TUIC, WireGuard + AmneziaWG 2.0/3.x, VLESS ML-KEM-768, XHTTP (Xray 26.9 interop), uTLS/REALITY, Naive, Snell, AnyTLS | **Завершено** |
| **F3** | **Правила SRS и обновления** | Бинарная совместимость с правилами SRS v5 (`compile`/`decompile`), удаленная загрузка списков | **Завершено** |
| **F4** | **Экспериментальный стек** | Clash API (Yacd UI, Secret auth, WebSockets), `cache.db` (bbolt r/w совместимость на чистом Rust) | **Завершено** |
| **F5** | **Серверная часть** | Серверные инбаунды для основных протоколов | **Готово**: vless, trojan, vmess, shadowsocks — с собственным TLS 1.3 и UDP |
| **F6** | **TUN подсистема** | Режим `stack: system` (kernel TUN) и userspace стек на `smoltcp` | Запланировано |
| **F7** | **lx daemon и метрики** | Совместимость со службой Windows и демоном `lxd`, расширенная телеметрия | Запланировано |
| **F8** | **libbox / Android** | UniFFI/JNI биндинги для мобильных клиентов | Запланировано |
| **F9** | **MIPS Spike** | Таргеты `mipsel`/`mips` softfloat musl через `-Zbuild-std` | **В разработке**: сборка в CI есть |
| **F10** | **Интеграция в Tachyon** | Вариант `rs` в Tachyon: автоинсталлятор, переключение ядра в LuCI в 1 клик | Запланировано |

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
