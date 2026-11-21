# Эксплуатация, sizing и целевые платформы

Документ описывает подбор ресурсов под различные классы оборудования, матрицу целевых платформ и релизных артефактов (v0.6.2), бюджеты размера исполняемого файла, методику диагностики типовых неисправностей и эксплуатационный чеклист.

---

## 1. Sizing по классам устройств (RAM / CPU / Flash)

`tachyon-core` автоматически вычисляет профиль подсистем при запуске (подробнее см. [Аппаратная адаптация и управление памятью](../01-architecture/memory-and-hardware.md)), однако выбор протоколов, типа перехвата трафика и формата наборов правил определяет реальный запас по ОЗУ и CPU.

| Класс устройства | Типовое оборудование | RAM / CPU / ISA | Рекомендуемый профиль эксплуатации | Ориентиры по ресурсам |
|---|---|---|---|---|
| **Ультракомпактные роутеры** | OpenWrt `ath79`, `ramips` (`MT7620`, `AR9331`, `QCA9531`), `ARMv6` | `16–32 MiB` RAM, 1 ядро, `mips`/`mipsel` soft-float или `armv6` без AES | 1 воркер (`current_thread`); шифр **ChaCha20-Poly1305**; перехват `redirect`/`tproxy` вместо `tun`; только `mmap` `.trs` в `/tmp/tachyon-rulesets/`; отключить `store_dns`; `cache.db` в `/tmp/` или с выносом `.ephemeral` в `/tmp/tachyon-core/`. | Критический порог RSS: `6–14 MiB`; `udp_nat_max_sessions = 128`; `HardwareProfile::dns_cache_capacity = 512` (нижний предел `ShardedCache` в `DnsService` — `1024`). |
| **Мобильные расширения (iOS)** | iPhone / iPad `NEPacketTunnelProvider` | `50 MiB` потолок Jetsam (независимо от физической DRAM), `aarch64` ARMv8 AES+PMULL+NEON | Сборка `TachyonCore.xcframework`; встроенный C ABI ограничивает воркеры `<= 2`; `tun` по переданному `tun_fd`; компактные `.trs` через `mmap`; `smoltcp` max-буфер `<= 384 KiB`. | Критический порог RSS: `22 MiB` (порог `Elevated`: `16.5 MiB`); `fakeip` LRU `4096`. |
| **Базовые роутеры OpenWrt** | `MT7621` (`mipsel`), `IPQ40xx` (`armv7`), `Cortex-A53` без Crypto Ext (`aarch64`) | `64–128 MiB` RAM, 2–4 ядра; без аппаратного AES -> приоритет **ChaCha20-Poly1305** | `1–2` воркера; `tproxy` или `tun` (`smoltcp` + GSO/GRO); при `64 MiB` задать `TACHYON_MEMLIMIT_MB=36` или оставить автопрофиль; `rule_set` в формате `.trs` (`mmap`); `cache.db` на `/etc/tachyon-core/` (`.ephemeral` уходит в `/tmp`). | Критический порог RSS: `35–70 MiB`; `h2_stream_window = 1–2 MiB`; `quic_conn_window = 5 MiB`. |
| **Средние и старшие роутеры** | MediaTek Filogic 820 / 830 (`MT7981`, `MT7986`), Qualcomm IPQ60xx/IPQ807x, x86 мини-ПК (`J4125`, `N100`) | `256–512 MiB` RAM, 2–4 ядра, `ARMv8 AES+PMULL` или `x86_64 AES-NI` | `2–4` воркера; приоритет **AES-128-GCM**; полный стек `tun` / `tproxy`, QUIC (`hysteria2`, `tuic`), `vless` + REALITY + Vision, `wireguard`/`amneziawg`, несколько `.trs` наборов правил и `clash_api`. | Критический порог RSS: `115–230 MiB`; `relay_buf = 120 KiB`; `splice_pipe = 512 KiB–1 MiB`. |
| **Серверы и шлюзы 10G+** | VPS / выделенные серверы Linux (`x86_64` AVX2/VAES, `aarch64` Neoverse), Windows/macOS хосты | `1–64+ GiB` RAM, 4–64+ ядер, `VAES+VPCLMULQDQ` / `AVX2` / `ARMv8` | Все доступные ядра (или cgroup `cpu.max`); серверные инбаунды с `splice(2)` и `TACHYON_TCP_CONGESTION=bbr`; BDP-окна H2 до `32 MiB` и QUIC до `64 MiB`; `udp_socket_buffer = 16 MiB` (поднять системные `net.core.rmem_max`/`wmem_max`). | Критический порог RSS: `256–512 MiB` (или `45%` при `<= 2 GiB`); `dns_cache = 8192`; `udp_nat = 8192`. |

### Влияние аппаратного AES на выбор протокола

На `Cortex-A55` под OpenWrt включение инструкций ARMv8 Crypto (`--cfg aes_armv8 --cfg polyval_armv8`) поднимает скорость `AES-GCM` с **0.03 GiB/s** (программная ветка) до **0.22 GiB/s** (~7x). Если целевой роутер не имеет аппаратных инструкций AES (все `mips`/`mipsel`, `armv6`, большинство `armv7`, часть `Cortex-A53`, `riscv64`), следует отдавать предпочтение шифрам `chacha20-poly1305` / `2022-blake3-chacha20-poly1305` (в TLS 1.3 и QUIC `core-crypto` автоматически ставит ChaCha20 первым при `!has_hw_aes_gcm()`).

---

## 2. Целевые платформы и релизные артефакты

Релизный пайплайн (`.github/workflows/release.yml`) собирает артефакты для **16 целевых триплетов** в рамках 14 матричных заданий. Для всех файлов формируется единый файл контрольных сумм `SHA256SUMS`.

### Сводная таблица целевых платформ

| Группа | Имя сборки | Target triple | Линковка и особенности ISA | Бюджет размера | Публикуемые артефакты |
|---|---|---|---|---|---|
| OpenWrt (static musl) | `x86_64` | `x86_64-unknown-linux-musl` | `rust-lld`, static CRT, `target-cpu=x86-64` (v1 baseline), runtime CPUID (`SSE2`/`AES-NI`/`AVX2`/`VAES`) | `14 MiB` (`14 680 064 B`; локальный gate `<= 12 MiB`) | `tachyon-core-x86_64-<ver>.tar.gz`, `.ipk`, `.apk` |
| OpenWrt (static musl) | `i386_pentium4` | `i686-unknown-linux-musl` | `rust-lld`, static CRT, `target-cpu=pentium4` (SSE2) | `14 MiB` | `tachyon-core-i386_pentium4-<ver>.tar.gz`, `.ipk`, `.apk` |
| OpenWrt (static musl) | `aarch64` | `aarch64-unknown-linux-musl` | `rust-lld`, `--cfg aes_armv8 polyval_armv8 chacha20_force_neon` (runtime `AT_HWCAP`) | `14 MiB` | `tachyon-core-aarch64-<ver>.tar.gz`, `.ipk`, `.apk` |
| OpenWrt (static musl) | `armv7` | `armv7-unknown-linux-musleabihf` | `rust-lld`, baseline `v7a + vfp3-d16` (без принудительного `+neon`) | `14 MiB` | `tachyon-core-armv7-<ver>.tar.gz`, `.ipk`, `.apk` |
| OpenWrt (static musl) | `armv6` | `arm-unknown-linux-musleabi` | `rust-lld`, soft-float без FPU/SIMD, встроенный шим `fmaximum_num` | `14 MiB` | `tachyon-core-armv6-<ver>.tar.gz`, `.ipk`, `.apk` |
| OpenWrt (static musl) | `riscv64` | `riscv64gc-unknown-linux-musl` | `rust-lld`, static CRT, `rv64gc` | `14 MiB` | `tachyon-core-riscv64-<ver>.tar.gz`, `.ipk`, `.apk` |
| OpenWrt (tier-3 MIPS) | `mipsel` | `mipsel-unknown-linux-musl` | Nightly `-Z build-std=std,panic_abort`, `mips32r2 +soft-float`, `musl 1.2.5` + `libunwind.a` с `-mips32r2 -msoft-float` | `16 MiB` (`16 777 216 B`) | `tachyon-core-mipsel-<ver>.tar.gz`, `.ipk`, `.apk` |
| OpenWrt (tier-3 MIPS) | `mips` | `mips-unknown-linux-musl` | Big-endian `mips32r2 +soft-float`, `musl 1.2.5` + `libunwind.a` с `-mips32r2 -msoft-float` | `16 MiB` | `tachyon-core-mips-<ver>.tar.gz`, `.ipk`, `.apk` |
| Linux Desktop/Server | `linux-amd64` | `x86_64-unknown-linux-gnu` | Динамический glibc, runtime CPUID dispatch | `16 MiB` | `tachyon-core-linux-amd64-<ver>.tar.gz` |
| Windows Desktop/Server | `windows-amd64` | `x86_64-pc-windows-msvc` | MSVC `link.exe`, runtime CPUID dispatch | `20 MiB` (`20 971 520 B`) | `tachyon-core-windows-amd64-<ver>.zip` |
| Apple macOS / iOS | `apple` (4 цели) | `aarch64-apple-darwin`, `x86_64-apple-darwin`, `aarch64-apple-ios`, `aarch64-apple-ios-sim` | ARMv8 crypto cfgs на `aarch64`; CLI-бинарники + `staticlib` `core-runtime` в `XCFramework` | `16 MiB` на бинарник | `tachyon-core-darwin-{arm64,amd64}-<ver>.tar.gz`, `tachyon-core-ios-arm64-<ver>.tar.gz`, `tachyon-core-ios-xcframework-<ver>.tar.gz` |
| Android NDK (API 24+) | `aarch64-linux-android` | `aarch64-linux-android` | Bionic PIE + JNI `cdylib` (`core-ffi`), ARMv8 crypto cfgs, `-Wl,-z,max-page-size=16384` | `16 MiB` | `tachyon-core-aarch64-linux-android-<ver>.tar.gz`, `libtachyon-arm64-v8a.so` |
| Android NDK (API 24+) | `armv7-linux-androideabi` | `armv7-linux-androideabi` | Bionic PIE + JNI `cdylib`, `-Wl,-z,max-page-size=16384` | `16 MiB` | `tachyon-core-armv7-linux-androideabi-<ver>.tar.gz`, `libtachyon-armeabi-v7a.so` |
| Android NDK (API 24+) | `x86_64-linux-android` | `x86_64-linux-android` | Bionic PIE + JNI `cdylib`, `target-cpu=x86-64`, `-Wl,-z,max-page-size=16384` | `16 MiB` | `tachyon-core-x86_64-linux-android-<ver>.tar.gz`, `libtachyon-x86_64.so` |

### Платформенные детали сборки и упаковки

- **MIPS / MIPSEL soft-float**: роутеры OpenWrt на ядрах `24Kc`, `24KEc` и `1004Kc` (`ath79`/`ramips`) не оснащены аппаратным FPU. Любая инструкция сопроцессора COP1 вызывает немедленное завершение процесса с `SIGILL` (код выхода `132`). Поэтому для обеих MIPS-целей обязательно используются флаги `-C target-cpu=mips32r2 -C target-feature=+crt-static,+soft-float`, а также сборка `musl 1.2.5` и `libunwind.a` с `-mips32r2 -msoft-float`.
- **Пакеты OpenWrt (`.ipk` и `.apk`)**: собираются детерминированным скриптом `scripts/build_openwrt_pkg.py` для всех 8 musl-архитектур одновременно в двух форматах — классическом `.ipk` (`opkg`) и `.apk` (`apk-tools v2` для OpenWrt 25+, с PAX-заголовками `APK-TOOLS.checksum.SHA1`). Пакеты не объявляют внешних `Depends` (статический бинарник со встроенными корневыми CA), что позволяет устанавливать их оффлайн. Состав пакета: `/usr/bin/tachyon-core`, `/etc/init.d/tachyon-core`, `/etc/config/tachyon-core`, `/etc/tachyon-core/config.json`.
- **Android JNI и 16 KB page alignment**: все 3 Android-таргета линкуются с `-Wl,-z,max-page-size=16384`, что удовлетворяет требованиям Android 15/16 к выравниванию ELF-сегментов на 16 KiB страницах без потери совместимости с устройствами на 4 KiB страницах. Флаг `noseparate-code` для динамических Bionic PIE не применяется. Крейт `core-ffi` собирается в `libtachyon-<abi>.so` (`arm64-v8a`, `armeabi-v7a`, `x86_64`) для класса `org.tachyon.vpn.TachyonCore`.
- **iOS XCFramework**: собираются две статические библиотеки `core-runtime` (`aarch64-apple-ios` и `aarch64-apple-ios-sim`), объединяемые `xcodebuild -create-xcframework` с заголовочным файлом `include/tachyon_core.h` и `module.modulemap` (модуль `TachyonCore`).

---

## 3. Бюджеты размера бинарника и флаги линковщика

Для уменьшения размера исполняемого файла без потери скорости на горячем пути применяются:

1. **Профиль релиза**: `opt-level = "z"` по умолчанию + точечный `opt-level = 3` для криптографии и сетевого стека (`Cargo.toml`), `lto = true`, `codegen-units = 1`, `panic = "abort"`, `strip = "symbols"`.
2. **Флаги компилятора (`.cargo/config.toml`)**:
   - `-C force-unwind-tables=no` — удаление `.eh_frame`/`.eh_frame_hdr` (на `mips32` экономит ~400 KiB).
   - `-Z location-detail=none`, `-Z fmt-debug=shallow`, `-Z remap-cwd-prefix=.` — исключение строковых путей исходников и подробного `Debug`-форматирования из бинарника.
3. **Флаги линковщика `rust-lld` (для static musl)**:
   - `--icf=safe` — сворачивание идентичного кода. Использование `--icf=all` запрещено: оно объединяет байтово идентичные статики с наблюдаемыми адресами, что ломает уникальность `std::any::TypeId` и нарушает `Any::downcast_ref` при определении `TcpStream` для `splice(2)`.
   - `-z noseparate-code` и `-z norelro` — устранение лишнего выравнивания сегментов и неиспользуемого в статической сборке RELRO.
4. **Причины различия бюджетов**:
   - Локальный Docker-гейт проверяет `x86_64-unknown-linux-musl <= 12 MiB` (`12 582 912 B`).
   - В `release.yml` для musl-таргетов задан верхний порог `14 MiB`, для `mips`/`mipsel` — `16 MiB` (на MIPS после `strip` остаётся ~350 KiB дескрипторов `.pdr`, а кросс-сборка через GNU `ld` не поддерживает `--icf=safe`), для `windows-amd64` — `20 MiB`.
5. **Отказ от UPX**: упаковка бинарников через UPX не применяется — сжатие пакетов `.tar.gz`/`.ipk`/`.apk` уменьшает скачиваемый объём, тогда как UPX заставляет распаковывать бинарник в ОЗУ при каждом запуске роутера и вызывает ложные срабатывания защитного ПО.
6. **Ловушка `RUSTFLAGS`**: при ручной сборке нельзя задавать переменную окружения `RUSTFLAGS=...` — Cargo подменяет ею весь массив `rustflags` из `.cargo/config.toml`, что тихо отключает `--cfg aes_armv8` / `polyval_armv8` / `chacha20_force_neon` на `aarch64` и флаги `+soft-float` на `mips`. Все целевые флаги должны жить в `.cargo/config.toml` либо повторяться целиком.

---

## 4. Диагностика типовых проблем

### Логирование и наблюдаемость

- **Переменная `RUST_LOG` не используется**: ядро не включает `env_logger`, а уровни `tracing`/`log` скомпилированы с `max_level_off`. Управление логами выполняется исключительно через секцию `log` в JSON-конфигурации (`level`: `trace`/`debug`/`info`/`warn`/`error`, `output`: `stderr`/`stdout`/путь к файлу, `timestamp`, `disabled`) или динамически через Clash API (`PATCH /configs` -> `log-level`, с поддержкой временного уровня по TTL 5–300 с).
- **Файл журнала и ротация**: стандартный путь подробного лога — `/tmp/tachyon-core/tachyon-core.log`. При превышении `2 MiB` (`MAX_LOG_FILE_BYTES`) файл автоматически усекается до нуля, предотвращая переполнение `tmpfs` на роутере. Последние `1024` строк хранятся в кольцевом буфере в памяти для `GET /logs`.
- **Метрики Prometheus (`GET /metrics`)**: доступны при включённом `clash_api` и экспортируют:
  - `tachyon_memory_rss_bytes` — текущий RSS процесса;
  - `tachyon_process_open_fds`, `tachyon_process_max_fds` — открытые файловые дескрипторы и мягкий лимит;
  - `tachyon_traffic_upload_bytes_total`, `tachyon_traffic_download_bytes_total`, `tachyon_outbound_connections_active`;
  - `tachyon_udp_nat_active`, `tachyon_udp_nat_evictions_total`, `tachyon_inbound_cap_drops_total`;
  - `tachyon_fakeip_v4_used`, `tachyon_fakeip_v4_capacity`, `tachyon_fakeip_evictions_total`;
  - `tachyon_dns_cache_hits_total`, `tachyon_dns_cache_misses_total`;
  - счётчики сбоев и перезагрузок (`telemetry.rs`).
- **Классификация сетевых ошибок (`DialErrorClass`)**: телеметрия автоматически группирует причины отказов по классам: `dns_fail`, `connect_timeout`, `tcp_reset`, `tls_handshake_fail`, `reality_auth_fail`, `quic_timeout`, `auth_rejected`, `eof_early`, `cert_pin_mismatch`, `io_other` (строки деталей санитизируются и обрезаются до 160 символов, без секретов и query-параметров).

### Типовые симптомы и способы устранения

| Симптом | Вероятная причина | Проверка и решение |
|---|---|---|
| Процесс падает на старте с `SIGILL` (код `132`) на роутере MIPS или старом ARM | Установлен бинарник не той архитектуры или собран без `+soft-float` / с принудительным `+neon`. | Проверить `uname -m` и `cat /proc/cpuinfo`; использовать релизный артефакт `mipsel`/`mips` (soft-float) или `armv6`/`armv7` без `+neon`. |
| Нет записей в журнале при установленном `RUST_LOG=debug` | `RUST_LOG` игнорируется; либо `log.disabled: true`, либо `log.output` указывает на файл (тогда консоль пуста). | Задать `"log": {"level": "debug", "output": "/tmp/tachyon-core/tachyon-core.log"}` или проверить `GET /logs`. |
| `EMFILE: Too many open files` под нагрузкой | Наследованный жёсткий лимит `RLIMIT_NOFILE` слишком мал (`core-cli` поднимает soft до `min(hard, 65535)`). | Проверить `tachyon_process_open_fds` / `tachyon_process_max_fds`; в init-скрипте OpenWrt `procd` задать `procd_set_param limits nofile="65535 65535"` (в systemd: `LimitNOFILE=65535`). |
| OOM Killer на роутере или обрыв Jetsam на iOS | Загружены крупные JSON/SRS `rule_set` в heap, не задан лимит памяти или слишком много одновременных потоков. | Перевести наборы правил на `.trs` (`mmap`); проверить `TACHYON_MEMLIMIT_MB` / `GOMEMLIMIT`; отслеживать `tachyon_memory_rss_bytes` и `tachyon_pool_purges_total`; отключить `store_dns` на `< 64 MiB`. |
| `EADDRINUSE` при ручном перезапуске или смене конфига | Предыдущий процесс ещё завершает сокеты или внешний процесс занял порт. | Использовать `SIGHUP` (горячая перезагрузка `reload_in_place` не закрывает неизменившиеся инбаунды); предварительно проверять применимость через `tachyon-core reload-preview --current ...`. |
| REALITY устанавливает TLS, но трафик не идёт (попадает на маскировочный сайт) | Несовпадение `public_key`, `short_id`, `server_name`, либо расхождение системных часов роутера (часто после холодной загрузки без батарейки RTC). | Проверить `reality_auth_fail` и логи `RealityVerifier`; включить секцию `ntp` в конфиге (`NTP_OFFSET_MS` автоматически скорректирует проверку времени TLS/REALITY). |
| После перезагрузки не открываются сайты по FakeIP («missing fakeip record») | Отключён `store_fakeip` или `cache.db` лежит в `/tmp/` и стирается при ребуте, а клиенты держат старые DNS-записи. | Включить `experimental.cache_file.enabled: true` и `store_fakeip: true` с путём на постоянном разделе (`/etc/tachyon-core/cache.db`); `.ephemeral` при этом останется в `/tmp/tachyon-core/`. |
| Ядро не стартует на роутере без интернета при загрузке | Отключён мягкий старт `TACHYON_RULESET_SOFT_START=0` при наличии удалённых `rule_set`. | Убрать `TACHYON_RULESET_SOFT_START=0` (по умолчанию мягкий старт включён: ядро поднимется сразу и догрузит наборы правил при появлении WAN). |
| Низкая скорость QUIC (`hysteria2`, `tuic`, `masque`) на Linux | Системные лимиты буферов UDP (`rmem_max`/`wmem_max`) меньше `udp_socket_buffer`. | Увеличить `net.core.rmem_max` и `net.core.wmem_max` (например, до `4194304` на роутере с 256+ MiB или `16777216` на сервере). |

---

## 5. Эксплуатационный чеклист

### Перед развёртыванием на роутере (OpenWrt)

1. Проверить архитектуру (`uname -m`, endianness MIPS, наличие FPU/AES в `/proc/cpuinfo`) и сверить контрольную сумму бинарника/пакета с `SHA256SUMS`.
2. Проверить конфигурацию на валидность перед запуском: `tachyon-core check -c /etc/tachyon-core/config.json`.
3. Разместить `log.output` в `/tmp/tachyon-core/tachyon-core.log` (в `tmpfs`, никогда не на flash).
4. При использовании `experimental.cache_file` убедиться, что `path` указывает на `/etc/tachyon-core/cache.db` (основной и `.volatile` сохраняются между перезагрузками, а `EPHEMERAL_BUCKETS` и `.lock` автоматически уходят в `/tmp/tachyon-core/`).
5. Использовать бинарные `.trs` наборы правил в режиме `mmap` (кэш по умолчанию `/tmp/tachyon-rulesets/`).
6. Включить секцию `ntp` на роутерах без аппаратных часов (RTC) для корректной работы TLS и REALITY сразу после старта.
7. Поднять `nofile` в `procd` (`limits nofile="65535 65535"`) и при наличии `<= 128 MiB` RAM при необходимости ограничить бюджет через `TACHYON_MEMLIMIT_MB`.
8. Для обновлений правил и аутбаундов без разрыва сессий использовать `tachyon-core reload-preview`, затем `SIGHUP` (или `PUT /configs`) и при необходимости `POST /tachyon/route-recheck`.

### Перед развёртыванием на сервере (Linux 10G+)

1. Поднять системные лимиты: `LimitNOFILE=65535`, `net.core.rmem_max=16777216`, `net.core.wmem_max=16777216`, `net.ipv4.tcp_congestion_control=bbr` (или `TACHYON_TCP_CONGESTION=bbr`).
2. Проверить стартовую строку `HardwareProfile` в логе: подтвердить `workers`, аппаратный ISA (`vaes+vpclmulqdq` / `aes+pmull`) и `crypto` GiB/s.
3. Если контейнер запущен в Docker/Kubernetes с ограничением ресурсов — проверить корректность `memory.max` и `cpu.max` в cgroup v2 (либо явно задать `TACHYON_MEMLIMIT_MB` и `TACHYON_WORKERS`).
4. При открытии `clash_api` привязать `external_controller` к `127.0.0.1` (или защищённому интерфейсу) и обязательно задать `secret`.
5. Настроить сбор метрик с `GET /metrics` (RSS, open FDs, UDP NAT, DNS cache hit ratio, активные соединения).

---

## Навигация

- [Оглавление документации](../README.md)
- [CLI и параметры рантайма](./cli-and-runtime.md)
- [Clash API и Tachyon REST API](./clash-and-tachyon-api.md)
- [Аппаратная адаптация, управление памятью и защита flash](../01-architecture/memory-and-hardware.md)
- [Криптография, TLS, uTLS, REALITY, ECH и QUIC](../01-architecture/crypto-and-tls.md)
- [Интеграция с OpenWrt](../05-integration/openwrt.md)
- [Мобильные платформы (iOS и Android)](../05-integration/mobile-ios-android.md)
- [Примеры конфигураций](../06-examples/README.md)
