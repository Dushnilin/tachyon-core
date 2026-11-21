# Встраивание `tachyon-core` как библиотеки (C ABI и Rust)

`tachyon-core` (v0.6.2) можно встраивать непосредственно в процесс хост-приложения двумя способами:
1. через стабильный **C ABI** (`include/tachyon_core.h`) — для C, C++, Swift, Objective-C, Go (`cgo`), C# (P/Invoke), Python (`ctypes`) и других языков;
2. напрямую на **Rust** через публичный API крейтов `core-config` и `core-runtime`.

---

## Часть 1. Встраивание через C ABI (`include/tachyon_core.h`)

### Сборка статической или динамической библиотеки

Символы C ABI экспортируются крейтом `core-runtime`:

```bash
# Статическая библиотека (libcore_runtime.a / core_runtime.lib)
cargo rustc -p core-runtime --release --crate-type staticlib

# Динамическая библиотека (libcore_runtime.so / libcore_runtime.dylib / core_runtime.dll)
cargo rustc -p core-runtime --release --crate-type cdylib
```

Заголовочный файл расположен в `include/tachyon_core.h`. Для Android JNI используется отдельный крейт `core-ffi` (`libtachyon.so`), описанный в [Мобильной интеграции](mobile-ios-android.md).

### Экспортируемые функции

| Сигнатура C | Возвращаемое значение | Описание |
|---|---|---|
| `const char *tachyon_core_version(void)` | Статическая NUL-строка (например, `"0.6.2"`) | Возвращает версию движка. **Не передавать** в `tachyon_core_string_free`. |
| `char *tachyon_core_last_error(void)` | Строка в куче или `NULL` | Возвращает копию последнего сообщения об ошибке или `NULL`, если ошибки не было. **Обязательно освобождать** через `tachyon_core_string_free`. |
| `void tachyon_core_string_free(char *ptr)` | `void` | Освобождает строку, возвращённую `tachyon_core_last_error`. Безопасен для `NULL`. |
| `int32_t tachyon_core_check(const char *config_json)` | `0` (валидно) или `-1` (ошибка) | Проверяет JSON-конфигурацию (включая разворачивание `subscription` и `fptn`) без запуска слушателей. |
| `int32_t tachyon_core_start(const char *config_json, int32_t tun_fd)` | `0` (успех) или `-1` (ошибка) | Валидирует конфигурацию, внедряет `tun_fd` (если `>= 0`) в `tun`-инбаунды и запускает движок на встроенном Tokio-рантайме. |
| `int32_t tachyon_core_reload(const char *config_json)` | `0` (успех) или `-1` (ошибка) | Обновляет конфигурацию запущенного экземпляра с сохранением исходного `tun_fd`. Использует `reload_in_place`, если слушатели не изменились, иначе выполняет чистый рестарт на том же рантайме. |
| `int32_t tachyon_core_stop(void)` | `0` | Останавливает работающий экземпляр и завершает встроенный рантайм. Идемпотентен (повторный вызов на остановленном движке возвращает `0`). |
| `int32_t tachyon_core_is_running(void)` | `1` (работает) или `0` (остановлен) | Проверяет наличие активной встроенной сессии. |

### Владение памятью, ошибки и потокобезопасность

1. **Владение строками**:
   - Входные указатели `config_json` должны указывать на валидную NUL-терминированную UTF-8 строку и заимствуются только на время вызова функции (после возврата вызывающая сторона может освободить буфер).
   - Указатель из `tachyon_core_version()` указывает на статическую память; попытка освободить его через `free()` или `tachyon_core_string_free()` приводит к неопределённому поведению.
   - Указатель из `tachyon_core_last_error()` принадлежит вызывающей стороне и должен освобождаться строго через `tachyon_core_string_free()` (не через системный `free()`).
2. **Обработка ошибок**:
   - Каждый вызов `tachyon_core_check`, `tachyon_core_start`, `tachyon_core_reload` и `tachyon_core_stop` очищает буфер последней ошибки в начале выполнения.
   - При возврате `-1` текст причины считывается через `tachyon_core_last_error()`. Нулевые байты внутри сообщения (если бы они встретились) заменяются пробелами.
3. **Один экземпляр на процесс и потокобезопасность**:
   - Внутри процесса существует ровно одна глобальная сессия (DNS-сервис, реестр соединений Clash и приёмник логов являются глобальными для процесса).
   - Внутреннее состояние защищено мьютексами, однако буфер `LAST_ERROR` — один на процесс. Сериализуйте все управляющие вызовы (`check`, `start`, `reload`, `stop`, `last_error`) на выделенном потоке управления.
   - `tachyon_core_start`, `tachyon_core_reload` и `tachyon_core_stop` являются **блокирующими** (запускают `block_on` на встроенном рантайме Tokio) — не вызывайте их из UI-потока.
   - Если `tachyon_core_start` вызывается при уже работающей сессии, предыдущая сессия предварительно останавливается (с таймаутом рантайма 250 мс) перед запуском новой.

### Пример интеграции на C (C11)

```c
#include <stdio.h>
#include <stdlib.h>
#include "tachyon_core.h"

static void print_last_error(const char *op) {
    char *err = tachyon_core_last_error();
    if (err != NULL) {
        fprintf(stderr, "%s failed: %s\n", op, err);
        tachyon_core_string_free(err);
    } else {
        fprintf(stderr, "%s failed: unknown error\n", op);
    }
}

int main(void) {
    printf("Embedded tachyon-core version: %s\n", tachyon_core_version());

    const char *cfg_v1 =
        "{"
        "  \"log\": {\"level\": \"info\"},"
        "  \"inbounds\": [{\"type\": \"mixed\", \"tag\": \"in\", \"listen\": \"127.0.0.1\", \"listen_port\": 2080}],"
        "  \"outbounds\": [{\"type\": \"direct\", \"tag\": \"direct\"}]"
        "}";

    if (tachyon_core_check(cfg_v1) != 0) {
        print_last_error("check");
        return EXIT_FAILURE;
    }

    /* tun_fd = -1: режим без внешнего TUN-дескриптора */
    if (tachyon_core_start(cfg_v1, -1) != 0) {
        print_last_error("start");
        return EXIT_FAILURE;
    }

    printf("is_running = %d\n", tachyon_core_is_running());

    const char *cfg_v2 =
        "{"
        "  \"log\": {\"level\": \"warn\"},"
        "  \"inbounds\": [{\"type\": \"mixed\", \"tag\": \"in\", \"listen\": \"127.0.0.1\", \"listen_port\": 2080}],"
        "  \"outbounds\": [{\"type\": \"direct\", \"tag\": \"direct\"}]"
        "}";

    if (tachyon_core_reload(cfg_v2) != 0) {
        print_last_error("reload");
    }

    tachyon_core_stop();
    printf("stopped, is_running = %d\n", tachyon_core_is_running());
    return EXIT_SUCCESS;
}
```

Пример линковки на Linux (с `libcore_runtime.a`):

```bash
cc -std=c11 -Iinclude main.c target/release/libcore_runtime.a -lpthread -ldl -lm -o host_app
```

---

## Часть 2. Прямое встраивание на Rust (`core-config` и `core-runtime`)

### Зависимости и Cargo-фичи

```toml
[dependencies]
core-config = { path = "crates/core-config" }
core-runtime = { path = "crates/core-runtime" }
serde_json = "1"
tokio = { version = "1", features = ["rt-multi-thread", "signal"] }
anyhow = "1"
```

Фичи крейта `core-runtime`:
- `full` (включена по умолчанию) — включает `clash-api` и полный набор протоколов `core-config/full`;
- `clash-api` — встроенный HTTP/WebSocket контроллер Clash и `/tachyon/*`;
- `legacy-openvpn-ciphers` — дополнительные устаревшие шифры OpenVPN (Blowfish, CAST5, DES, Camellia, ARIA, SM4, SEED, RIPEMD);
- `allocstat` — диагностический счётчик аллокаций (только для профилирования).

### Публичный API `core-config`

| Функция | Сигнатура | Назначение |
|---|---|---|
| `check_str` | `pub fn check_str(raw: &str) -> Result<(), String>` | Полная валидация JSON-конфигурации (разворачивает `subscription` и `fptn`, возвращает `tachyon-core` сообщения об ошибках). |
| `check_str_warnings` | `pub fn check_str_warnings(raw: &str) -> Result<Vec<String>, String>` | То же, но дополнительно возвращает список предупреждений об устаревших опциях. |
| `humanize_config_error` | `pub fn humanize_config_error(err: String) -> String` | Приводит диагностическое сообщение об ошибке схемы к единому читаемому формату. |
| `import_profile_to_config` | `pub use subscription::import_profile_to_config` | Конвертация внешнего профиля/подписки в JSON-конфигурацию `tachyon-core`. |
| `convert_clash_yaml_config` | `pub use subscription::convert_clash_yaml_config` | Конвертация конфигурации Clash YAML в JSON-схему `tachyon-core`. |
| `convert_xray_json_config` | `pub use subscription::convert_xray_json_config` | Конвертация конфигурации Xray JSON в JSON-схему `tachyon-core`. |

### Публичный API `core-runtime`

#### Запуск, перезагрузка и жизненный цикл `BoxInstance`

| Элемент | Сигнатура | Назначение |
|---|---|---|
| `start` | `pub async fn start(root: &Value) -> anyhow::Result<BoxInstance>` | Запускает все подсистемы (логирование, `cache_file`, маршрутизатор, DNS, Clash API, эндпоинты, инбаунды). При ошибке на любом этапе откатывает уже поднятые задачи. |
| `run` | `pub async fn run(config_path: &Path) -> anyhow::Result<()>` | Читает файл, запускает `BoxInstance` и блокируется до `SIGTERM` / `SIGINT`. |
| `run_str` | `pub async fn run_str(raw: &str) -> anyhow::Result<()>` | То же из JSON-строки. |
| `run_reloadable` | `pub async fn run_reloadable<F>(load: F) -> anyhow::Result<()>` | Запуск с полной поддержкой `SIGHUP` (горячая перезагрузка `in_place` или рестарт слушателей с автооткатом). |
| `can_reload_in_place` | `pub fn can_reload_in_place(old_root: &Value, new_root: &Value) -> bool` | Определяет, можно ли применить `new_root` без пересоздания слушателей. |
| `reload_router_in_place` | `pub async fn reload_router_in_place(router: &Arc<Router>, new_root: &Value) -> anyhow::Result<()>` | Атомарно обновляет маршрутизатор, DNS и аутбаунды поверх разделяемого `Arc<Router>`. |
| `config_digest` | `pub fn config_digest(root: &Value) -> String` | Вычисляет SHA-256 (64 hex-символа) от сериализованного JSON-документа. |

Методы `BoxInstance`:

| Метод | Сигнатура | Назначение |
|---|---|---|
| `inbound_addrs` | `pub fn inbound_addrs(&self) -> &[(String, SocketAddr)]` | Список `(tag, local_addr)` всех запущенных инбаундов. |
| `clash_api_addr` | `pub fn clash_api_addr(&self) -> Option<SocketAddr>` | Адрес прослушивания Clash/Tachyon API (если включён). |
| `router` | `pub fn router(&self) -> Arc<Router>` | Ссылка на работающий маршрутизатор. |
| `dns` | `pub fn dns(&self) -> Option<Arc<dns::DnsService>>` | Ссылка на активный DNS-сервис (если настроен). |
| `cache_file` | `pub fn cache_file(&self) -> Option<cache_file::SharedCacheFile>` | Дескриптор открытого хранилища `cache.db`. |
| `reload_in_place` | `pub async fn reload_in_place(&mut self, new_root: &Value) -> anyhow::Result<()>` | Обновляет маршрутизатор, DNS, наборы правил, аутбаунды и уровень лога без остановки инбаундов и обрыва соединений. |
| `shutdown` | `pub fn shutdown(&self)` | Немедленно отменяет задачи слушателей и сбрасывает кэш (вызывается также в `Drop`). |
| `shutdown_wait` | `pub async fn shutdown_wait(&mut self)` | Корректное завершение: отменяет задачи, дожидается освобождения всех UDP/QUIC-сокетов, завершает эндпоинты и снимает блокировку `cache.db`. |

#### Телеметрия, аппаратный профиль и логирование

| Модуль | Ключевые публичные API | Назначение |
|---|---|---|
| `core_runtime::hardware` | `HardwareProfile::detect()`, `pin_runtime_thread()`, `process_memory_bytes()`, `system_available_ram_bytes()`, `memory_pressure_level()`, `purge_all_runtime_pools()`, `HardwareIdentity::detect()` | Определение числа воркеров/буферов под железо, мониторинг RSS и давления памяти, очистка пулов. |
| `core_runtime::clash_state` | `traffic_totals() -> (u64, u64)`, `snapshot()`, `stats_snapshot(reset)`, `device_traffic_snapshot()`, `set_device_rate_limit(ip, up, down)`, `close(id)`, `close_all()`, `recheck_routes(&router)` | Живые счётчики трафика, реестр соединений, пер-устройственный QoS и перевалидация маршрутов. |
| `core_runtime::telemetry` | `uptime_secs()`, `reload_totals()`, `last_reload_info()`, `process_fd_stats()`, `udp_nat_active()`, `dns_cache_counters()`, `outbound_metrics_snapshot()`, `dns_metrics_snapshot()`, `anomalies_snapshot(min_fail, min_rate)` | Системная и протокольная телеметрия без обращения по HTTP. |
| `core_runtime::logging` | `subscribe() -> (u64, Receiver<(Level, String)>)`, `unsubscribe(id)`, `recent(level)`, `recent_structured(level, limit)`, `set_level(raw)`, `set_level_with_ttl(raw, ttl_sec)` | Подписка на живой поток логов и динамическое управление уровнем журналирования. |

> **Ограничение глобального состояния:** подсистемы DNS, `clash_state` и `logging` хранят состояние на уровне процесса. Внутри одного процесса должен работать не более чем один активный `BoxInstance`; в интеграционных тестах доступ к запуску экземпляров необходимо сериализовать мьютексом.

### Пример встраивания на Rust

```rust
use std::time::Duration;
use anyhow::Context;
use serde_json::Value;

fn build_runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    let hw = core_runtime::hardware::HardwareProfile::detect();
    let rt = if hw.workers == 1 {
        tokio::runtime::Builder::new_current_thread()
            .event_interval(31)
            .max_blocking_threads(hw.max_blocking_threads)
            .on_thread_start(core_runtime::hardware::pin_runtime_thread)
            .enable_all()
            .build()?
    } else {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(hw.workers)
            .event_interval(31)
            .max_blocking_threads(hw.max_blocking_threads)
            .on_thread_start(core_runtime::hardware::pin_runtime_thread)
            .enable_all()
            .build()?
    };
    Ok(rt)
}

fn main() -> anyhow::Result<()> {
    let raw_v1 = r#"{
        "log": { "level": "info", "timestamp": true },
        "inbounds": [
            { "type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080 }
        ],
        "outbounds": [
            { "type": "direct", "tag": "direct" }
        ]
    }"#;

    // 1. Валидация конфигурации до старта
    let warnings = core_config::check_str_warnings(raw_v1)
        .map_err(|e| anyhow::anyhow!("config check failed: {e}"))?;
    for w in warnings {
        eprintln!("[WARN] {w}");
    }
    let root_v1: Value = serde_json::from_str(raw_v1).context("parse json")?;

    let rt = build_runtime()?;
    let run_res: anyhow::Result<()> = rt.block_on(async {
        // 2. Подписка на события логов (опционально)
        let (log_sub_id, mut log_rx) = core_runtime::logging::subscribe();
        let log_task = tokio::spawn(async move {
            while let Some((lvl, msg)) = log_rx.recv().await {
                eprintln!("[embedded:{}] {msg}", lvl.as_str());
            }
        });

        // 3. Запуск экземпляра
        let mut instance = core_runtime::start(&root_v1).await?;
        println!("Started inbounds: {:?}", instance.inbound_addrs());

        // 4. Чтение телеметрии напрямую из процесса
        let (up, down) = core_runtime::clash_state::traffic_totals();
        let (rss, _) = core_runtime::hardware::process_memory_bytes();
        println!("uptime={}s up={up} down={down} rss={rss}", core_runtime::telemetry::uptime_secs());

        // 5. Горячая перезагрузка конфигурации (пример)
        let raw_v2 = raw_v1.replace("\"info\"", "\"warn\"");
        core_config::check_str(&raw_v2).map_err(|e| anyhow::anyhow!("{e}"))?;
        let root_v2: Value = serde_json::from_str(&raw_v2)?;

        if core_runtime::can_reload_in_place(&root_v1, &root_v2) {
            instance.reload_in_place(&root_v2).await?;
        } else {
            instance.shutdown_wait().await;
            instance = core_runtime::start(&root_v2).await?;
        }

        // 6. Ожидание сигнала завершения и корректная остановка
        let _ = tokio::signal::ctrl_c().await;
        instance.shutdown_wait().await;

        core_runtime::logging::unsubscribe(log_sub_id);
        log_task.abort();
        Ok(())
    });

    rt.shutdown_timeout(Duration::from_millis(250));
    run_res
}
```
