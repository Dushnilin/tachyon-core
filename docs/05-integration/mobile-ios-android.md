# Интеграция `tachyon-core` на мобильных платформах (iOS и Android)

Руководство описывает встраивание `tachyon-core` (v0.6.2) в мобильные VPN-клиенты на iOS (`NEPacketTunnelProvider` через `TachyonCore.xcframework`) и Android (`VpnService` через JNI-библиотеку `libtachyon.so` или автономный PIE-бинарник).

---

## iOS (`NEPacketTunnelProvider` + `TachyonCore.xcframework`)

### Релизный артефакт и структура XCFramework

В каждом релизе публикуется архив `tachyon-core-ios-xcframework-v0.6.2.tar.gz`, содержащий `TachyonCore.xcframework` со статическими библиотеками для двух срезов:

| Срез XCFramework | Целевой профиль Rust | Назначение |
|---|---|---|
| `ios-arm64` | `aarch64-apple-ios` | Физические устройства iPhone / iPad (ARMv8 AES/PMULL/NEON) |
| `ios-arm64-simulator` | `aarch64-apple-ios-sim` | Симулятор iOS на Apple Silicon |

Внутри каждого среза в каталоге `Headers/` находятся:
- `tachyon_core.h` — заголовочный файл C ABI (см. [Встраивание через Rust и C ABI](embedding-rust-and-c.md));
- `module.modulemap`:
  ```text
  module TachyonCore {
      header "tachyon_core.h"
      export *
  }
  ```

### Подключение в Xcode

1. Распакуйте `TachyonCore.xcframework` и добавьте его в проект Xcode.
2. В настройках таргета Network Extension (**PacketTunnel**) в разделе **Frameworks and Libraries** укажите `TachyonCore.xcframework` со значением **Do Not Embed** (статическая библиотека линкуется внутрь бинарника расширения).
3. Подключите системные фреймворки `NetworkExtension`, `Security`, `SystemConfiguration`, `libresolv.tbd`.
4. В Swift-коде импортируйте модуль: `import TachyonCore`.

### Лимит памяти iOS Jetsam (50 MiB) и автоматическая адаптация

Расширение `NEPacketTunnelProvider` на iOS ограничено жёстким лимитом памяти Jetsam (~50 MiB) независимо от объёма физической ОЗУ устройства. При компиляции под `target_os = "ios"` ядро адаптируется автоматически:
- `HardwareProfile::detect()` ограничивает расчётный профиль ОЗУ потолком `50 MiB`, независимо от значения `sysctl hw.memsize`;
- рантайм Tokio во встроенном C ABI ограничивает число рабочих потоков значением `min(hw.workers, 2)` (если не переопределено через `TACHYON_WORKERS`);
- буферы потоков (`32..=56 KiB`), пулы ретрансляции, ёмкость кэша DNS, FakeIP и таблицы UDP NAT масштабируются под профиль 50 MiB;
- фоновая задача мониторинга давления памяти и эндпоинт `POST /tachyon/memory/trim` очищают пулы буферов и кэши при росте RSS.

Дополнительные рекомендации для конфигурации iOS (см. также [Пример компактного мобильного конфига](../06-examples/07-mobile-embedded-tun.json)):
- используйте компактные `.trs`-наборы правил (zero-copy `mmap`, не загружающие деревья правил в кучу процесса);
- задавайте `auto_route: false` в инбаунде `tun` (маршрутами и DNS управляет `NEPacketTunnelNetworkSettings`);
- храните `cache.db` в общем App Group контейнере (`FileManager.default.containerURL(forSecurityApplicationGroupIdentifier:)`).

### Жизненный цикл и передача `tun_fd`

На iOS процесс расширения не может самостоятельно открывать `utun` — файловый дескриптор выдаётся системой после вызова `setTunnelNetworkSettings(...)`.
- Передайте полученный `tun_fd >= 0` вторым аргументом в `tachyon_core_start(config_json, tun_fd)`.
- Движок валидирует исходный JSON-конфиг, после чего автоматически внедряет `"fd": tun_fd` во все инбаунды с `"type": "tun"` и переводит дескриптор в неблокирующий режим (`O_NONBLOCK`).
- При последующем вызове `tachyon_core_reload(new_config_json)` сохранённый `tun_fd` подставляется автоматически; если инбаунды не изменились, выполняется обновление на месте (`reload_in_place`) без обрыва соединений.
- Для режима без TUN (только локальный прокси) передайте `tun_fd = -1`.

### Пример Swift-обёртки и `NEPacketTunnelProvider`

```swift
import Foundation
import NetworkExtension
import TachyonCore

enum TachyonCoreError: LocalizedError {
    case engine(String)

    var errorDescription: String? {
        switch self {
        case .engine(let message): return message
        }
    }
}

final class TachyonBridge {
    static let shared = TachyonBridge()
    private let queue = DispatchQueue(label: "org.tachyon.core.control")

    var version: String {
        String(cString: tachyon_core_version())
    }

    var isRunning: Bool {
        tachyon_core_is_running() == 1
    }

    private func takeLastError() -> String {
        guard let ptr = tachyon_core_last_error() else {
            return "unknown error"
        }
        defer { tachyon_core_string_free(ptr) }
        return String(cString: ptr)
    }

    func check(configJson: String) throws {
        try queue.sync {
            let rc = configJson.withCString { tachyon_core_check($0) }
            if rc != 0 {
                throw TachyonCoreError.engine(takeLastError())
            }
        }
    }

    func start(configJson: String, tunFd: Int32) throws {
        try queue.sync {
            let rc = configJson.withCString { tachyon_core_start($0, tunFd) }
            if rc != 0 {
                throw TachyonCoreError.engine(takeLastError())
            }
        }
    }

    func reload(configJson: String) throws {
        try queue.sync {
            let rc = configJson.withCString { tachyon_core_reload($0) }
            if rc != 0 {
                throw TachyonCoreError.engine(takeLastError())
            }
        }
    }

    func stop() {
        queue.sync {
            _ = tachyon_core_stop()
        }
    }
}

final class PacketTunnelProvider: NEPacketTunnelProvider {
    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.mtu = 1400
        let ipv4 = NEIPv4Settings(addresses: ["172.19.0.1"], subnetMasks: ["255.255.255.252"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4
        settings.dnsSettings = NEDNSSettings(servers: ["172.19.0.2"])

        setTunnelNetworkSettings(settings) { [weak self] error in
            if let error {
                completionHandler(error)
                return
            }
            guard let self else { return }
            guard let tunFd = self.resolveTunnelFileDescriptor() else {
                completionHandler(TachyonCoreError.engine("utun file descriptor not found"))
                return
            }
            do {
                let configJson = try self.loadConfigJson()
                try TachyonBridge.shared.start(configJson: configJson, tunFd: tunFd)
                completionHandler(nil)
            } catch {
                completionHandler(error)
            }
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        TachyonBridge.shared.stop()
        completionHandler()
    }

    private func resolveTunnelFileDescriptor() -> Int32? {
        // KVC для NEPacketTunnelFlow (стандартный способ в NetworkExtension)
        if let fd = packetFlow.value(forKeyPath: "socket.fileDescriptor") as? Int32, fd >= 0 {
            return fd
        }
        return nil
    }

    private func loadConfigJson() throws -> String {
        // Чтение конфигурации из App Group контейнера
        fatalError("provide config.json from App Group container")
    }
}
```

> Все блокирующие вызовы (`tachyon_core_start`, `tachyon_core_reload`, `tachyon_core_stop`) выполняйте на выделенной последовательной очереди (`DispatchQueue`), а не в основном потоке.

---

## Android (`VpnService` + JNI `libtachyon.so`)

### Релизные артефакты и совместимость

Для Android (API 24+ / Android 7.0+) в релизе поставляются два вида артефактов для архитектур `arm64-v8a`, `armeabi-v7a` и `x86_64`:

| ABI Android | JNI-библиотека (встраивание в процесс) | Автономный PIE-бинарник |
|---|---|---|
| `arm64-v8a` | `libtachyon-arm64-v8a.so` | `tachyon-core-aarch64-linux-android-v0.6.2.tar.gz` |
| `armeabi-v7a` | `libtachyon-armeabi-v7a.so` | `tachyon-core-armv7-linux-androideabi-v0.6.2.tar.gz` |
| `x86_64` | `libtachyon-x86_64.so` | `tachyon-core-x86_64-linux-android-v0.6.2.tar.gz` |

Особенности сборки:
- Динамическая линковка с Bionic (NDK API 24+).
- Выравнивание сегментов ELF на **16 КБ** (`-Wl,-z,max-page-size=16384`) для полного соответствия требованиям Android 15/16 (16 KB page size) при сохранении совместимости с устройствами с 4 КБ страницами.
- Для `arm64-v8a` включена runtime-диспетчеризация аппаратных инструкций ARMv8 AES/PMULL/NEON.

Размещение библиотек в Android-проекте (файлы переименовываются в `libtachyon.so`):

```text
app/src/main/jniLibs/
├── arm64-v8a/libtachyon.so
├── armeabi-v7a/libtachyon.so
└── x86_64/libtachyon.so
```

Библиотека загружается вызовом `System.loadLibrary("tachyon")`.

### JNI-интерфейс (`org.tachyon.vpn.TachyonCore`)

Все нативные методы привязаны к классу **`org.tachyon.vpn.TachyonCore`**:

| Метод Kotlin / Java | Возвращаемое значение | Назначение |
|---|---|---|
| `start(config: String, tunFd: Int, protectPath: String, logPath: String): Int` | `0` (успех) или `-1` | Валидирует конфиг, внедряет платформенные параметры и запускает ядро. Блокирующий вызов — выполнять вне main thread, не вызывать параллельно со `stop()`. |
| `stop(): Int` | `0` (успех) или `-1` | Останавливает слушатели, дожидается завершения задач (`shutdown_wait`) и останавливает Tokio-рантайм. Блокирующий вызов. |
| `lastError(): String?` | Строка ошибки | Текст последней ошибки, записанной при возврате `-1`. |
| `version(): String?` | `"0.6.2"` | Версия встроенного ядра. |
| `nativeStats(): String?` | JSON | Счётчики и телеметрия активного балансировщика: `{"running":true,"up":N,"down":N,"connections":M,"balancer":{"tag":...,"now":...,"mode":...,"telemetry":...}}`. |
| `check(config: String): String?` | JSON | Валидация конфигурации без запуска: `{"ok":true,"warnings":[...]}` или `{"ok":false,"error":"..."}`. |
| `fetchSubscription(url: String, customUa: String, sendHwid: Boolean, customHwid: String, insecure: Boolean): String?` | JSON | Адаптивная загрузка и разбор подписки (если ядро запущено, сначала пытается идти через `socks5://127.0.0.1:2080`, затем напрямую). Возвращает `{"ok":true,"body":...,"nodes":[...],"primary_tags":[...],"user_agent":...,"user_info":{...}}` или `{"ok":false,"error":...}`. |
| `parseSubscription(payload: String): String?` | JSON | Офлайн-разбор тела подписки всех форматов: `{"ok":true,"nodes":[...],"primary_tags":[...]}` или `{"ok":false,"error":...}`. |
| `protectOpen(path: String): Int` | `0` или `-1` | Привязывает Unix domain socket по пути `path` (предварительно удаляя старый файл сокета). Вызывать до `start(...)`. |
| `protectLoop(service: Any): Int` | `0` или `-1` | Блокирующий цикл приёма файловых дескрипторов по сокету; для каждого fd вызывает метод `service.protect(int): boolean` (сигнатура JNI `(I)Z`). Выполнять в отдельном фоновом потоке. |
| `protectClose(): Int` | `0` | Останавливает `protectLoop` и закрывает слушающий Unix-сокет. |

### Автоматическая модификация конфигурации внутри `start(...)`

В Android-приложении исходный JSON-документ проходит валидацию `check_str_warnings` как есть (без нестандартных полей), после чего JNI-слой выполняет следующие действия:
1. Разворачивает секции подписок (при их наличии).
2. Если `tunFd >= 0`, вставляет `"fd": tunFd` в каждый инбаунд с `"type": "tun"` (при `tunFd < 0` поле не добавляется — режим без TUN).
3. Если `protectPath` не пуст, вставляет `"protect_path": protectPath` во все записи `outbounds` и `endpoints`, где это поле не задано явно.
4. Удаляет секцию `ntp` (на Android встроенный NTP открывает незащищённый UDP-сокет, который при активном VPN зацикливался бы обратно в TUN).
5. Если `logPath` не пуст, записывает `"log.output": logPath` (при наличии секции `log`) и выполняет `chdir` в родительский каталог `logPath`, чтобы `cache.db` и кэш наборов правил создавались в доступном на запись каталоге приложения, а не в read-only корне процесса.

### Защита исходящих сокетов от петель (`protect_path`)

Когда Android `VpnService` перехватывает весь трафик устройства в TUN, исходящие сокеты самого `tachyon-core` должны быть исключены из VPN через `VpnService.protect(fd)`.

Протокол взаимодействия по Unix-сокету `protect_path`:
1. При создании каждого исходящего сокета `tachyon-core` подключается к Unix domain socket `protect_path`.
2. Отправляет однобайтовую полезную нагрузку с управляющим сообщением `SCM_RIGHTS`, содержащим дескриптор сокета (`RawFd`).
3. Серверная сторона (`protectLoop` внутри `libtachyon.so`, либо внешний helper при использовании PIE-бинарника) принимает дубликат дескриптора, вызывает `VpnService.protect(dupFd)`, закрывает дубликат и отправляет клиенту 1 байт подтверждения (`0x01`).
4. Если `protect()` вернул `false`, сокет закрывается без отправки подтверждения, и ядро трактует соединение как незащищённое (ошибка `failed to protect fd`).

Порядок запуска и остановки:
- **Запуск**: `protectOpen(protectSock)` -> запуск потока `protectLoop(vpnService)` -> `VpnService.Builder().establish()` -> `start(config, tunFd, protectSock, logPath)`.
- **Остановка**: `stop()` -> `protectClose()` -> `tunInterface.close()`.

### Пример Kotlin-обёртки и `VpnService`

```kotlin
package org.tachyon.vpn

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.File
import java.util.concurrent.Executors

object TachyonCore {
    init {
        System.loadLibrary("tachyon")
    }

    external fun start(config: String, tunFd: Int, protectPath: String, logPath: String): Int
    external fun stop(): Int
    external fun lastError(): String?
    external fun version(): String?
    external fun nativeStats(): String?
    external fun check(config: String): String?
    external fun fetchSubscription(
        url: String,
        customUa: String,
        sendHwid: Boolean,
        customHwid: String,
        insecure: Boolean
    ): String?
    external fun parseSubscription(payload: String): String?
    external fun protectOpen(path: String): Int
    external fun protectLoop(service: VpnService): Int
    external fun protectClose(): Int
}

class TachyonVpnService : VpnService() {
    private val controlExecutor = Executors.newSingleThreadExecutor()
    @Volatile private var tunPfd: ParcelFileDescriptor? = null
    @Volatile private var protectThread: Thread? = null

    fun startCore(configJson: String) {
        controlExecutor.execute {
            val workDir = File(filesDir, "tachyon").apply { mkdirs() }
            val protectSock = File(workDir, "protect.sock").absolutePath
            val logPath = File(workDir, "tachyon-core.log").absolutePath

            check(TachyonCore.protectOpen(protectSock) == 0) {
                "protectOpen failed: ${TachyonCore.lastError()}"
            }

            val loopThread = Thread({
                TachyonCore.protectLoop(this@TachyonVpnService)
            }, "tachyon-protect").apply {
                isDaemon = true
                start()
            }
            protectThread = loopThread

            val pfd = Builder()
                .setSession("Tachyon")
                .setMtu(1400)
                .addAddress("172.19.0.1", 30)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("172.19.0.2")
                .addDisallowedApplication(packageName)
                .establish()
                ?: throw IllegalStateException("VpnService.Builder.establish() returned null")
            tunPfd = pfd

            val rc = TachyonCore.start(configJson, pfd.fd, protectSock, logPath)
            if (rc != 0) {
                val err = TachyonCore.lastError()
                TachyonCore.protectClose()
                pfd.close()
                tunPfd = null
                throw IllegalStateException("TachyonCore.start failed: $err")
            }
        }
    }

    fun stopCore() {
        controlExecutor.execute {
            TachyonCore.stop()
            TachyonCore.protectClose()
            protectThread?.join(500)
            protectThread = null
            tunPfd?.close()
            tunPfd = null
        }
    }

    override fun onDestroy() {
        stopCore()
        controlExecutor.shutdown()
        super.onDestroy()
    }

    override fun onRevoke() {
        stopCore()
        stopSelf()
        super.onRevoke()
    }
}
```

### Использование автономного PIE-бинарника на Android

Если архитектура приложения запускает `tachyon-core` как дочерний процесс вместо JNI (`libtachyon.so`):
- Поместите бинарник `tachyon-core` в `jniLibs/<abi>/libtachyon_exec.so` (чтобы Android извлёк его с правом на исполнение в `applicationInfo.nativeLibraryDir`, с учётом `android:extractNativeLibs="true"`).
- Создайте сервер Unix-сокета в приложении (`LocalServerSocket` / `UnixServerSocket`), принимающий `SCM_RIGHTS` + 1 байт и отвечающий 1 байтом после `VpnService.protect(fd)`.
- Передайте `tun_fd` через унаследованный дескриптор и переменную окружения `TACHYON_TUN_FD` (или поле `fd`), а путь к сокету — через `protect_path` в каждом аутбаунде/эндпоинте.
