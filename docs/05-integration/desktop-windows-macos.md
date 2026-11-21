# Интеграция `tachyon-core` на Windows и macOS

Руководство описывает установку и эксплуатацию `tachyon-core` (v0.6.2) на настольных ОС Windows и macOS: работу с TUN-интерфейсами (встроенный Wintun и нативный `utun`), настройку системного прокси, автозапуск в виде службы и способы интеграции движка в настольные приложения.

## Загрузка и подготовка бинарников

| Платформа | Релизный артефакт | Исполняемый файл | Целевой профиль |
|---|---|---|---|
| Windows x86_64 | `tachyon-core-windows-amd64-v0.6.2.zip` | `tachyon-core.exe` | `x86_64-pc-windows-msvc` |
| macOS Apple Silicon | `tachyon-core-darwin-arm64-v0.6.2.tar.gz` | `tachyon-core` | `aarch64-apple-darwin` (ARMv8 AES/PMULL/NEON) |
| macOS Intel | `tachyon-core-darwin-amd64-v0.6.2.tar.gz` | `tachyon-core` | `x86_64-apple-darwin` |

### macOS: снятие карантина Gatekeeper

После распаковки архива, загруженного браузером, снимите атрибут карантина:

```bash
tar -xzf tachyon-core-darwin-arm64-v0.6.2.tar.gz
sudo install -m 0755 tachyon-core-darwin-arm64-v0.6.2 /usr/local/bin/tachyon-core
sudo xattr -dr com.apple.quarantine /usr/local/bin/tachyon-core
tachyon-core version
```

---

## Режим TUN

### Windows: встроенный драйвер Wintun

`tachyon-core.exe` содержит подписанный драйвер ядра Wintun (`wintun.sys`, `wintun.cat`, `wintun.inf`) непосредственно внутри исполняемого файла и взаимодействует с `wintun.sys` напрямую через кольцевые буферы (`TUN_IOCTL_REGISTER_RINGS`). **Отдельный файл `wintun.dll` не требуется.**

Особенности работы:
- Для установки драйвера в Windows Driver Store, создания виртуального сетевого адаптера и настройки маршрутов (`auto_route: true`) процесс должен быть запущен **от имени Администратора** (или как служба Windows под учётной записью `LocalSystem`).
- При запуске без прав Администратора движок записывает предупреждение в лог и переводит `tun`-инбаунд в пассивный режим без аварийного завершения остальных инбаундов.
- При завершении работы процесс удаляет созданный программный адаптер и маршруты.

Пример секции `inbounds` для Windows:

```json
{
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "interface_name": "TachyonTun",
      "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
      "mtu": 1500,
      "auto_route": true,
      "strict_route": true,
      "stack": "gvisor"
    }
  ]
}
```

### macOS: нативный интерфейс `utun`

На macOS `tachyon-core` открывает системный интерфейс `utun` через сокет `AF_SYSTEM` (`com.apple.net.utun_control`):
- Требуются права `root` (например, через `sudo` или `LaunchDaemon`), либо интеграция внутри `NetworkExtension` (`NEPacketTunnelProvider`) с передачей готового дескриптора через `tachyon_core_start(config_json, tun_fd)` или `TACHYON_TUN_FD`.
- Если в `interface_name` указано имя вида `utunN`, движок запрашивает указанный юнит; при произвольном имени ядро macOS выделяет свободный `utunX`.
- При `auto_route: true` движок автоматически:
  1. поднимает интерфейс и назначает MTU/адреса через `/sbin/ifconfig`;
  2. привязывает исходящие сокеты самого ядра к физическому интерфейсу по умолчанию (`IP_BOUND_IF` / `IPV6_BOUND_IF`), предотвращая маршрутные петли;
  3. добавляет маршруты IPv4/IPv6 через `/sbin/route`;
  4. перенастраивает DNS на активных сетевых службах через `/usr/sbin/networksetup -setdnsservers` и очищает кэш `mDNSResponder`;
  5. при корректном завершении (`SIGTERM` / `SIGINT`) восстанавливает исходные DNS-серверы и удаляет добавленные маршруты.

Пример секции `inbounds` для macOS:

```json
{
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "interface_name": "utun9",
      "address": ["172.19.0.1/30"],
      "mtu": 1500,
      "auto_route": true,
      "stack": "gvisor"
    }
  ]
}
```

---

## Режим системного прокси (`mixed` / `http`)

Если права Администратора / `root` недоступны или требуется проксировать только приложения, поддерживающие HTTP/SOCKS-прокси, используйте инбаунд `mixed` или `http`:

```json
{
  "inbounds": [
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "127.0.0.1",
      "listen_port": 2080,
      "set_system_proxy": false
    }
  ]
}
```

> **Примечание о `set_system_proxy`:** поле `set_system_proxy` принимается валидатором конфигурации `tachyon-core` для совместимости со схемой sing-box, но сам процесс `tachyon-core` не модифицирует системный реестр Windows и настройки прокси macOS. Включение/отключение системного прокси ОС выполняется графической оболочкой приложения или скриптом запуска.

### Настройка системного прокси на Windows (PowerShell)

```powershell
# Включить HTTP/HTTPS системный прокси на 127.0.0.1:2080
$reg = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
Set-ItemProperty -Path $reg -Name ProxyEnable -Value 1
Set-ItemProperty -Path $reg -Name ProxyServer -Value "127.0.0.1:2080"
Set-ItemProperty -Path $reg -Name ProxyOverride -Value "localhost;127.*;10.*;172.16.*;192.168.*;<local>"

# Выключить системный прокси
Set-ItemProperty -Path $reg -Name ProxyEnable -Value 0
```

### Настройка системного прокси на macOS (`networksetup`)

```bash
SERVICE="Wi-Fi"

# Включить HTTP, HTTPS и SOCKS5 прокси
networksetup -setwebproxy "$SERVICE" 127.0.0.1 2080
networksetup -setsecurewebproxy "$SERVICE" 127.0.0.1 2080
networksetup -setsocksfirewallproxy "$SERVICE" 127.0.0.1 2080

# Отключить системный прокси
networksetup -setwebproxystate "$SERVICE" off
networksetup -setsecurewebproxystate "$SERVICE" off
networksetup -setsocksfirewallproxystate "$SERVICE" off
```

---

## Автозапуск службы

### Windows: системная служба или Планировщик задач

Поскольку `tachyon-core.exe` является консольным процессом (не реализует Windows Service Control Manager API напрямую), для запуска в качестве Windows Service используйте обёртку WinSW / NSSM либо Планировщик задач Windows.

#### Пример с NSSM (от имени Администратора)

```powershell
mkdir C:\ProgramData\tachyon-core
Copy-Item .\tachyon-core.exe C:\ProgramData\tachyon-core\
Copy-Item .\config.json C:\ProgramData\tachyon-core\

nssm install tachyon-core C:\ProgramData\tachyon-core\tachyon-core.exe
nssm set tachyon-core AppParameters "run -c C:\ProgramData\tachyon-core\config.json -D C:\ProgramData\tachyon-core"
nssm set tachyon-core AppDirectory C:\ProgramData\tachyon-core
nssm set tachyon-core AppStdout C:\ProgramData\tachyon-core\stdout.log
nssm set tachyon-core AppStderr C:\ProgramData\tachyon-core\stderr.log
nssm set tachyon-core Start SERVICE_AUTO_START
nssm start tachyon-core
```

#### Пример через Планировщик задач (без сторонних утилит)

```powershell
$action = New-ScheduledTaskAction `
    -Execute "C:\ProgramData\tachyon-core\tachyon-core.exe" `
    -Argument "run -c C:\ProgramData\tachyon-core\config.json -D C:\ProgramData\tachyon-core" `
    -WorkingDirectory "C:\ProgramData\tachyon-core"
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "TachyonCore" -Action $action -Trigger $trigger -Principal $principal
```

На Windows сигнал `SIGHUP` отсутствует, поэтому горячую перезагрузку работающего процесса выполняйте через `PUT /configs` контроллера Clash/Tachyon API.

### macOS: `LaunchDaemon` (для TUN / системного сервиса)

Создайте `/Library/LaunchDaemons/org.tachyon.core.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>org.tachyon.core</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/tachyon-core</string>
        <string>run</string>
        <string>-c</string>
        <string>/etc/tachyon-core/config.json</string>
        <string>-D</string>
        <string>/var/lib/tachyon-core</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/tachyon-core.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/tachyon-core.err.log</string>
</dict>
</plist>
```

Установка прав и запуск:

```bash
sudo mkdir -p /etc/tachyon-core /var/lib/tachyon-core
sudo chown root:wheel /Library/LaunchDaemons/org.tachyon.core.plist
sudo chmod 644 /Library/LaunchDaemons/org.tachyon.core.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/org.tachyon.core.plist

# Горячая перезагрузка конфигурации на macOS:
sudo launchctl kill SIGHUP system/org.tachyon.core
```

Для запуска без прав `root` (только `mixed`/`socks`/`http`) аналогичный plist помещается в `~/Library/LaunchAgents/` и загружается через `launchctl bootstrap gui/$(id -u) ...`.

---

## Интеграция с настольными приложениями

Существуют два архитектурных подхода к встраиванию `tachyon-core` в десктопный клиент (Electron, Tauri, Qt, SwiftUI, WPF/WinUI):

### 1. Внешний процесс (sidecar) + Clash/Tachyon API

Рекомендуемый вариант для приложений на Electron, Qt, C# и кроссплатформенных GUI, особенно когда для TUN требуется отдельный привилегированный helper-сервис:

1. Приложение запускает `tachyon-core run -c <path> -D <workdir>` с локальным контроллером `127.0.0.1:<port>` и сгенерированным на сессию токеном `secret`.
2. Перед применением новой конфигурации UI проверяет её через `tachyon-core check -c <candidate>` (или `tachyon-core reload-preview --current ...`) и отправляет `PUT /configs` (`{"path": "..."}` или `{"payload": "..."}`).
3. Переключение узлов (`PUT /proxies/{group}`), массовый пинг (`POST /tachyon/delay-batch`), трафик в реальном времени (`ws://.../traffic`), активные соединения (`ws://.../connections`), диагностика (`POST /tachyon/connection-test`) и сводка здоровья (`GET /tachyon/health`) выполняются по HTTP/WebSocket.
4. Для импорта подписок и декодирования ссылок без реализации парсеров в UI доступны CLI-команды `tachyon-core subscription fetch/parse/decrypt`.

### 2. Прямое встраивание в процесс

- **Приложения на Rust (Tauri, egui, Slint, Iced)**: подключают крейты `core-config` и `core-runtime` напрямую, управляют жизненным циклом `BoxInstance` и вызывают `reload_in_place` без HTTP-прослойки.
- **Приложения на Swift (macOS App / NetworkExtension), C/C++, C# (P/Invoke), Go (cgo)**: линкуют статическую или динамическую библиотеку с C ABI из `include/tachyon_core.h` (`tachyon_core_check`, `tachyon_core_start`, `tachyon_core_reload`, `tachyon_core_stop`, `tachyon_core_is_running`).

Подробные сигнатуры, правила владения памятью и примеры кода приведены в руководстве [Встраивание как библиотеки (Rust и C ABI)](embedding-rust-and-c.md).
