<#
Ночь на роутере 192.168.1.206 с ПК: кладёт файлы на устройство, дожидается
конца идущей матрицы, запускает ночную нагрузку (только tachyon-core, каждый
протокол подряд, N коннектов и трафик minutes минут), раз в 10 минут поглядывает,
а утром забирает json и собирает BENCHMARK.html (матрица, вкладка роутера) и
NIGHT.html (эндьюранс) в корень репозитория.

    .\scripts\bench\night.ps1                       # до 08:00, 10000 коннектов, 20 мин
    .\scripts\bench\night.ps1 -StopAt 0930 -Conns 5000 -Minutes 10

ПК за ночь не должен уснуть: спит ПК — спит и опрос, но роутер доделает сам,
и утренний повтор night.ps1 просто заберёт готовое (готовые json'ы пропускаются).
#>
param(
    [string]$Router = "root@192.168.1.206",
    [int]$Conns = 10000,
    [int]$Minutes = 20,
    [string]$StopAt = "0800",
    [string]$LxVer = "1.14.2-lx.12",
    [string]$Note = "Виртуальный роутер на Proxmox (хост — NanoPi R3S LTS 2GB): 2 vCPU aarch64 (Cortex-A55, aes/pmull), 727 МиБ RAM, OpenWrt 25.12.5; tachyon-core aarch64-unknown-linux-musl против sing-box-lx, клиент и сервер по одному ядру."
)
$ErrorActionPreference = "Continue"   # Stop в PS 5.1 роняет скрипт на чужом stderr
$root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$bench = Join-Path $root "target\bench"
$sshOpt = @("-o", "BatchMode=yes", "-o", "ConnectTimeout=8")
$stopTime = [datetime]::ParseExact($StopAt, "HHmm", $null)
if ($stopTime -le (Get-Date)) { $stopTime = $stopTime.AddDays(1) }

function RemoteState([string]$probe) {
    try { return (& ssh @sshOpt $Router $probe 2>$null | Select-Object -Last 1).Trim() }
    catch { return "" }
}

Write-Host "==> деплой на $Router"
if (-not (Test-Path "$bench\tachyon-core-arm64")) {
    Write-Host "    aarch64-сборки нет, собираю в контейнере (~5 мин)"
    docker run --rm -v "${root}:/src" -v tachyon-core-cargo-registry:/usr/local/cargo/registry `
        -v tachyon-core-cargo-git:/usr/local/cargo/git -v tachyon-core-target:/cache/target `
        -w /src -e CARGO_TARGET_DIR=/cache/target -e CARGO_INCREMENTAL=0 -e CARGO_BUILD_JOBS=4 `
        tachyon-core-test:latest bash -c "rustup target add aarch64-unknown-linux-musl && cargo build --workspace --release --target aarch64-unknown-linux-musl"
    docker run --rm -v tachyon-core-target:/cache -v "${root}:/src" tachyon-core-test:latest `
        sh -c "cp /cache/aarch64-unknown-linux-musl/release/tachyon-core /src/target/bench/tachyon-core-arm64"
}
$sbArm = "$bench\sb-arm64\sing-box-$LxVer-linux-arm64\sing-box"
if (-not (Test-Path $sbArm)) {
    Write-Host "    качаю sing-box-lx $LxVer linux-arm64"
    Invoke-WebRequest -UseBasicParsing `
        -Uri "https://github.com/Leadaxe/sing-box-lx/releases/download/v$LxVer/sing-box-$LxVer-linux-arm64.tar.gz" `
        -OutFile "$bench\sb-arm64.tar.gz"
    New-Item -ItemType Directory -Force "$bench\sb-arm64" | Out-Null
    tar -xzf "$bench\sb-arm64.tar.gz" -C "$bench\sb-arm64"
}
& ssh @sshOpt $Router "mkdir -p /tmp/bench/results" 2>$null
& scp -O @sshOpt "$bench\tachyon-core-arm64" "${Router}:/tmp/bench/tachyon-core" | Out-Null
& scp -O @sshOpt $sbArm "${Router}:/tmp/bench/sing-box" | Out-Null
& scp -O @sshOpt "$root\scripts\bench\proto.py" "$root\scripts\bench\bench.py" `
    "$root\scripts\bench\night_load.py" "$root\scripts\bench\overnight.sh" "${Router}:/tmp/bench/" | Out-Null
& ssh @sshOpt $Router "chmod +x /tmp/bench/tachyon-core /tmp/bench/sing-box /tmp/bench/overnight.sh" 2>$null

if ((RemoteState "grep -qs night_load /proc/[0-9]*/cmdline && echo RUN || echo IDLE") -ne "RUN") {
    # если ещё идёт полный прогон матрицы — не мешаем, дождаться его конца
    while ((Get-Date) -lt $stopTime -and
           (RemoteState "grep -qs proto.py /proc/[0-9]*/cmdline && echo BUSY || echo FREE") -eq "BUSY") {
        Write-Host ("    {0:HH:mm} — жду конца идущей матрицы..." -f (Get-Date))
        Start-Sleep -Seconds 120
    }
    Write-Host "==> запуск ночи: $Conns коннектов, $Minutes мин/протокол, стоп в $StopAt"
    & ssh @sshOpt $Router "cd /tmp/bench && CONNS=$Conns MINUTES=$Minutes setsid nohup sh overnight.sh </dev/null >/dev/null 2>&1 & sleep 2; grep -qs night_load /proc/[0-9]*/cmdline && echo запущено" 2>$null
    Start-Sleep -Seconds 180
    Write-Host "    первые шаги прогона:"
    & ssh @sshOpt $Router "tail -5 /tmp/bench/night.log 2>/dev/null" 2>$null
}
else { Write-Host "==> ночь уже идёт, перехожу к опросу" }

Write-Host "==> опрос каждые 10 минут, стоп в $StopAt"
while ($true) {
    if ((RemoteState "grep -qs night_load /proc/[0-9]*/cmdline && echo RUN || echo IDLE") -eq "IDLE") {
        Write-Host "    роутер закончил"
        break
    }
    if ((Get-Date) -ge $stopTime) {
        Write-Host "    $StopAt — снимаю ночной прогон (SIGTERM, ядра остановятся сами)"
        & ssh @sshOpt $Router "pgrep -f night_load | while read p; do kill -TERM `$p; done" 2>$null
        Start-Sleep -Seconds 30
        break
    }
    $n = RemoteState "ls /tmp/bench/results/load-*.json 2>/dev/null | wc -l"
    Write-Host ("    {0:HH:mm} — готово протоколов: {1}" -f (Get-Date), $n)
    Start-Sleep -Seconds 600
}

Write-Host "==> забираю json"
New-Item -ItemType Directory -Force -Path "$bench\router" | Out-Null
& scp -O @sshOpt "${Router}:/tmp/bench/results/load-*.json" "$bench\router\" 2>$null
& scp -O @sshOpt "${Router}:/tmp/bench/results/proto-*.json" "$bench\router\" 2>$null
$night = @(Get-ChildItem "$bench\router\load-*.json" -ErrorAction SilentlyContinue)
$matrix = @(Get-ChildItem "$bench\router\proto-2*.json" -ErrorAction SilentlyContinue)
if ($night.Count) {
    & python "$root\scripts\bench\night_report.py" "$bench\router" --out "$root\NIGHT.html"
}
if ($matrix.Count) {
    & python "$root\scripts\bench\report.py" --all "$bench" --out "$root\BENCHMARK.html" --note $Note
    Write-Host "==> BENCHMARK.html собран, вкладка роутера из $($matrix.Count) прогона(ов)"
}
Write-Host "готово в $(Get-Date -Format 'HH:mm')"
