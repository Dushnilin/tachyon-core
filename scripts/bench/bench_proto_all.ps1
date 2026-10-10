# Runs bench_proto_all.py in Docker: Tachyon vs Sing-box vs Xray vs Mihomo across 39 protocols
#
#   .\scripts\bench\bench_proto_all.ps1                         # router profile (1 worker, core 1)
#   .\scripts\bench\bench_proto_all.ps1 -Profile desktop        # desktop profile (multi-core)
#   .\scripts\bench\bench_proto_all.ps1 -Only ss-aes-128-gcm    # single protocol
#   .\scripts\bench\bench_proto_all.ps1 -Seconds 2              # longer bulk run
param(
    [ValidateSet("router", "router2", "desktop")]
    [string]$Profile = "router",
    [int]$Seconds = 1,
    [int]$LatencyRounds = 800,
    [string]$Only = ""
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path "$PSScriptRoot\..\.."
$work = Join-Path $root "target\bench"
New-Item -ItemType Directory -Force $work | Out-Null

Copy-Item "$PSScriptRoot\bench_proto_all.py" "$work\bench_proto_all.py" -Force

# Ensure Xray binary exists
$xrayPath = "$work\xray-linux"
if (-not (Test-Path $xrayPath)) {
    Write-Host "Downloading Xray-core..."
    $zipPath = "$work\xray.zip"
    Invoke-WebRequest -Uri "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip" -OutFile $zipPath
    Expand-Archive -Path $zipPath -DestinationPath "$work\xray_tmp" -Force
    Move-Item -Force "$work\xray_tmp\xray" $xrayPath
    Remove-Item -Recurse -Force "$work\xray_tmp", $zipPath
}

# Ensure Mihomo binary exists
$mihomoPath = "$work\mihomo-linux"
if (-not (Test-Path $mihomoPath)) {
    Write-Host "Downloading Mihomo..."
    $gzPath = "$work\mihomo.gz"
    Invoke-WebRequest -Uri "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.32/mihomo-linux-amd64-v1.19.32.gz" -OutFile $gzPath
    python -c "import gzip, shutil; shutil.copyfileobj(gzip.open(r'$gzPath', 'rb'), open(r'$mihomoPath', 'wb'))"
    Remove-Item -Force $gzPath
}

$extraArgs = @("--profile", $Profile, "--seconds", $Seconds, "--latency-rounds", $LatencyRounds)
if ($Only) {
    $extraArgs += @("--only", $Only)
}
# Steer is extracted from its OpenWrt ipk by bench_multi.ps1 -Steer; reuse if present
if (Test-Path "$work\steer\usr\bin\sing-box") {
    $extraArgs += @("--steer", "/bench/steer/usr/bin/sing-box")
} else {
    Write-Host "steer binaries not found (run .\scripts\bench\bench_multi_steer.ps1 once) - steer column will be skipped"
}

$outJson = "/bench/proto-all-$Profile.json"
$outHtml = "/bench/proto-all-$Profile.html"
$extraArgs += @("--out", $outJson, "--html", $outHtml)

$argStr = $extraArgs -join " "

Write-Host "Launching All-Protocol Multi-Proxy Benchmark ($Profile profile) ..."
docker run --rm --ulimit nofile=1048576:1048576 `
    -v "${work}:/bench" python:3 `
    sh -c "chmod +x /bench/tachyon-core /bench/sing-box* /bench/xray-linux /bench/mihomo-linux /bench/steer/usr/bin/* /bench/steer/usr/sbin/* 2>/dev/null; python3 /bench/bench_proto_all.py $argStr"

Write-Host "`nReport saved to: $work\proto-all-$Profile.html"
Write-Host "JSON saved to:   $work\proto-all-$Profile.json"
