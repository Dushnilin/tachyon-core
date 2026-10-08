# Runs bench_multi.py in a clean python:3 container: tachyon-core vs sing-box vs Xray vs Mihomo.
#
#   .\scripts\bench\bench_multi.ps1                      # router profile (1 worker, core 1, ~20s)
#   .\scripts\bench\bench_multi.ps1 -Profile desktop     # desktop profile (multi-core, ~20s)
#   .\scripts\bench\bench_multi.ps1 -Quick               # ultra-fast 1s pass (~10s)
#   .\scripts\bench\bench_multi.ps1 -Only tachyon,xray   # run subset of proxies
param(
    [ValidateSet("router", "desktop")]
    [string]$Profile = "router",
    [int]$Seconds = 2,
    [int]$LatencyRounds = 3000,
    [switch]$Quick,
    [string]$Only = ""
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path "$PSScriptRoot\..\.."
$work = Join-Path $root "target\bench"
New-Item -ItemType Directory -Force $work | Out-Null

Copy-Item "$PSScriptRoot\bench_multi.py" "$work\bench_multi.py" -Force

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
if ($Quick) {
    $extraArgs += @("--no-c1k", "--seconds", "1", "--latency-rounds", "1500")
}
if ($Only) {
    $extraArgs += @("--only", $Only)
}

$outJson = "/bench/multi-$Profile.json"
$outHtml = "/bench/multi-$Profile.html"
$extraArgs += @("--out", $outJson, "--html", $outHtml)

$argStr = $extraArgs -join " "

Write-Host "Launching multi-proxy benchmark ($Profile profile) ..."
docker run --rm --ulimit nofile=1048576:1048576 `
    -v "${work}:/bench" python:3 `
    sh -c "chmod +x /bench/tachyon-core /bench/sing-box* /bench/xray-linux /bench/mihomo-linux && python3 /bench/bench_multi.py $argStr"

Write-Host "`nReport saved to: $work\multi-$Profile.html"
Write-Host "JSON saved to:   $work\multi-$Profile.json"
