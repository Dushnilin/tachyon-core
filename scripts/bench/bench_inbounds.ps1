# Runs bench_inbounds.py in Docker: server-side inbound benchmark,
# tachyon vs sing-box-lx vs steer vs Xray vs Mihomo as the SERVER engine
# (client is always tachyon).
#
#   .\scripts\bench\bench_inbounds.ps1                       # all inbounds
#   .\scripts\bench\bench_inbounds.ps1 -Only ss-aes-128-gcm  # single inbound
#   .\scripts\bench\bench_inbounds.ps1 -Seconds 2            # longer bulk run
param(
    [string]$Only = "",
    [int]$Seconds = 1,
    [int]$Rounds = 200
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path "$PSScriptRoot\..\.."
$work = Join-Path $root "target\bench"
New-Item -ItemType Directory -Force $work | Out-Null

Copy-Item "$PSScriptRoot\bench_inbounds.py" "$work\bench_inbounds.py" -Force
Copy-Item "$PSScriptRoot\bench.py" "$work\bench.py" -Force

$extraArgs = "--seconds $Seconds --rounds $Rounds " +
    "--tachyon /bench/tachyon-core --ref /bench/sing-box-lx " +
    "--steer /bench/steer/usr/bin/sing-box --xray /bench/xray-linux --mihomo /bench/mihomo-linux " +
    "--out-json /bench/inbound_bench_result.json --out-html /bench/inbound_bench.html"
if ($Only) {
    $extraArgs += " --only $Only"
}

docker run --rm --privileged --ulimit nofile=1048576:1048576 `
    --device /dev/net/tun -v "${work}:/bench" -w /bench python:3 `
    sh -c "chmod +x /bench/tachyon-core /bench/sing-box* /bench/xray-linux /bench/mihomo-linux /bench/steer/usr/bin/* /bench/steer/usr/sbin/* 2>/dev/null; python3 /bench/bench_inbounds.py $extraArgs"

Write-Host "`nReport saved to: $work\inbound_bench.html"
Write-Host "JSON saved to:   $work\inbound_bench_result.json"
