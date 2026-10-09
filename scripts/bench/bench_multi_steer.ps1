# Runs multi-core benchmark with steer included:
# tachyon-core vs sing-box vs Xray vs Mihomo vs steer
#
#   .\scripts\bench\bench_multi_steer.ps1                      # router profile (1 worker, core 1, ~25s)
#   .\scripts\bench\bench_multi_steer.ps1 -Profile desktop     # desktop profile (multi-core, ~25s)
#   .\scripts\bench\bench_multi_steer.ps1 -Quick               # ultra-fast 1s pass (~15s)
#   .\scripts\bench\bench_multi_steer.ps1 -Only tachyon,steer  # run subset of proxies
param(
    [ValidateSet("router", "desktop")]
    [string]$Profile = "router",
    [int]$Seconds = 2,
    [int]$LatencyRounds = 3000,
    [switch]$Quick,
    [string]$Only = ""
)

& "$PSScriptRoot\bench_multi.ps1" -Profile $Profile -Seconds $Seconds -LatencyRounds $LatencyRounds -Quick:$Quick -Only $Only -Steer
