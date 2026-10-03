# Runs bench.py in a clean python:3 container against the x86_64 musl build and
# the sing-box binaries from an image that carries them.
#
#   .\scripts\bench\run.ps1                 # full: tachyon-core vs sing-box vs sing-box-lx
#   .\scripts\bench\run.ps1 -Quick          # tachyon-core only, throughput + RSS, ~1 minute
#   .\scripts\bench\run.ps1 -SbImage other  # another image with /usr/local/bin/sing-box*
param(
    [string]$SbImage = "tachyon-allbins",
    [string]$Target = "x86_64-unknown-linux-musl",
    [string]$TargetDir = "target",
    [string]$ProxyCpus = "0-1",
    [switch]$Quick
)
$ErrorActionPreference = "Stop"
$root = Resolve-Path "$PSScriptRoot\..\.."
$work = Join-Path $root "target\bench"
New-Item -ItemType Directory -Force $work | Out-Null

Copy-Item "$root\$TargetDir\$Target\release\tachyon-core" "$work\tachyon-core" -Force
Copy-Item "$PSScriptRoot\bench.py" "$work\bench.py" -Force

# the reference binaries are copied once; -Quick reuses them
if (-not (Test-Path "$work\sing-box")) {
    $cid = docker create $SbImage
    try {
        docker cp "${cid}:/usr/local/bin/sing-box" "$work\sing-box"
        docker cp "${cid}:/usr/local/bin/sing-box-lx8" "$work\sing-box-lx" 2>$null
    } finally { docker rm $cid | Out-Null }
}

$bins = @("--bin", "tachyon-core=/bench/tachyon-core")
if ($Quick) {
    $extra = "--quick --seconds 3"
} else {
    $extra = ""
    $bins += @("--bin", "sing-box=/bench/sing-box")
    if (Test-Path "$work\sing-box-lx") { $bins += @("--bin", "sing-box-lx=/bench/sing-box-lx") }
}

docker run --rm --ulimit nofile=1048576:1048576 `
    -v "${work}:/bench" python:3 `
    sh -c "chmod +x /bench/tachyon-core /bench/sing-box* && python3 /bench/bench.py --proxy-cpus $ProxyCpus $extra $($bins -join ' ') --out /bench/result.json"
Write-Host "result: $work\result.json"
