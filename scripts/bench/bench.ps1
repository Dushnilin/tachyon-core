# Benchmark tachyon-core against sing-box, Xray and Mihomo.
#
#   powershell -File scripts\bench\bench.ps1                  # everything
#   powershell -File scripts\bench\bench.ps1 -Only ss,vmess   # subset of protocols
#   powershell -File scripts\bench\bench.ps1 -Build          # rebuild the musl binary first
#   powershell -File scripts\bench\bench.ps1 -Cores 1          # single-core router
#
# Needs the reference binaries next to each other in target\bench:
#   tachyon-core   built here by cargo (x86_64-unknown-linux-musl)
#   sing-box-lx    the reference pin, see ROADMAP.md
#   xray-linux     https://github.com/XTLS/Xray-core/releases
#   mihomo-linux   https://github.com/MetaCubeX/mihomo/releases
#
# The run happens in a throwaway python:3 container; the reports land in
# target\bench as bench.html / bench.md / bench.json.
param(
    [string]$Only = "",
    [switch]$Build,
    [switch]$SkipRun,
    [int]$Cores = 2,
    [int]$Seconds = 1,
    [int]$Streams = 8,
    [int]$Rounds = 400
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $root
$bench = Join-Path $root "target\bench"
New-Item -ItemType Directory -Force $bench | Out-Null

# The musl build needs a cross toolchain this Windows host does not have; it is
# what the Docker gate produces. The benchmark reuses whatever sits in
# target\bench unless -Build is asked for explicitly.
if ($Build) {
    $env:RUSTFLAGS = "-C linker=rust-lld -C link-self-contained=yes"
    cargo build -p core-cli --release --target x86_64-unknown-linux-musl
    if ($LASTEXITCODE -ne 0) { throw "build failed" }
    Remove-Item Env:\RUSTFLAGS
    Copy-Item "target\x86_64-unknown-linux-musl\release\tachyon-core" "$bench\tachyon-core" -Force
}
if (-not (Test-Path "$bench\tachyon-core")) {
    throw "no tachyon-core in target\bench - build the musl binary first (Docker gate)"
}

foreach ($b in "sing-box-lx", "xray-linux", "mihomo-linux") {
    if (-not (Test-Path "$bench\$b")) { throw "missing reference binary: target\bench\$b" }
}

Copy-Item "scripts\bench\bench.py" "$bench\bench.py" -Force

$size = [math]::Round((Get-Item "$bench\tachyon-core").Length / 1MB, 2)
$only = if ($Only) { "--only $Only" } else { "" }
Write-Host "tachyon-core $size MiB, router budget $Cores core(s)..."

if ($SkipRun) { return }

# openssl makes the throwaway certs; everything else is already in python:3.
docker run --rm --ulimit nofile=1048576:1048576 -v "${bench}:/bench" python:3 sh -c `
    "apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq openssl >/dev/null 2>&1; chmod +x /bench/tachyon-core /bench/sing-box-lx /bench/xray-linux /bench/mihomo-linux; python3 /bench/bench.py --cores $Cores --seconds $Seconds --streams $Streams --rounds $Rounds $only --out /bench/bench.json --html /bench/bench.html --md /bench/bench.md"
if ($LASTEXITCODE -ne 0) { throw "benchmark run failed" }

Write-Host ""
Write-Host "  HTML: target\bench\bench.html"
Write-Host "  MD:   target\bench\bench.md"
Write-Host "  JSON: target\bench\bench.json"
