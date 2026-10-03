# Protocol matrix against sing-box: build the musl binary, run proto.py in
# Docker, print the whole report at the end.
#
#   powershell -File scripts\bench\proto.ps1                 # everything
#   powershell -File scripts\bench\proto.ps1 -Only vmess     # cases whose name contains "vmess"
#   powershell -File scripts\bench\proto.ps1 -SkipBuild      # use target\bench\tachyon-core as is
#
# Needs target\bench\sing-box-lx (the reference) next to the tachyon binary.
param(
    [string]$Only = "",
    [switch]$SkipBuild,
    [int]$Runs = 1,
    [int]$Seconds = 2,
    [int]$Rounds = 2000,
    [string]$Part = "AB"
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $root
$bench = Join-Path $root "target\bench"
New-Item -ItemType Directory -Force $bench | Out-Null

if (-not $SkipBuild) {
    $env:RUSTFLAGS = "-C linker=rust-lld -C link-self-contained=yes"
    cargo build -p core-cli --release --target x86_64-unknown-linux-musl
    if ($LASTEXITCODE -ne 0) { throw "build failed" }
    Copy-Item target\x86_64-unknown-linux-musl\release\tachyon-core "$bench\tachyon-core" -Force
}
Copy-Item scripts\bench\bench.py, scripts\bench\proto.py $bench -Force

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$name = "proto-$stamp"
$filter = if ($Only) { "--only $Only" } else { "" }
$cmd = "chmod +x /bench/tachyon-core /bench/sing-box*; python3 /bench/proto.py --tachyon /bench/tachyon-core --ref /bench/sing-box-lx --runs $Runs --seconds $Seconds --rounds $Rounds --part $Part $filter --out /bench/$name.json 2>&1"

$size = [math]::Round((Get-Item "$bench\tachyon-core").Length / 1MB, 2)
Write-Host "tachyon-core: $size MiB, running the matrix (about 10 minutes for everything)..."
docker run --rm --ulimit nofile=1048576:1048576 -v "${bench}:/bench" python:3 sh -c $cmd | Out-Null

$report = "$bench\$name.md"
Write-Host ""
Write-Host "================ RESULT ($name) ================"
if (Test-Path $report) { Get-Content $report } else { Write-Host "no report was written, the run failed" }
Write-Host "================================================"
Write-Host "report: $report"
