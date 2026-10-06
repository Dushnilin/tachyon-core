# Protocol matrix against sing-box: build the musl binary, run proto.py in
# Docker, print the whole report at the end.
#
#   powershell -File scripts\bench\proto.ps1                 # everything (~7 min)
#   powershell -File scripts\bench\proto.ps1 -Only vmess     # cases whose name contains "vmess"
#   powershell -File scripts\bench\proto.ps1 -SkipBuild      # use target\bench\tachyon-core as is
#
# Debug loop (a few minutes instead of ten):
#
#   powershell -File scripts\bench\proto.ps1 -Quick -Only ss2022 -SkipBuild
#
# -Quick drops the interop cells (part A runs T->ref and ref->T as well, which
# doubles it) and cuts latency rounds 400->200: enough to see a fix move the
# numbers, not enough for a verdict -- re-run without -Quick before trusting a
# row. -NoCross alone does just the first cut. The default window is already
# fast (runs 1, seconds 1, rounds 400); pass -Runs 2 -Seconds 2 -Rounds 2000
# when a row has to hold up as a verdict.
#
# Needs target\bench\sing-box-lx (the reference) next to the tachyon binary.
param(
    [string]$Only = "",
    [switch]$SkipBuild,
    [switch]$NoCross,
    [switch]$Quick,
    [int]$Runs = 1,
    [int]$Seconds = 1,
    [int]$Rounds = 400,
    [string]$Part = "AB"
)

if ($Quick) {
    $NoCross = $true
    if (-not $PSBoundParameters.ContainsKey("Seconds")) { $Seconds = 1 }
    if (-not $PSBoundParameters.ContainsKey("Rounds")) { $Rounds = 200 }
}

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
Copy-Item scripts\bench\bench.py, scripts\bench\proto.py, scripts\bench\report.py $bench -Force

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$name = "proto-$stamp"
$filter = if ($Only) { "--only $Only" } else { "" }
$cross = if ($NoCross) { "--no-cross" } else { "" }
$cmd = "chmod +x /bench/tachyon-core /bench/sing-box*; python3 /bench/proto.py --tachyon /bench/tachyon-core --ref /bench/sing-box-lx --runs $Runs --seconds $Seconds --rounds $Rounds --part $Part $filter $cross --out /bench/$name.json 2>&1"

$size = [math]::Round((Get-Item "$bench\tachyon-core").Length / 1MB, 2)
$mode = if ($Quick) { "quick debug mode" } elseif ($NoCross) { "no interop cells" } else { "full grid" }
Write-Host "tachyon-core: $size MiB, running the matrix ($mode)..."
docker run --rm -e PROTO_LOG -e PROTO_WORK --ulimit nofile=1048576:1048576 -v "${bench}:/bench" python:3 sh -c $cmd | Out-Null

$report = "$bench\$name.md"
Write-Host ""
Write-Host "================ RESULT ($name) ================"
if (Test-Path $report) { Get-Content $report } else { Write-Host "no report was written, the run failed" }
Write-Host "================================================"
Write-Host "report: $report"
