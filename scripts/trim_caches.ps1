<#
  Trim the build caches that only ever grow: host target/ and the docker volumes.

    pwsh scripts/trim_caches.ps1            # dry run, prints what would go
    pwsh scripts/trim_caches.ps1 -Apply     # does it

  Only debug/ and incremental/ trees go, and only past the budget. Release
  outputs, bench binaries and the reference sing-box are never touched.
#>
param(
    [switch]$Apply,
    [int]$HostBudgetGB = 15,
    [int]$VolumeBudgetGB = 8
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

function Get-DirGB($path) {
    $sum = (Get-ChildItem $path -Recurse -File -Force -ErrorAction SilentlyContinue |
        Measure-Object Length -Sum).Sum
    [math]::Round(($sum / 1GB), 2)
}

function Remove-Tree($path, $why) {
    if ($Apply) { Remove-Item -Recurse -Force $path -ErrorAction SilentlyContinue }
    "{0}  {1}  ({2})" -f ($(if ($Apply) { 'removed' } else { 'would remove' })), $path, $why
}

# host: <target>/debug and <target>/<triple>/debug
$targets = @(Join-Path $root 'target')
foreach ($t in $targets) {
    $debugDirs = @(Join-Path $t 'debug') +
        (Get-ChildItem $t -Directory -ErrorAction SilentlyContinue |
            ForEach-Object { Join-Path $_.FullName 'debug' })
    foreach ($d in $debugDirs | Where-Object { Test-Path $_ }) {
        $gb = Get-DirGB $d
        if ($gb -le $HostBudgetGB) { continue }
        $inc = Join-Path $d 'incremental'
        if (Test-Path $inc) { Remove-Tree $inc "incremental, $gb GB debug dir over $HostBudgetGB" }
        if ($Apply) { $gb = Get-DirGB $d }
        if (-not $Apply -or $gb -gt $HostBudgetGB) { Remove-Tree $d "debug, $gb GB over $HostBudgetGB" }
    }
}

# docker: stopped containers, dangling images, and debug trees inside the volumes
if (Get-Command docker -ErrorAction SilentlyContinue) {
    if ($Apply) {
        docker container prune -f | Out-Null
        docker image prune -f | Out-Null
    }
    $vols = docker volume ls --format '{{.Name}}' | Where-Object { $_ -match '^tachyon-.*(target|cache)' }
    foreach ($v in $vols) {
        $sh = 'for d in /t/debug /t/target/debug; do [ -d $d ] || continue; ' +
              's=$(du -sm $d | cut -f1); echo "$d $s"; ' +
              ('if [ "$s" -gt {0} ]; then [ "{1}" = 1 ] && rm -rf $d; echo "trim $d"; fi; done' -f ($VolumeBudgetGB * 1024), [int]$Apply.IsPresent)
        docker run --rm -v "${v}:/t" alpine:edge sh -c $sh | ForEach-Object { "volume $v : $_" }
    }
}
