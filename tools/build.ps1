# Build pcap-rw and finish the release executable in one go.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File tools\build.ps1
#   powershell -ExecutionPolicy Bypass -File tools\build.ps1 -SkipBuild    # post-steps only
#   powershell -ExecutionPolicy Bypass -File tools\build.ps1 -NoSign       # leave it unsigned
#
# Steps: cargo build -> keep the raw output -> icon -> version resource -> signature.
# Signing is on by default; drop it with -NoSign.
#
# Order matters, and so does the starting point: seticon.py rewrites the resource
# section and drops any signature already attached, so every run starts from the
# untouched cargo output stored as dist\pcap-rw.raw.exe instead of layering onto
# whatever dist\pcap-rw.exe currently is. Re-running is therefore safe.
#
# The MinGW bin directory (for dlltool) has to be on PATH before this runs.

param(
    [switch]$SkipBuild,
    [switch]$NoSign,
    [switch]$NoTimestamp
)

$ErrorActionPreference = "Stop"

$repo = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $repo "dist"
$exe = Join-Path $dist "pcap-rw.exe"
$raw = Join-Path $dist "pcap-rw.raw.exe"
$icon = Join-Path $repo "assets\app.ico"

# python is not always on PATH under PowerShell; look in the usual places.
function Resolve-Python {
    foreach ($name in "python", "python3", "py") {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
    }
    $patterns = @(
        (Join-Path $env:USERPROFILE ".workbuddy\binaries\python\versions\*\python.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\Python\Python3*\python.exe"),
        "C:\Python3*\python.exe"
    )
    foreach ($pattern in $patterns) {
        $hit = Get-ChildItem $pattern -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }
    throw "找不到 python，请把它加入 PATH"
}

$python = Resolve-Python
$env:PYTHONIOENCODING = "utf-8"   # 否则中文输出在重定向时会按 GBK 写出，日志变成乱码

Push-Location $repo
try {
    if (-not $SkipBuild) {
        Write-Output "== cargo build --release"
        cargo build --release
        if ($LASTEXITCODE -ne 0) { throw "cargo build 失败（退出码 $LASTEXITCODE）" }

        New-Item -ItemType Directory -Force -Path $dist | Out-Null
        Copy-Item (Join-Path $repo "target\release\pcap-rw.exe") $raw -Force
    }

    if (-not (Test-Path $raw)) {
        throw "找不到原始产物 $raw，先去掉 -SkipBuild 跑一次构建"
    }

    Copy-Item $raw $exe -Force
    $before = (Get-Item $exe).Length

    Write-Output "== icon"
    & $python tools\seticon.py $exe $icon
    if ($LASTEXITCODE -ne 0) { throw "seticon.py 失败" }

    Write-Output "== version resource"
    & $python tools\version.py $exe
    if ($LASTEXITCODE -ne 0) { throw "version.py 失败" }

    if (-not $NoSign) {
        Write-Output "== signature"
        $signArgs = @($exe)
        if ($NoTimestamp) { $signArgs += "-NoTimestamp" }
        & (Join-Path $PSScriptRoot "sign.ps1") @signArgs
    }

    $item = Get-Item $exe
    Write-Output ""
    Write-Output ("输出 : " + $item.FullName)
    Write-Output ("大小 : " + $item.Length + " 字节（构建产物 " + $before + "）")
    Write-Output ("SHA256: " + (Get-FileHash $exe -Algorithm SHA256).Hash)
} finally {
    Pop-Location
}
