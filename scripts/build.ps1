$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$goCmd = Get-Command go -ErrorAction SilentlyContinue
$goExe = if ($goCmd) { $goCmd.Source } else { Join-Path $root '.toolchain\go\bin\go.exe' }
if (-not (Test-Path $goExe)) {
    throw "未找到 Go 编译器，请先安装 Go 或运行工具链初始化脚本。"
}

$distDir = Join-Path $root 'dist'
New-Item -ItemType Directory -Force -Path $distDir | Out-Null

$goCache = Join-Path $root '.toolchain\gocache'
$goTmp = Join-Path $root '.toolchain\gotmp'
New-Item -ItemType Directory -Force -Path $goCache, $goTmp | Out-Null
if (-not $env:GOCACHE) { $env:GOCACHE = $goCache }
if (-not $env:GOTMPDIR) { $env:GOTMPDIR = $goTmp }

Write-Output "使用编译器: $goExe"
& $goExe version

$env:CGO_ENABLED = '0'

Write-Output "`n[1/2] 正在编译 Windows 本地仿真/管理可执行文件 (windows/amd64)..."
$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
$winOut = Join-Path $distDir 'gatekeeper-windows-amd64.exe'
& $goExe build -trimpath -ldflags="-s -w" -o $winOut .
if ($LASTEXITCODE -ne 0) { throw "Windows amd64 编译失败" }

Write-Output "`n[2/2] 正在交叉编译 ImmortalWrt 静态二进制文件 (linux/arm64)..."
$env:GOOS = 'linux'
$env:GOARCH = 'arm64'
$armOut = Join-Path $distDir 'gatekeeper-linux-arm64'
& $goExe build -trimpath -ldflags="-s -w" -o $armOut .
if ($LASTEXITCODE -ne 0) { throw "Linux arm64 交叉编译失败" }

Remove-Item Env:GOOS -ErrorAction SilentlyContinue
Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue

# 验证 ELF ARM64 文件头
$bytes = [System.IO.File]::ReadAllBytes($armOut)
if ($bytes.Length -lt 20 -or $bytes[0] -ne 0x7F -or $bytes[1] -ne 0x45 -or $bytes[2] -ne 0x4C -or $bytes[3] -ne 0x46) {
    throw "输出文件不是有效的 ELF 可执行文件: $armOut"
}
$elfClass = $bytes[4]
$machine = [BitConverter]::ToUInt16($bytes, 18)
if ($elfClass -ne 2 -or $machine -ne 183) {
    throw "ELF 架构校验失败: class=$elfClass, e_machine=$machine (期望 class=2, e_machine=183 aarch64)"
}

$winMB = [Math]::Round((Get-Item $winOut).Length / 1MB, 2)
$armMB = [Math]::Round((Get-Item $armOut).Length / 1MB, 2)
Write-Output "`n编译完成！"
Write-Output "  Windows 版本: $winOut ($winMB MB)"
Write-Output "  ImmortalWrt ARM64 版本: $armOut ($armMB MB, ELF64 AArch64 校验通过)"
