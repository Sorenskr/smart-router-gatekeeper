@echo off
chcp 65001 >nul
cd /d "%~dp0"
title Smart Router Gatekeeper - 一键安装到 ImmortalWrt 软路由

echo ============================================================
echo   一键安装到 ImmortalWrt 软路由 (SSH 自动部署)
echo ============================================================
echo.

set "ROUTER_IP="
set /p "ROUTER_IP=请输入软路由 IP (直接回车默认 192.168.6.1): "
if "%ROUTER_IP%"=="" set "ROUTER_IP=192.168.6.1"

set "ADMIN_PWD="
set /p "ADMIN_PWD=请设置管理后台登录密码 (直接回车默认 admin123): "
if "%ADMIN_PWD%"=="" set "ADMIN_PWD=admin123"

echo.
echo 准备部署到 root@%ROUTER_IP%，后台登录密码将设为: %ADMIN_PWD%
echo 过程中会提示您输入软路由的 SSH (root) 密码，请按提示输入后回车即可。
echo.

if exist "dist\gatekeeper-linux-arm64" (
    powershell -ExecutionPolicy Bypass -File "scripts\deploy_to_immortalwrt.ps1" -RouterIP "%ROUTER_IP%" -Password "%ADMIN_PWD%" -SkipBuild
) else (
    powershell -ExecutionPolicy Bypass -File "scripts\deploy_to_immortalwrt.ps1" -RouterIP "%ROUTER_IP%" -Password "%ADMIN_PWD%"
)

echo.
echo 如上方已显示部署成功，即可关闭本窗口并在浏览器打开管理网址。
pause
