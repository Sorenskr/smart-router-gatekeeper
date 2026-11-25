@echo off
chcp 65001 >nul
cd /d "%~dp0"
title Smart Router Gatekeeper - 一键安装到 ImmortalWrt 软路由

echo ============================================================
echo   一键安装到 ImmortalWrt 软路由 (Windows 全自动部署)
echo ============================================================
echo   说明：全程已自动跳过 yes/no 确认，只需输入一次密码即可自动装完！
echo.

set "ROUTER_IP="
set /p "ROUTER_IP=1. 请输入软路由 IP (直接回车默认 192.168.6.1): "
if "%ROUTER_IP%"=="" set "ROUTER_IP=192.168.6.1"

set "GK_SSH_PASS_INPUT="
set /p "GK_SSH_PASS_INPUT=2. 请输入软路由 SSH (root) 密码 (输入后按回车): "

set "ADMIN_PWD="
set /p "ADMIN_PWD=3. 请设置网页管理后台密码 (直接回车默认 admin123): "
if "%ADMIN_PWD%"=="" set "ADMIN_PWD=admin123"

echo.
echo 正在自动连接 root@%ROUTER_IP% 上传并配置开机自启，请稍候十几秒...
echo.

if exist "dist\gatekeeper-linux-arm64" (
    powershell -ExecutionPolicy Bypass -File "scripts\deploy_to_immortalwrt.ps1" -RouterIP "%ROUTER_IP%" -Password "%ADMIN_PWD%" -SkipBuild
) else (
    powershell -ExecutionPolicy Bypass -File "scripts\deploy_to_immortalwrt.ps1" -RouterIP "%ROUTER_IP%" -Password "%ADMIN_PWD%"
)

set "GK_SSH_PASS_INPUT="
echo.
echo 如上方已显示「部署成功」，即可打开浏览器访问 http://%ROUTER_IP%:8088
pause
