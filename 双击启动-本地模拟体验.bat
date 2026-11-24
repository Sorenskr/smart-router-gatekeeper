@echo off
chcp 65001 >nul
cd /d "%~dp0"
title Smart Router Gatekeeper - 本地模拟体验

echo ============================================================
echo   Smart Router Gatekeeper - 本地仿真预览启动器
echo ============================================================
echo.

if not exist "dist\gatekeeper-windows-amd64.exe" (
    if exist "scripts\build.ps1" (
        echo 未检测到可执行文件，正在尝试本地编译...
        powershell -ExecutionPolicy Bypass -File "scripts\build.ps1"
    )
)

if not exist "dist\gatekeeper-windows-amd64.exe" (
    echo [提示] 未找到 dist\gatekeeper-windows-amd64.exe。
    echo 请前往 GitHub Releases 下载 SmartRouterGatekeeper-Windows-Kit.zip 解压后双击运行！
    pause
    exit /b 1
)

echo 正在启动本地模拟仿真服务...
echo   - 管理大屏地址: http://127.0.0.1:8088 (默认密码 admin123)
echo   - 模拟手机认证页: http://127.0.0.1:8089/portal
echo.
echo 浏览器即将自动打开；保持本窗口开启即可，关闭窗口即停止服务。
start "" "http://127.0.0.1:8088"
"dist\gatekeeper-windows-amd64.exe" --mock --port 8088 --portal-port 8089 --data-dir "%~dp0data" --admin-ip 192.168.6.10
pause
