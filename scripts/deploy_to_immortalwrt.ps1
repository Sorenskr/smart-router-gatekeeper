[CmdletBinding()]
param(
    [string]$RouterIP = "192.168.6.1",
    [string]$User = "root",
    [int]$SshPort = 22,
    [int]$AdminPort = 8088,
    [int]$PortalPort = 8089,
    [int]$DNSPort = 5354,
    [string]$Password = "admin123",
    [string]$LanIface = "br-lan",
    [ValidateSet("quick", "token", "none")]
    [string]$TunnelMode = "quick",
    [string]$TunnelToken = "",
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$armBin = Join-Path $root 'dist\gatekeeper-linux-arm64'

if (-not $SkipBuild -or -not (Test-Path $armBin)) {
    Write-Output ">>> 步骤 1/4: 编译最新 linux/arm64 静态二进制文件..."
    & (Join-Path $PSScriptRoot 'build.ps1')
}

if (-not (Test-Path $armBin)) {
    throw "未找到二进制文件: $armBin"
}

$target = "${User}@${RouterIP}"
Write-Output "`n>>> 步骤 2/4: 上传单文件程序到 ImmortalWrt (${target})..."
& scp -P $SshPort $armBin "${target}:/tmp/gatekeeper.new"
if ($LASTEXITCODE -ne 0) { throw "SCP 上传失败，请确认 SSH 连通性与密码/密钥" }

$remoteScript = @'
set -eu
ROUTER_IP="__ROUTER_IP__"
ADMIN_PORT="__ADMIN_PORT__"
PORTAL_PORT="__PORTAL_PORT__"
DNS_PORT="__DNS_PORT__"
PASSWORD="__PASSWORD__"
LAN_IFACE="__LAN_IFACE__"
TUNNEL_MODE="__TUNNEL_MODE__"
TUNNEL_TOKEN="__TUNNEL_TOKEN__"

ADMIN_IP=""
if [ -n "${SSH_CLIENT:-}" ]; then
  ADMIN_IP=$(echo "$SSH_CLIENT" | awk '{print $1}')
fi

mv /tmp/gatekeeper.new /usr/bin/gatekeeper
chmod +x /usr/bin/gatekeeper
mkdir -p /etc/gatekeeper

# 开启 conntrack 字节流量统计，以便大屏展示实时上下行速率
sysctl -w net.netfilter.nf_conntrack_acct=1 >/dev/null 2>&1 || true
mkdir -p /etc/sysctl.d
echo "net.netfilter.nf_conntrack_acct=1" > /etc/sysctl.d/99-gatekeeper.conf

# 尝试检测或安装 conntrack-tools（用于断网时秒级掐断存量连接）
if ! command -v conntrack >/dev/null 2>&1; then
  if command -v apk >/dev/null 2>&1; then
    apk update >/dev/null 2>&1 || true
    apk add conntrack-tools >/dev/null 2>&1 || true
  elif command -v opkg >/dev/null 2>&1; then
    opkg update >/dev/null 2>&1 || true
    opkg install conntrack >/dev/null 2>&1 || true
  fi
fi

# 若请求开启远程隧道且缺少 cloudflared，尝试通过包管理器或官方 ARM64 包安装
if [ "$TUNNEL_MODE" != "none" ] && ! command -v cloudflared >/dev/null 2>&1; then
  if command -v apk >/dev/null 2>&1; then
    apk add cloudflared >/dev/null 2>&1 || true
  elif command -v opkg >/dev/null 2>&1; then
    opkg install cloudflared >/dev/null 2>&1 || true
  fi
  if ! command -v cloudflared >/dev/null 2>&1; then
    echo "[Gatekeeper] 正在尝试下载 cloudflared-linux-arm64..."
    CF_URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64"
    if command -v curl >/dev/null 2>&1; then
      curl -fsSL "$CF_URL" -o /usr/bin/cloudflared.tmp && mv /usr/bin/cloudflared.tmp /usr/bin/cloudflared && chmod +x /usr/bin/cloudflared || true
    elif command -v wget >/dev/null 2>&1; then
      wget -qO /usr/bin/cloudflared.tmp "$CF_URL" && mv /usr/bin/cloudflared.tmp /usr/bin/cloudflared && chmod +x /usr/bin/cloudflared || true
    fi
  fi
fi

ADMIN_IP_ARG=""
if [ -n "$ADMIN_IP" ]; then
  ADMIN_IP_ARG="--admin-ip $ADMIN_IP"
fi

cat <<EOF > /etc/init.d/gatekeeper
#!/bin/sh /etc/rc.common
START=99
STOP=10
USE_PROCD=1

start_service() {
  procd_open_instance
  procd_set_param command /usr/bin/gatekeeper \
    --port $ADMIN_PORT \
    --portal-port $PORTAL_PORT \
    --dns-port $DNS_PORT \
    --data-dir /etc/gatekeeper \
    --password "$PASSWORD" \
    --router-ip "$ROUTER_IP" \
    --lan-iface "$LAN_IFACE" \
    $ADMIN_IP_ARG
  procd_set_param respawn 3600 5 5
  procd_set_param stdout 1
  procd_set_param stderr 1
  procd_close_instance
}
EOF
chmod +x /etc/init.d/gatekeeper
/etc/init.d/gatekeeper enable
/etc/init.d/gatekeeper restart

# 等待管理端口就绪
i=0
while [ $i -lt 20 ]; do
  if wget -qO- "http://127.0.0.1:${ADMIN_PORT}/api/auth/me" >/dev/null 2>&1 || curl -fsS "http://127.0.0.1:${ADMIN_PORT}/api/auth/me" >/dev/null 2>&1; then
    break
  fi
  sleep 1
  i=$((i + 1))
done

echo "=================================================="
echo " 部署成功！已自动将您的管理机 IP (${ADMIN_IP:-localhost}) 加入防锁死白名单"
echo " 局域网管理大屏: http://${ROUTER_IP}:${ADMIN_PORT}"
echo " 手机端强制认证页: http://${ROUTER_IP}:${PORTAL_PORT}/portal"
echo "=================================================="

if [ "$TUNNEL_MODE" != "none" ] && command -v cloudflared >/dev/null 2>&1 && command -v curl >/dev/null 2>&1; then
  COOKIE_JAR="/tmp/gk_deploy_cookie"
  rm -f "$COOKIE_JAR"
  curl -fsS -c "$COOKIE_JAR" -H "Content-Type: application/json" \
    -d "{\"password\":\"${PASSWORD}\"}" \
    "http://127.0.0.1:${ADMIN_PORT}/api/auth/login" >/dev/null || true
  curl -fsS -b "$COOKIE_JAR" -H "Content-Type: application/json" \
    -d "{\"mode\":\"${TUNNEL_MODE}\",\"token\":\"${TUNNEL_TOKEN}\"}" \
    "http://127.0.0.1:${ADMIN_PORT}/api/tunnel/start" >/dev/null || true
  j=0
  PUBLIC_URL=""
  while [ $j -lt 15 ]; do
    STATE_JSON=$(curl -fsS -b "$COOKIE_JAR" "http://127.0.0.1:${ADMIN_PORT}/api/state" 2>/dev/null || true)
    PUBLIC_URL=$(echo "$STATE_JSON" | sed -n 's/.*"public_url":"\([^"]*\)".*/\1/p')
    if [ -n "$PUBLIC_URL" ]; then
      break
    fi
    sleep 1
    j=$((j + 1))
  done
  rm -f "$COOKIE_JAR"
  if [ -n "$PUBLIC_URL" ]; then
    echo " 全球外网访问地址: ${PUBLIC_URL}"
  else
    echo " 全球外网隧道正在后台建立中，请在管理大屏顶部 Cloudflare Tunnel 面板查看地址。"
  fi
elif [ "$TUNNEL_MODE" != "none" ]; then
  echo " 提示: 未检测到 cloudflared，您可在管理大屏登录或手动上传 cloudflared-linux-arm64 后点击「一键开启外网控制」。"
fi
'@

$remoteScript = $remoteScript.
    Replace("__ROUTER_IP__", $RouterIP).
    Replace("__ADMIN_PORT__", "$AdminPort").
    Replace("__PORTAL_PORT__", "$PortalPort").
    Replace("__DNS_PORT__", "$DNSPort").
    Replace("__PASSWORD__", $Password).
    Replace("__LAN_IFACE__", $LanIface).
    Replace("__TUNNEL_MODE__", $TunnelMode).
    Replace("__TUNNEL_TOKEN__", $TunnelToken).
    Replace("`r`n", "`n")

Write-Output "`n>>> 步骤 3/4: 在 ImmortalWrt 配置 procd 开机自启、防锁死白名单与 nftables..."
$remoteB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($remoteScript))
& ssh -p $SshPort $target "echo '$remoteB64' | base64 -d | sh"
if ($LASTEXITCODE -ne 0) { throw "远程初始化脚本执行失败" }

Write-Output "`n>>> 步骤 4/4: 全部部署流程已完成！"
