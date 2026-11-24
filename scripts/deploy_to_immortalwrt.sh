#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

ROUTER_IP="${ROUTER_IP:-192.168.6.1}"
SSH_USER="${SSH_USER:-root}"
SSH_PORT="${SSH_PORT:-22}"
ADMIN_PORT="${ADMIN_PORT:-8088}"
PORTAL_PORT="${PORTAL_PORT:-8089}"
DNS_PORT="${DNS_PORT:-5354}"
PASSWORD="${PASSWORD:-admin123}"
LAN_IFACE="${LAN_IFACE:-br-lan}"
TUNNEL_MODE="${TUNNEL_MODE:-quick}"
TUNNEL_TOKEN="${TUNNEL_TOKEN:-}"

ARM_BIN="$ROOT_DIR/dist/gatekeeper-linux-arm64"
GO_BIN="$(command -v go || true)"
if [ -z "$GO_BIN" ] && [ -x "$ROOT_DIR/.toolchain/go/bin/go" ]; then
  GO_BIN="$ROOT_DIR/.toolchain/go/bin/go"
fi

if [ ! -f "$ARM_BIN" ] && [ -n "$GO_BIN" ]; then
  echo ">>> [1/3] 正在交叉编译 linux/arm64 静态二进制文件..."
  mkdir -p "$ROOT_DIR/dist"
  (cd "$ROOT_DIR" && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 "$GO_BIN" build -trimpath -ldflags="-s -w" -o "$ARM_BIN" .)
fi

if [ ! -f "$ARM_BIN" ]; then
  echo "错误: 未找到 $ARM_BIN 且当前环境未检测到 Go 编译器" >&2
  exit 1
fi

echo ">>> [2/3] 正在上传二进制文件至 ${SSH_USER}@${ROUTER_IP}..."
scp -P "$SSH_PORT" "$ARM_BIN" "${SSH_USER}@${ROUTER_IP}:/tmp/gatekeeper.new"

echo ">>> [3/3] 正在配置开机自启、防锁死白名单与全球加密隧道..."
ssh -p "$SSH_PORT" "${SSH_USER}@${ROUTER_IP}" "ROUTER_IP='$ROUTER_IP' ADMIN_PORT='$ADMIN_PORT' PORTAL_PORT='$PORTAL_PORT' DNS_PORT='$DNS_PORT' PASSWORD='$PASSWORD' LAN_IFACE='$LAN_IFACE' TUNNEL_MODE='$TUNNEL_MODE' TUNNEL_TOKEN='$TUNNEL_TOKEN' sh -s" <<'REMOTE_EOF'
set -eu
ADMIN_IP=""
if [ -n "${SSH_CLIENT:-}" ]; then
  ADMIN_IP=$(echo "$SSH_CLIENT" | awk '{print $1}')
fi

mv /tmp/gatekeeper.new /usr/bin/gatekeeper
chmod +x /usr/bin/gatekeeper
mkdir -p /etc/gatekeeper

sysctl -w net.netfilter.nf_conntrack_acct=1 >/dev/null 2>&1 || true
mkdir -p /etc/sysctl.d
echo "net.netfilter.nf_conntrack_acct=1" > /etc/sysctl.d/99-gatekeeper.conf

if ! command -v conntrack >/dev/null 2>&1; then
  if command -v apk >/dev/null 2>&1; then
    apk update >/dev/null 2>&1 || true
    apk add conntrack-tools >/dev/null 2>&1 || true
  elif command -v opkg >/dev/null 2>&1; then
    opkg update >/dev/null 2>&1 || true
    opkg install conntrack >/dev/null 2>&1 || true
  fi
fi

if [ "$TUNNEL_MODE" != "none" ] && ! command -v cloudflared >/dev/null 2>&1; then
  if command -v apk >/dev/null 2>&1; then
    apk add cloudflared >/dev/null 2>&1 || true
  elif command -v opkg >/dev/null 2>&1; then
    opkg install cloudflared >/dev/null 2>&1 || true
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

echo "=================================================="
echo " 部署完成！本地管理后台: http://${ROUTER_IP}:${ADMIN_PORT}"
echo " 手机端强制认证页: http://${ROUTER_IP}:${PORTAL_PORT}/portal"
echo "=================================================="

if [ "$TUNNEL_MODE" != "none" ] && command -v cloudflared >/dev/null 2>&1 && command -v curl >/dev/null 2>&1; then
  COOKIE_JAR="/tmp/gk_deploy_cookie"
  rm -f "$COOKIE_JAR"
  sleep 2
  curl -fsS -c "$COOKIE_JAR" -H "Content-Type: application/json" -d "{\"password\":\"${PASSWORD}\"}" "http://127.0.0.1:${ADMIN_PORT}/api/auth/login" >/dev/null || true
  curl -fsS -b "$COOKIE_JAR" -H "Content-Type: application/json" -d "{\"mode\":\"${TUNNEL_MODE}\",\"token\":\"${TUNNEL_TOKEN}\"}" "http://127.0.0.1:${ADMIN_PORT}/api/tunnel/start" >/dev/null || true
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do
    STATE_JSON=$(curl -fsS -b "$COOKIE_JAR" "http://127.0.0.1:${ADMIN_PORT}/api/state" 2>/dev/null || true)
    PUBLIC_URL=$(echo "$STATE_JSON" | sed -n 's/.*"public_url":"\([^"]*\)".*/\1/p')
    if [ -n "$PUBLIC_URL" ]; then
      echo " 全球外网访问地址: ${PUBLIC_URL}"
      break
    fi
    sleep 1
  done
  rm -f "$COOKIE_JAR"
fi
REMOTE_EOF
