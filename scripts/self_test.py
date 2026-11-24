#!/usr/bin/env python3
"""
Smart Router Gatekeeper 端到端自动化验收测试脚本
直接拉起编译后的二进制进程 (--mock)，覆盖：
  测试 1：模拟新手机连接 -> 提交名字 "测试机_阿杰" -> 验证 REST 与 WebSocket 实时收到待审批记录
  测试 2：设置最大连接数为 2 -> 已有 2 台授权 -> 批准第 3 台触发 409 上限拦截 -> 验证一键顶替并触发 conntrack -D 日志
  测试 3：一键断网 -> 验证状态变 paused & 门户变为暂停态 & 速率归零 -> 恢复连网 -> 验证恢复 approved
  测试 4：修改设备名称 -> 重启服务进程 -> 验证持久化不丢失
  测试 5：审查 nftables 防锁死、PassWall 绕过阻断、DNS 劫持、Captive 探针 302/204 以及 Mock Tunnel 启停
"""

import base64
import hashlib
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ADMIN_PORT = 18088
PORTAL_PORT = 18089
ADMIN_BASE = f"http://127.0.0.1:{ADMIN_PORT}"
PORTAL_BASE = f"http://127.0.0.1:{PORTAL_PORT}"


_NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def http_json(url, method="GET", body=None, token=None):
    data = None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with _NO_PROXY_OPENER.open(req, timeout=8) as resp:
            raw = resp.read().decode("utf-8")
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8")
        try:
            parsed = json.loads(raw) if raw else {}
        except Exception:
            parsed = {"raw": raw}
        return e.code, parsed


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def http_probe(url):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirectHandler())
    try:
        resp = opener.open(url, timeout=5)
        return resp.status, resp.headers.get("Location", ""), resp.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Location", ""), ""


def ws_connect_and_read_one(host, port, path):
    """使用纯 Python socket 完成 RFC 6455 WebSocket 握手并读取一条 JSON 推送帧"""
    sock = socket.create_connection((host, port), timeout=6)
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    )
    sock.sendall(req.encode("ascii"))

    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("WebSocket 握手连接意外关闭")
        buf += chunk

    head, rest = buf.split(b"\r\n\r\n", 1)
    head_str = head.decode("ascii", errors="ignore")
    if "101 Switching Protocols" not in head_str:
        raise RuntimeError(f"WebSocket 握手失败: {head_str}")

    expected_accept = base64.b64encode(
        hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()
    ).decode("ascii")
    if expected_accept not in head_str:
        raise RuntimeError("WebSocket Sec-WebSocket-Accept 校验失败")

    def read_exact(n):
        nonlocal rest
        while len(rest) < n:
            more = sock.recv(4096)
            if not more:
                raise RuntimeError("读取 WebSocket 帧中断")
            rest += more
        out = rest[:n]
        rest = rest[n:]
        return out

    b1, b2 = read_exact(2)
    length = b2 & 0x7F
    if length == 126:
        length = struct.unpack("!H", read_exact(2))[0]
    elif length == 127:
        length = struct.unpack("!Q", read_exact(8))[0]
    payload = read_exact(length)
    sock.close()
    return json.loads(payload.decode("utf-8"))


def wait_ready(proc):
    for _ in range(30):
        if proc.poll() is not None:
            out = proc.stdout.read() if proc.stdout else ""
            raise RuntimeError(f"测试服务端提前退出 (exit={proc.returncode})，输出:\n{out}")
        try:
            code, data = http_json(f"{ADMIN_BASE}/api/auth/me")
            if code == 200 and data.get("mock_mode") is True:
                return
        except Exception:
            pass
        time.sleep(0.3)
    out = ""
    if proc.poll() is not None and proc.stdout:
        out = proc.stdout.read()
    raise RuntimeError(f"测试服务端未能在规定时间内启动就绪。\n{out}")


def start_proc(exe_path, data_dir):
    return subprocess.Popen(
        [
            exe_path,
            "--mock",
            "--port", str(ADMIN_PORT),
            "--portal-port", str(PORTAL_PORT),
            "--data-dir", data_dir,
            "--admin-ip", "192.168.6.10",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def stop_proc(proc):
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    exe_path = os.path.join(root, "dist", "gatekeeper-windows-amd64.exe")
    if not os.path.exists(exe_path):
        raise FileNotFoundError(f"未找到可执行文件: {exe_path}")

    test_base = os.path.join(root, ".toolchain")
    os.makedirs(test_base, exist_ok=True)
    temp_dir = tempfile.mkdtemp(prefix="gk_selftest_", dir=test_base)
    proc = None
    try:
        print(f"[启动] 拉起仿真服务端进行自检 (data-dir={temp_dir})...")
        proc = start_proc(exe_path, temp_dir)
        wait_ready(proc)

        # 登录获取 Token
        code, login = http_json(f"{ADMIN_BASE}/api/auth/login", "POST", {"password": "admin123"})
        assert code == 200 and login.get("ok"), f"登录失败: {code} {login}"
        token = login["token"]

        # 验证 WebSocket 连接并读取首帧全量快照
        ws_msg = ws_connect_and_read_one("127.0.0.1", ADMIN_PORT, f"/api/ws?token={token}")
        assert ws_msg.get("type") == "state", f"WS 初始帧类型错误: {ws_msg}"
        assert len(ws_msg["data"]["devices"]) == 5, "Mock 模式初始应有 5 台仿真设备"
        print("[通过] WebSocket 握手与 5 台初始设备检测正常")

        # 测试 1：模拟新手机连接 -> 提交名字 "测试机_阿杰" -> 后台收到待审批
        new_mac = "AA:BB:CC:77:88:99"
        code, apply_res = http_json(
            f"{PORTAL_BASE}/api/portal/apply?mac={new_mac}",
            "POST",
            {"name": "测试机_阿杰", "mac": new_mac, "ip": "192.168.6.177", "hostname": "Pixel-Ajie"},
        )
        assert code == 200 and apply_res["portal"]["status"] == "pending", f"测试1 申请失败: {apply_res}"

        ws_after_apply = ws_connect_and_read_one("127.0.0.1", ADMIN_PORT, f"/api/ws?token={token}")
        devs = {d["mac"]: d for d in ws_after_apply["data"]["devices"]}
        assert new_mac in devs and devs[new_mac]["status"] == "pending" and devs[new_mac]["requested_name"] == "测试机_阿杰", \
            "测试1 后台未及时收到待审批记录"
        print("[通过] 测试 1：新手机提交「测试机_阿杰」并实时推送到管理端")

        # 测试 2：设置最大连接数为 2 -> 已有 2 台已授权 -> 批准第 3 台触发 409 上限拦截 -> 一键顶替
        code, _ = http_json(f"{ADMIN_BASE}/api/settings", "PUT", {"max_concurrent_devices": 2}, token)
        assert code == 200
        code, conflict = http_json(f"{ADMIN_BASE}/api/devices/{new_mac}/approve", "POST", {}, token)
        assert code == 409 and conflict.get("code") == "CONCURRENCY_LIMIT_REACHED", f"测试2 未触发上限拦截: {code} {conflict}"
        oldest_mac = conflict["oldest_device"]["mac"]
        assert oldest_mac == "AA:BB:CC:11:22:01", f"最早接入设备判断错误: {oldest_mac}"

        code, replaced = http_json(
            f"{ADMIN_BASE}/api/devices/{new_mac}/approve",
            "POST",
            {"replace_oldest": True},
            token,
        )
        assert code == 200 and replaced["evicted"]["mac"] == oldest_mac, f"测试2 顶替失败: {replaced}"
        print(f"[通过] 测试 2：并发上限 (2/2) 精确拦截 409，并一键顶替最早设备 {oldest_mac}")

        # 测试 3：对已连接手机执行一键断网 -> 状态变 paused -> 恢复连网 -> 状态恢复 approved
        code, paused = http_json(f"{ADMIN_BASE}/api/devices/{new_mac}/pause", "POST", {}, token)
        assert code == 200 and paused["device"]["status"] == "paused"

        code, p_status = http_json(f"{PORTAL_BASE}/api/portal/status?mac={new_mac}")
        assert code == 200 and p_status["status"] == "paused" and "暂停" in p_status["message"]

        # 验证门户探针未放行返回 302 跳转
        probe_code, probe_loc, _ = http_probe(f"{PORTAL_BASE}/generate_204?mac={new_mac}")
        assert probe_code == 302 and "/portal" in probe_loc, f"暂停设备探针应 302 跳转，实际 {probe_code} {probe_loc}"

        # 恢复连网
        code, resumed = http_json(f"{ADMIN_BASE}/api/devices/{new_mac}/resume", "POST", {}, token)
        assert code == 200 and resumed["device"]["status"] == "approved"
        probe_ok_code, _, _ = http_probe(f"{PORTAL_BASE}/generate_204?mac={new_mac}")
        assert probe_ok_code == 204, f"放行后探针应返回 204，实际 {probe_ok_code}"
        print("[通过] 测试 3：一键断网 / 恢复连网与手机认证页 / Captive 探针状态闭环正常")

        # 测试 4：修改设备名称 + 修改上限为 3 -> 重启二进制进程 -> 验证数据持久化不丢失
        code, _ = http_json(f"{ADMIN_BASE}/api/devices/{new_mac}/remark", "PUT", {"remark": "阿杰主力手机_已持久化"}, token)
        assert code == 200
        code, _ = http_json(f"{ADMIN_BASE}/api/settings", "PUT", {"max_concurrent_devices": 3}, token)
        assert code == 200

        stop_proc(proc)
        proc = start_proc(exe_path, temp_dir)
        wait_ready(proc)
        code, login2 = http_json(f"{ADMIN_BASE}/api/auth/login", "POST", {"password": "admin123"})
        assert code == 200
        token2 = login2["token"]

        code, snap2 = http_json(f"{ADMIN_BASE}/api/state", "GET", None, token2)
        assert code == 200
        devs2 = {d["mac"]: d for d in snap2["devices"]}
        assert devs2[new_mac]["admin_remark"] == "阿杰主力手机_已持久化", "测试4 设备备注未持久化"
        assert devs2[new_mac]["status"] == "approved", "测试4 设备状态未持久化"
        assert snap2["settings"]["max_concurrent_devices"] == 3, "测试4 并发上限未持久化"
        print("[通过] 测试 4：服务重启后设备备注、状态与并发配置 100% 持久化不丢失")

        # 验证内嵌静态资源与门户页 HTTP 200 正常返回
        for page_url in [
            f"{ADMIN_BASE}/",
            f"{ADMIN_BASE}/styles.css",
            f"{ADMIN_BASE}/dashboard.js",
            f"{PORTAL_BASE}/portal",
            f"{PORTAL_BASE}/portal.js",
        ]:
            p_code, _, p_body = http_probe(page_url)
            assert p_code == 200 and len(p_body) > 100, f"静态页面加载异常: {page_url} code={p_code}"

        # 验证门户单设备 WebSocket 推送正常
        p_ws = ws_connect_and_read_one("127.0.0.1", PORTAL_PORT, f"/api/portal/ws?mac={new_mac}")
        assert p_ws.get("type") == "portal_status" and p_ws["data"]["mac"] == new_mac, f"门户 WS 状态异常: {p_ws}"

        # 测试 5：审查 nftables 脚本、防锁死、防 PassWall 绕过、conntrack 审计与 Mock Cloudflare Tunnel
        code, fw_res = http_json(f"{ADMIN_BASE}/api/firewall/script", "GET", None, token2)
        assert code == 200
        script = fw_res["script"]
        for must_have in [
            "table inet gatekeeper",
            "type filter hook prerouting priority -170",
            "type nat hook prerouting priority -160",
            "udp dport 53 counter redirect to :5354",
            "tcp dport 53 counter redirect to :5354",
            f"tcp dport 80 counter redirect to :{PORTAL_PORT}",
            f"ip daddr 192.168.6.1 tcp dport {{ 22, {ADMIN_PORT} }} counter accept",
            "192.168.6.10",
            "00:1a:2b:3c:4d:01",
            "aa:bb:cc:77:88:99",
        ]:
            assert must_have in script, f"测试5 nftables 脚本缺失关键规则: {must_have}"

        assert "conntrack -D" in json.dumps(snap2["audit_logs"], ensure_ascii=False), "测试5 缺少 conntrack -D 审计日志"

        # 测试 Mock Cloudflare Tunnel 一键开启与关闭
        code, tun_start = http_json(f"{ADMIN_BASE}/api/tunnel/start", "POST", {"mode": "quick"}, token2)
        assert code == 200 and tun_start["tunnel"]["running"] and "trycloudflare.com" in tun_start["tunnel"]["public_url"]
        code, tun_stop = http_json(f"{ADMIN_BASE}/api/tunnel/stop", "POST", {}, token2)
        assert code == 200 and not tun_stop["tunnel"]["running"]
        print("[通过] 测试 5：nftables 防锁死、防 PassWall 绕过、conntrack 清理与云端隧道全部合规")

        # 测试 6：定时断网 (分钟/秒) -> 到期自动恢复 -> 手动提前恢复 -> 定时断网持久化
        code, tp_res = http_json(f"{ADMIN_BASE}/api/devices/{new_mac}/pause", "POST", {"duration_seconds": 2}, token2)
        assert code == 200 and tp_res["device"]["status"] == "paused" and tp_res["device"].get("pause_until"), f"定时断网失败: {tp_res}"

        code, p_timed = http_json(f"{PORTAL_BASE}/api/portal/status?mac={new_mac}")
        assert code == 200 and p_timed["status"] == "paused" and p_timed.get("pause_remaining_sec", 0) > 0, f"门户倒计时异常: {p_timed}"

        # 等待后台调度器自动恢复
        auto_ok = False
        for _ in range(25):
            time.sleep(0.25)
            _, p_cur = http_json(f"{PORTAL_BASE}/api/portal/status?mac={new_mac}")
            if p_cur["status"] == "approved" and not p_cur.get("pause_until"):
                auto_ok = True
                break
        assert auto_ok, "测试 6 定时断网到期后未在规定时间内自动恢复连网"
        probe_after_auto, _, _ = http_probe(f"{PORTAL_BASE}/generate_204?mac={new_mac}")
        assert probe_after_auto == 204, f"自动恢复后探针应返回 204，实际 {probe_after_auto}"

        # 设 45 分钟定时断网 -> 手动提前恢复
        code, _ = http_json(f"{ADMIN_BASE}/api/devices/{new_mac}/pause", "POST", {"duration_minutes": 45}, token2)
        assert code == 200
        code, manual_res = http_json(f"{ADMIN_BASE}/api/devices/{new_mac}/resume", "POST", {}, token2)
        assert code == 200 and manual_res["device"]["status"] == "approved" and not manual_res["device"].get("pause_until")

        # 设 60 分钟定时断网 -> 重启进程验证倒计时截止时间持久化
        code, _ = http_json(f"{ADMIN_BASE}/api/devices/{new_mac}/pause", "POST", {"duration_minutes": 60}, token2)
        assert code == 200
        stop_proc(proc)
        proc = start_proc(exe_path, temp_dir)
        wait_ready(proc)
        _, login3 = http_json(f"{ADMIN_BASE}/api/auth/login", "POST", {"password": "admin123"})
        _, snap3 = http_json(f"{ADMIN_BASE}/api/state", "GET", None, login3["token"])
        devs3 = {d["mac"]: d for d in snap3["devices"]}
        assert devs3[new_mac]["status"] == "paused" and devs3[new_mac].get("pause_until") and devs3[new_mac]["pause_remaining_sec"] > 3000, \
            f"测试 6 重启后定时断网倒计时未持久化: {devs3[new_mac]}"
        print("[通过] 测试 6：定时断网自动恢复、手动提前恢复与重启倒计时持久化全部通过")

        print("\n>>> 全部 6 项自动化端到端验收测试 100% 通过！")
    finally:
        stop_proc(proc)
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
