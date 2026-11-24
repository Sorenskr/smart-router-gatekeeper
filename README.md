# Smart Router Gatekeeper · 软路由设备准入认证与全球实时云控系统

一套专为 **ImmortalWrt 24.10 / OpenWrt (`aarch64`)** 打造的零依赖、单文件设备准入控制（Captive Portal）与全球实时云控管理面板。同时内置 `--mock` 本地仿真模式，可在 Windows / macOS / Linux 本机零路由器环境 100% 预览与测试全部功能。

---

## 核心特性

1. **防 PassWall 绕过的独立 `nftables` 准入引擎**
   - 独立维护 `table inet gatekeeper`，不污染系统 `fw4` 与 PassWall 规则。
   - `prerouting` 链以 `-170`（filter）与 `-160`（nat）高优先级抢在 PassWall `TPROXY (-150)` / `REDIRECT (-100)` 与 `dnsmasq` 之前生效，彻底阻断未授权设备的国内/外网/代理/DNS/IPv6 流量。
   - 内置 Captive DNS（`:5354`）与 Captive Portal（`:8089`），手机连 Wi-Fi 自动弹出登录页。
   - 断网/顶替时自动执行 `conntrack -D` 秒级掐断存量长连接。
   - 强制防锁死兜底：自动保护网关 `192.168.6.1`、管理主机 IP/MAC 白名单及 SSH `22` / 管理端口 `8088`。

2. **极速无卡顿管控大屏（`:8088`）**
   - 采用纯 Go 标准库 + `//go:embed` 内嵌静态资源，无重度模糊重绘、Keyed 增量更新 DOM 与前端 0ms 乐观响应。
   - **设备快捷备注**：点击设备名称即可输入备注，并提供「电脑」「手机」「平板」「测试机」「办公机」快捷标签一键保存。
   - **联网时间与多单位时长切换**：直观显示设备何时联网；点击「已连时长」胶囊可在 **`分钟 → 小时 → 天`** 之间循环切换（1 秒精确走表）。
   - **一键断网 / 定时断网 / 一键恢复**：支持立即永久断网，或设置断网 **5分钟 / 15分钟 / 30分钟 / 1小时 / 2小时 / 6小时 / 自定义分钟或小时**，倒计时结束由后端每秒调度器自动恢复放行；支持随时手动提前恢复。
   - **并发上限锁**：可随时调设最大同时在线设备数（白名单不占名额），超限审批时弹窗提示一键顶替最早接入的设备。
   - **多维筛选与排序**：按全部/已联网/待审批/已断网/白名单筛选，按联网时间、已连时长、实时网速、备注名或 IP 升降序排列。

3. **全球异地远程控制（Cloudflare Tunnel）**
   - 集成 `cloudflared` Quick Tunnel（免公网 IP、免域名一键生成 `https://*.trycloudflare.com`）与 Named Tunnel Token 模式。

---

## 快速本地仿真运行（Windows / 开发调试）

```powershell
# 运行构建脚本（编译 Windows amd64 与 ImmortalWrt linux/arm64）
powershell -ExecutionPolicy Bypass -File .\scripts\build.ps1

# 启动本地仿真模式
.\dist\gatekeeper-windows-amd64.exe --mock --port 8088 --portal-port 8089 --data-dir .\data
```

- **管理大屏**：`http://127.0.0.1:8088`（默认密码 `admin123`）
- **模拟手机认证页**：`http://127.0.0.1:8089/portal`

---

## 一键部署到 ImmortalWrt (`aarch64`, `192.168.6.1`)

### PowerShell（推荐）
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\deploy_to_immortalwrt.ps1 -RouterIP 192.168.6.1 -Password "您的管理密码"
```

### Bash / WSL
```bash
ROUTER_IP=192.168.6.1 PASSWORD="您的管理密码" bash ./scripts/deploy_to_immortalwrt.sh
```

部署脚本将自动把静态编译的 `gatekeeper-linux-arm64` 上传到 `/usr/bin/gatekeeper`，将当前电脑 IP 加入防锁死白名单，开启 `net.netfilter.nf_conntrack_acct=1`，创建 `/etc/init.d/gatekeeper` 开机自启并输出局域网及 Cloudflare 公网 HTTPS 访问地址。
