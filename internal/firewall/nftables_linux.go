//go:build linux

package firewall

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"gatekeeper/internal/model"
	"gatekeeper/internal/store"
)

const cmdTimeout = 5 * time.Second

// NFTablesManager 在 ImmortalWrt / Linux 内核上操作独立的 table inet gatekeeper 并清理 conntrack。
type NFTablesManager struct {
	opMu         sync.Mutex
	mu           sync.Mutex
	store        *store.Store
	adminPort    int
	portalPort   int
	dnsPort      int
	hasNFT       bool
	hasConntrack bool
	active       bool
	lastScript   string
	ruleCount    int
}

// NewLinuxManager 创建真实 Linux nftables 防火墙控制器。
func NewLinuxManager(st *store.Store, adminPort, portalPort, dnsPort int) *NFTablesManager {
	_, nftErr := exec.LookPath("nft")
	_, ctErr := exec.LookPath("conntrack")
	return &NFTablesManager{
		store:        st,
		adminPort:    adminPort,
		portalPort:   portalPort,
		dnsPort:      dnsPort,
		hasNFT:       nftErr == nil,
		hasConntrack: ctErr == nil,
	}
}

func (m *NFTablesManager) SyncAll() error {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	return m.syncAllLocked()
}

func (m *NFTablesManager) syncAllLocked() error {
	if !m.store.IsGatekeeperEnabled() {
		if m.hasNFT {
			ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
			_ = exec.CommandContext(ctx, "nft", "delete", "table", "inet", "gatekeeper").Run()
			cancel()
		}
		m.mu.Lock()
		m.active = false
		m.ruleCount = 0
		m.lastScript = "# 准入认证总开关已关闭（全网自由直通模式）：未加载拦截表，所有设备直接放行。\n"
		m.mu.Unlock()
		return nil
	}

	script, count, err := m.buildCurrentScript()
	if err != nil {
		return err
	}

	m.mu.Lock()
	m.lastScript = script
	m.ruleCount = count
	hasNFT := m.hasNFT
	m.mu.Unlock()

	if !hasNFT {
		return fmt.Errorf("未检测到 nft 命令，请确认 ImmortalWrt 已安装 nftables/fw4")
	}

	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("应用 nftables 规则失败: %w (%s)", err, strings.TrimSpace(stderr.String()))
	}

	m.mu.Lock()
	m.active = true
	m.mu.Unlock()
	return nil
}

func (m *NFTablesManager) buildCurrentScript() (string, int, error) {
	wlMACs, wlIPs, allowedMACs, routerIP, lanIface, allowAdmin := m.store.GetFirewallSets()
	return BuildNFTablesScript(ScriptConfig{
		RouterIP:        routerIP,
		LanIface:        lanIface,
		AdminPort:       m.adminPort,
		PortalPort:      m.portalPort,
		DNSPort:         m.dnsPort,
		WhitelistMACs:   wlMACs,
		WhitelistIPs:    wlIPs,
		AllowedMACs:     allowedMACs,
		AllowAdminPorts: allowAdmin,
	})
}

func (m *NFTablesManager) refreshScriptCache() {
	if script, count, err := m.buildCurrentScript(); err == nil {
		m.mu.Lock()
		m.lastScript = script
		m.ruleCount = count
		m.mu.Unlock()
	}
}

func (m *NFTablesManager) GrantMAC(mac string) error {
	normMAC, err := model.NormalizeMAC(mac)
	if err != nil {
		return err
	}
	lower := strings.ToLower(normMAC)

	m.opMu.Lock()
	m.mu.Lock()
	isActive := m.active && m.hasNFT
	m.mu.Unlock()

	applied := false
	if isActive {
		ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
		cmd := exec.CommandContext(ctx, "nft", "add", "element", "inet", "gatekeeper", "allowed_macs", fmt.Sprintf("{ %s }", lower))
		if err := cmd.Run(); err == nil {
			applied = true
			m.refreshScriptCache()
		}
		cancel()
	}
	if !applied {
		if err := m.syncAllLocked(); err != nil {
			m.opMu.Unlock()
			return err
		}
	}
	m.opMu.Unlock()

	m.store.AddAuditEvent("firewall", "nftables 放行规则生效", normMAC,
		fmt.Sprintf("已将 %s 加入 table inet gatekeeper @allowed_macs 集合", lower))
	return nil
}

func (m *NFTablesManager) RevokeMAC(mac string, ips ...string) error {
	normMAC, err := model.NormalizeMAC(mac)
	if err != nil {
		return err
	}
	lower := strings.ToLower(normMAC)

	m.opMu.Lock()
	m.mu.Lock()
	isActive := m.active && m.hasNFT
	m.mu.Unlock()

	revoked := false
	if isActive {
		ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
		cmd := exec.CommandContext(ctx, "nft", "delete", "element", "inet", "gatekeeper", "allowed_macs", fmt.Sprintf("{ %s }", lower))
		if err := cmd.Run(); err == nil {
			revoked = true
			m.refreshScriptCache()
		}
		cancel()
	}
	if !revoked {
		if err := m.syncAllLocked(); err != nil {
			m.opMu.Unlock()
			return err
		}
	}
	m.opMu.Unlock()

	allIPs := m.collectDeviceIPs(normMAC, ips)
	_ = m.KillConntrack(allIPs...)
	m.store.AddAuditEvent("firewall", "nftables 拦截并断流", normMAC,
		fmt.Sprintf("已从 @allowed_macs 移除 %s，并清理 %v 的 conntrack 存量连接", lower, allIPs))
	return nil
}

func (m *NFTablesManager) EnsureHealthy() error {
	if !m.hasNFT || !m.store.IsGatekeeperEnabled() {
		return nil
	}
	m.opMu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	cmd := exec.CommandContext(ctx, "nft", "list", "table", "inet", "gatekeeper")
	err := cmd.Run()
	cancel()
	if err != nil {
		syncErr := m.syncAllLocked()
		m.opMu.Unlock()
		if syncErr != nil {
			return syncErr
		}
		m.store.AddAuditEvent("firewall", "防火墙规则自愈恢复", "gatekeeper", "检测到 gatekeeper 表缺失，已自动重建全部防绕过规则")
		return nil
	}
	m.opMu.Unlock()
	return nil
}

func (m *NFTablesManager) KillConntrack(ips ...string) error {
	if !m.hasConntrack {
		return nil
	}
	seen := make(map[string]struct{})
	for _, raw := range ips {
		ip := strings.TrimSpace(raw)
		if !model.IsValidIPv4(ip) {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		ctx1, c1 := context.WithTimeout(context.Background(), cmdTimeout)
		_ = exec.CommandContext(ctx1, "conntrack", "-D", "-s", ip).Run()
		c1()
		ctx2, c2 := context.WithTimeout(context.Background(), cmdTimeout)
		_ = exec.CommandContext(ctx2, "conntrack", "-D", "-d", ip).Run()
		c2()
	}
	return nil
}

func (m *NFTablesManager) CurrentScript() string {
	if !m.store.IsGatekeeperEnabled() {
		return "# 准入认证总开关已关闭（全网自由直通模式）：未加载拦截表，所有设备直接放行。\n"
	}
	m.mu.Lock()
	cached := m.lastScript
	m.mu.Unlock()
	if cached != "" {
		return cached
	}
	script, count, _ := m.buildCurrentScript()
	m.mu.Lock()
	m.lastScript = script
	m.ruleCount = count
	m.mu.Unlock()
	return script
}

func (m *NFTablesManager) Status() (bool, bool, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active && m.hasNFT, m.hasConntrack, m.ruleCount
}

func (m *NFTablesManager) Cleanup() error {
	if !m.hasNFT {
		return nil
	}
	m.opMu.Lock()
	defer m.opMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	return exec.CommandContext(ctx, "nft", "delete", "table", "inet", "gatekeeper").Run()
}

func (m *NFTablesManager) collectDeviceIPs(normMAC string, extra []string) []string {
	set := make(map[string]struct{})
	for _, ip := range extra {
		clean := strings.TrimSpace(ip)
		if model.IsValidIPv4(clean) {
			set[clean] = struct{}{}
		}
	}
	if dev, ok := m.store.GetDevice(normMAC); ok && model.IsValidIPv4(dev.IP) {
		set[dev.IP] = struct{}{}
	}
	if raw, err := os.ReadFile("/proc/net/arp"); err == nil {
		for _, line := range strings.Split(string(raw), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				if m, err := model.NormalizeMAC(fields[3]); err == nil && m == normMAC && model.IsValidIPv4(fields[0]) {
					set[fields[0]] = struct{}{}
				}
			}
		}
	}
	out := make([]string, 0, len(set))
	for ip := range set {
		out = append(out, ip)
	}
	return out
}
