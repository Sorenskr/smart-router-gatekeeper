//go:build linux

package firewall

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"

	"gatekeeper/internal/model"
	"gatekeeper/internal/store"
)

// NFTablesManager 在 ImmortalWrt / Linux 内核上操作独立的 table inet gatekeeper 并清理 conntrack。
type NFTablesManager struct {
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
	wlMACs, wlIPs, allowedMACs, routerIP, lanIface, allowAdmin := m.store.GetFirewallSets()
	script, count, err := BuildNFTablesScript(ScriptConfig{
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

	cmd := exec.Command("nft", "-f", "-")
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

func (m *NFTablesManager) GrantMAC(mac string) error {
	normMAC, err := model.NormalizeMAC(mac)
	if err != nil {
		return err
	}
	if err := m.SyncAll(); err != nil {
		return err
	}
	m.store.AddAuditEvent("firewall", "nftables 放行规则生效", normMAC,
		fmt.Sprintf("已将 %s 加入 table inet gatekeeper @allowed_macs 集合", strings.ToLower(normMAC)))
	return nil
}

func (m *NFTablesManager) RevokeMAC(mac string, ips ...string) error {
	normMAC, err := model.NormalizeMAC(mac)
	if err != nil {
		return err
	}
	if err := m.SyncAll(); err != nil {
		return err
	}
	allIPs := m.collectDeviceIPs(normMAC, ips)
	_ = m.KillConntrack(allIPs...)
	m.store.AddAuditEvent("firewall", "nftables 拦截并断流", normMAC,
		fmt.Sprintf("已从 @allowed_macs 移除 %s，并清理 %v 的 conntrack 存量连接", strings.ToLower(normMAC), allIPs))
	return nil
}

func (m *NFTablesManager) EnsureHealthy() error {
	if !m.hasNFT {
		return nil
	}
	cmd := exec.Command("nft", "list", "table", "inet", "gatekeeper")
	if err := cmd.Run(); err != nil {
		if syncErr := m.SyncAll(); syncErr != nil {
			return syncErr
		}
		m.store.AddAuditEvent("firewall", "防火墙规则自愈恢复", "gatekeeper", "检测到 gatekeeper 表缺失，已自动重建全部防绕过规则")
	}
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
		_ = exec.Command("conntrack", "-D", "-s", ip).Run()
		_ = exec.Command("conntrack", "-D", "-d", ip).Run()
	}
	return nil
}

func (m *NFTablesManager) CurrentScript() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastScript != "" {
		return m.lastScript
	}
	wlMACs, wlIPs, allowedMACs, routerIP, lanIface, allowAdmin := m.store.GetFirewallSets()
	script, count, _ := BuildNFTablesScript(ScriptConfig{
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
	m.lastScript = script
	m.ruleCount = count
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
	return exec.Command("nft", "delete", "table", "inet", "gatekeeper").Run()
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
