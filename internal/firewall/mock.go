package firewall

import (
	"fmt"
	"strings"
	"sync"

	"gatekeeper/internal/model"
	"gatekeeper/internal/store"
)

// MockManager 在 Windows 本地开发或 --mock 仿真模式下生成真实 nftables 脚本并记录等效防火墙指令日志。
type MockManager struct {
	mu         sync.Mutex
	store      *store.Store
	adminPort  int
	portalPort int
	dnsPort    int
	lastScript string
	ruleCount  int
}

// NewMockManager 创建本地仿真防火墙管理器。
func NewMockManager(st *store.Store, adminPort, portalPort, dnsPort int) *MockManager {
	return &MockManager{
		store:      st,
		adminPort:  adminPort,
		portalPort: portalPort,
		dnsPort:    dnsPort,
	}
}

func (m *MockManager) SyncAll() error {
	if !m.store.IsGatekeeperEnabled() {
		m.mu.Lock()
		m.lastScript = "# [MOCK] 准入认证总开关已关闭（全网自由直通模式）：已移除拦截规则，所有设备直接放行。\n"
		m.ruleCount = 0
		m.mu.Unlock()
		return nil
	}
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
	m.mu.Unlock()
	return nil
}

func (m *MockManager) GrantMAC(mac string) error {
	normMAC, err := model.NormalizeMAC(mac)
	if err != nil {
		return err
	}
	if err := m.SyncAll(); err != nil {
		return err
	}
	m.store.AddAuditEvent("firewall", "[MOCK] nftables 放行 MAC", normMAC,
		fmt.Sprintf("模拟执行: nft add element inet gatekeeper allowed_macs { %s }", strings.ToLower(normMAC)))
	return nil
}

func (m *MockManager) RevokeMAC(mac string, ips ...string) error {
	normMAC, err := model.NormalizeMAC(mac)
	if err != nil {
		return err
	}
	if err := m.SyncAll(); err != nil {
		return err
	}
	var validIPs []string
	for _, ip := range ips {
		if model.IsValidIPv4(ip) {
			validIPs = append(validIPs, ip)
		}
	}
	if dev, ok := m.store.GetDevice(normMAC); ok && model.IsValidIPv4(dev.IP) {
		found := false
		for _, v := range validIPs {
			if v == dev.IP {
				found = true
				break
			}
		}
		if !found {
			validIPs = append(validIPs, dev.IP)
		}
	}
	m.store.AddAuditEvent("firewall", "[MOCK] nftables 撤销放行", normMAC,
		fmt.Sprintf("模拟执行: nft delete element inet gatekeeper allowed_macs { %s }", strings.ToLower(normMAC)))
	if len(validIPs) > 0 {
		_ = m.KillConntrack(validIPs...)
	}
	return nil
}

func (m *MockManager) EnsureHealthy() error {
	return m.SyncAll()
}

func (m *MockManager) KillConntrack(ips ...string) error {
	for _, ip := range ips {
		clean := strings.TrimSpace(ip)
		if !model.IsValidIPv4(clean) {
			continue
		}
		m.store.AddAuditEvent("conntrack", "[MOCK] 掐断存量连接", clean,
			fmt.Sprintf("模拟执行: conntrack -D -s %s && conntrack -D -d %s", clean, clean))
	}
	return nil
}

func (m *MockManager) CurrentScript() string {
	if !m.store.IsGatekeeperEnabled() {
		return "# [MOCK] 准入认证总开关已关闭（全网自由直通模式）：已移除拦截规则，所有设备直接放行。\n"
	}
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

func (m *MockManager) Status() (bool, bool, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return true, true, m.ruleCount
}

func (m *MockManager) Cleanup() error {
	return nil
}
