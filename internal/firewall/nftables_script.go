package firewall

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gatekeeper/internal/model"
)

var safeIfacePattern = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,32}$`)

// ScriptConfig 描述生成独立 table inet gatekeeper 脚本所需的全部参数。
type ScriptConfig struct {
	RouterIP        string
	LanIface        string
	AdminPort       int
	PortalPort      int
	DNSPort         int
	WhitelistMACs   []string
	WhitelistIPs    []string
	AllowedMACs     []string
	AllowAdminPorts bool
}

// BuildNFTablesScript 生成幂等、独立、防 PassWall 绕过且具备管理机防锁死兜底的 nftables 脚本。
func BuildNFTablesScript(cfg ScriptConfig) (string, int, error) {
	routerIP := strings.TrimSpace(cfg.RouterIP)
	if !model.IsValidIPv4(routerIP) {
		routerIP = "192.168.6.1"
	}
	lanIface := strings.TrimSpace(cfg.LanIface)
	if !safeIfacePattern.MatchString(lanIface) {
		lanIface = "br-lan"
	}
	if cfg.AdminPort <= 0 || cfg.AdminPort > 65535 {
		cfg.AdminPort = 8088
	}
	if cfg.PortalPort <= 0 || cfg.PortalPort > 65535 {
		cfg.PortalPort = 8089
	}
	if cfg.DNSPort <= 0 || cfg.DNSPort > 65535 {
		cfg.DNSPort = 5354
	}

	wlMACs := sanitizeMACList(cfg.WhitelistMACs)
	allowedMACs := sanitizeMACList(cfg.AllowedMACs)
	wlIPs := sanitizeIPList(append(cfg.WhitelistIPs, routerIP, "127.0.0.1"))

	var b strings.Builder
	ruleCount := 0

	b.WriteString("#!/usr/sbin/nft -f\n")
	b.WriteString("# Smart Router Gatekeeper - 独立准入隔离表（不修改 fw4 / passwall 表）\n")
	b.WriteString("table inet gatekeeper\n")
	b.WriteString("delete table inet gatekeeper\n\n")
	b.WriteString("table inet gatekeeper {\n")

	// 1. 永久白名单 MAC 集合（管理主机/免审设备）
	b.WriteString("  set whitelist_macs {\n")
	b.WriteString("    type ether_addr\n")
	if len(wlMACs) > 0 {
		b.WriteString(fmt.Sprintf("    elements = { %s }\n", strings.Join(wlMACs, ", ")))
	}
	b.WriteString("  }\n\n")

	// 2. 永久白名单 IP 集合（含路由器网关 IP 与启动防锁死管理 IP）
	b.WriteString("  set whitelist_ips {\n")
	b.WriteString("    type ipv4_addr\n")
	if len(wlIPs) > 0 {
		b.WriteString(fmt.Sprintf("    elements = { %s }\n", strings.Join(wlIPs, ", ")))
	}
	b.WriteString("  }\n\n")

	// 3. 动态已授权联网设备 MAC 集合
	b.WriteString("  set allowed_macs {\n")
	b.WriteString("    type ether_addr\n")
	if len(allowedMACs) > 0 {
		b.WriteString(fmt.Sprintf("    elements = { %s }\n", strings.Join(allowedMACs, ", ")))
	}
	b.WriteString("  }\n\n")

	// 链 1：prerouting_guard（priority -170，抢在 PassWall TPROXY -150 与 REDIRECT -100 之前拦截！）
	b.WriteString("  chain prerouting_guard {\n")
	b.WriteString("    type filter hook prerouting priority -170; policy accept;\n")
	b.WriteString(fmt.Sprintf("    iifname != \"%s\" accept\n", lanIface))
	b.WriteString("    ether saddr @whitelist_macs counter accept\n")
	b.WriteString("    ip saddr @whitelist_ips counter accept\n")
	b.WriteString("    ether saddr @allowed_macs counter accept\n")
	b.WriteString("    udp dport { 67, 68 } counter accept\n")
	b.WriteString("    udp dport 53 counter accept\n")
	b.WriteString("    tcp dport 53 counter accept\n")
	b.WriteString("    tcp dport 80 counter accept\n")
	b.WriteString(fmt.Sprintf("    ip daddr %s tcp dport %d counter accept\n", routerIP, cfg.PortalPort))
	ruleCount += 9

	if cfg.AllowAdminPorts {
		b.WriteString(fmt.Sprintf("    ip daddr %s tcp dport { 22, %d } counter accept\n", routerIP, cfg.AdminPort))
		ruleCount++
	}
	b.WriteString(fmt.Sprintf("    ip daddr %s icmp type echo-request counter accept\n", routerIP))
	b.WriteString("    icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } counter accept\n")
	b.WriteString("    counter drop\n")
	b.WriteString("  }\n\n")
	ruleCount += 3

	// 链 2：prerouting_portal_nat（priority -160，抢在 PassWall dnsmasq/sing-box 劫持之前将未授权 DNS/HTTP 重定向至门户）
	b.WriteString("  chain prerouting_portal_nat {\n")
	b.WriteString("    type nat hook prerouting priority -160; policy accept;\n")
	b.WriteString(fmt.Sprintf("    iifname != \"%s\" accept\n", lanIface))
	b.WriteString("    ether saddr @whitelist_macs accept\n")
	b.WriteString("    ip saddr @whitelist_ips accept\n")
	b.WriteString("    ether saddr @allowed_macs accept\n")
	b.WriteString(fmt.Sprintf("    udp dport 53 counter redirect to :%d\n", cfg.DNSPort))
	b.WriteString(fmt.Sprintf("    tcp dport 53 counter redirect to :%d\n", cfg.DNSPort))
	b.WriteString(fmt.Sprintf("    tcp dport 80 counter redirect to :%d\n", cfg.PortalPort))
	b.WriteString("  }\n\n")
	ruleCount += 7

	// 链 3：input_guard（阻止未授权设备直连路由器 dnsmasq:53 或 PassWall 本地代理端口）
	b.WriteString("  chain input_guard {\n")
	b.WriteString("    type filter hook input priority -10; policy accept;\n")
	b.WriteString(fmt.Sprintf("    iifname != \"%s\" accept\n", lanIface))
	b.WriteString("    ether saddr @whitelist_macs accept\n")
	b.WriteString("    ip saddr @whitelist_ips accept\n")
	b.WriteString("    ether saddr @allowed_macs accept\n")
	b.WriteString(fmt.Sprintf("    udp dport { 67, 68, %d } counter accept\n", cfg.DNSPort))
	b.WriteString(fmt.Sprintf("    tcp dport %d counter accept\n", cfg.DNSPort))
	b.WriteString(fmt.Sprintf("    tcp dport %d counter accept\n", cfg.PortalPort))
	ruleCount += 7
	if cfg.AllowAdminPorts {
		b.WriteString(fmt.Sprintf("    tcp dport { 22, %d } counter accept\n", cfg.AdminPort))
		ruleCount++
	}
	b.WriteString("    icmp type echo-request counter accept\n")
	b.WriteString("    icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } counter accept\n")
	b.WriteString("    counter drop\n")
	b.WriteString("  }\n\n")
	ruleCount += 3

	// 链 4：forward_guard（纵深防御：彻底禁止未授权 LAN 设备经过路由转发访问任何内外网）
	b.WriteString("  chain forward_guard {\n")
	b.WriteString("    type filter hook forward priority -10; policy accept;\n")
	b.WriteString(fmt.Sprintf("    iifname != \"%s\" accept\n", lanIface))
	b.WriteString("    ether saddr @whitelist_macs accept\n")
	b.WriteString("    ip saddr @whitelist_ips accept\n")
	b.WriteString("    ether saddr @allowed_macs accept\n")
	b.WriteString("    counter drop\n")
	b.WriteString("  }\n")
	b.WriteString("}\n")
	ruleCount += 5

	return b.String(), ruleCount, nil
}

func sanitizeMACList(raw []string) []string {
	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, m := range raw {
		norm, err := model.NormalizeMAC(m)
		if err != nil {
			continue
		}
		lower := strings.ToLower(norm)
		if _, ok := seen[lower]; ok {
			continue
		}
		seen[lower] = struct{}{}
		out = append(out, lower)
	}
	sort.Strings(out)
	return out
}

func sanitizeIPList(raw []string) []string {
	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, s := range raw {
		clean := strings.TrimSpace(s)
		if !model.IsValidIPv4(clean) {
			continue
		}
		if _, ok := seen[clean]; ok {
			continue
		}
		seen[clean] = struct{}{}
		out = append(out, clean)
	}
	sort.Strings(out)
	return out
}
