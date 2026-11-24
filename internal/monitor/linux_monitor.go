//go:build linux

package monitor

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"gatekeeper/internal/firewall"
	"gatekeeper/internal/model"
	"gatekeeper/internal/store"
)

type prevCounters struct {
	txBytes uint64
	rxBytes uint64
	ts      time.Time
}

// LinuxMonitor 在 ImmortalWrt 上读取 ARP、DHCP 租约、nf_conntrack、系统负载与网络连通度。
type LinuxMonitor struct {
	mu           sync.RWMutex
	store        *store.Store
	fw           firewall.Manager
	adminPort    int
	portalPort   int
	dnsPort      int
	health       model.SystemHealth
	prevByIP     map[string]prevCounters
	ipToMAC      map[string]string
	onUpdate     func()
	hasCloudflared bool
}

// NewLinuxMonitor 创建真实软路由网络监控器。
func NewLinuxMonitor(st *store.Store, fw firewall.Manager, adminPort, portalPort, dnsPort int, onUpdate func()) *LinuxMonitor {
	settings := st.GetSettings()
	_, cfErr := exec.LookPath("cloudflared")
	return &LinuxMonitor{
		store:          st,
		fw:             fw,
		adminPort:      adminPort,
		portalPort:     portalPort,
		dnsPort:        dnsPort,
		prevByIP:       make(map[string]prevCounters),
		ipToMAC:        make(map[string]string),
		onUpdate:       onUpdate,
		hasCloudflared: cfErr == nil,
		health: model.SystemHealth{
			RouterOnline:         true,
			MockMode:             false,
			RouterIP:             settings.RouterIP,
			LanIface:             settings.LanIface,
			AdminPort:            adminPort,
			PortalPort:           portalPort,
			DNSPort:              dnsPort,
			CloudflaredInstalled: cfErr == nil,
		},
	}
}

func (m *LinuxMonitor) Start(ctx context.Context) {
	m.sampleAll()
	m.probeConnectivity()

	fastTicker := time.NewTicker(2 * time.Second)
	probeTicker := time.NewTicker(10 * time.Second)
	defer fastTicker.Stop()
	defer probeTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-fastTicker.C:
			_ = m.fw.EnsureHealthy()
			m.sampleAll()
			if m.onUpdate != nil {
				m.onUpdate()
			}
		case <-probeTicker.C:
			m.probeConnectivity()
		}
	}
}

func (m *LinuxMonitor) Health() model.SystemHealth {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.health
}

func (m *LinuxMonitor) ResolveMACByIP(ip string) string {
	clean := strings.TrimSpace(ip)
	if clean == "" {
		return ""
	}
	m.mu.RLock()
	mac := m.ipToMAC[clean]
	m.mu.RUnlock()
	if mac != "" {
		return mac
	}
	if mac = m.store.ResolveMACByIP(clean); mac != "" {
		return mac
	}
	// 实时回退读取一次 ARP 表，防止全新设备刚访问门户还未到 2 秒扫描周期
	arp := readARPAndNeigh(m.store.GetSettings().LanIface)
	for _, entry := range arp {
		if entry.ip == clean && entry.mac != "" {
			return entry.mac
		}
	}
	return ""
}

type neighEntry struct {
	ip     string
	mac    string
	online bool
}

func (m *LinuxMonitor) sampleAll() {
	settings := m.store.GetSettings()
	leases := readDHCPLeases("/tmp/dhcp.leases")
	neighs := readARPAndNeigh(settings.LanIface)
	conntrackMap := readConntrackStats()

	now := time.Now()
	byMAC := make(map[string]model.LiveDeviceObservation)
	ip2mac := make(map[string]string)

	for mac, lease := range leases {
		obs := model.LiveDeviceObservation{
			MAC:      mac,
			IP:       lease.ip,
			Hostname: lease.hostname,
			Online:   false,
		}
		byMAC[mac] = obs
		if lease.ip != "" {
			ip2mac[lease.ip] = mac
		}
	}

	for _, n := range neighs {
		obs, exists := byMAC[n.mac]
		if !exists {
			obs = model.LiveDeviceObservation{MAC: n.mac}
		}
		if n.ip != "" {
			obs.IP = n.ip
			ip2mac[n.ip] = n.mac
		}
		if n.online {
			obs.Online = true
		}
		byMAC[n.mac] = obs
	}

	observations := make([]model.LiveDeviceObservation, 0, len(byMAC))
	for _, obs := range byMAC {
		if obs.IP != "" {
			if st, ok := conntrackMap[obs.IP]; ok {
				obs.ActiveConns = st.conns
				obs.TotalRxBytes = st.rxBytes
				obs.TotalTxBytes = st.txBytes
				if st.conns > 0 {
					obs.Online = true
				}
				if prev, pOk := m.prevByIP[obs.IP]; pOk {
					dt := now.Sub(prev.ts).Seconds()
					if dt > 0.2 {
						if st.rxBytes >= prev.rxBytes {
							obs.RxRateBps = uint64(float64(st.rxBytes-prev.rxBytes) / dt)
						}
						if st.txBytes >= prev.txBytes {
							obs.TxRateBps = uint64(float64(st.txBytes-prev.txBytes) / dt)
						}
					}
				}
				m.prevByIP[obs.IP] = prevCounters{
					txBytes: st.txBytes,
					rxBytes: st.rxBytes,
					ts:      now,
				}
			}
		}
		observations = append(observations, obs)
	}

	m.store.SyncObservations(observations)

	nftActive, ctAvail, ruleCount := m.fw.Status()
	uptime, load, memPct := readLinuxSystemMetrics()
	passwall := detectPasswall()

	m.mu.Lock()
	m.ipToMAC = ip2mac
	m.health.RouterOnline = true
	m.health.RouterIP = settings.RouterIP
	m.health.LanIface = settings.LanIface
	m.health.UptimeSec = uptime
	m.health.CPULoad = load
	m.health.MemUsedPercent = memPct
	m.health.PasswallActive = passwall
	m.health.NFTablesActive = nftActive
	m.health.ConntrackAvailable = ctAvail
	m.health.FirewallRulesCount = ruleCount
	_, cfErr := exec.LookPath("cloudflared")
	m.health.CloudflaredInstalled = cfErr == nil
	m.mu.Unlock()
}

func (m *LinuxMonitor) probeConnectivity() {
	domOK, domMs := probeTCP("223.5.5.5:53", 2*time.Second)
	proxyOK, proxyMs := probeHTTP204("https://www.gstatic.com/generate_204", 3*time.Second)

	m.mu.Lock()
	m.health.DomesticReachable = domOK
	m.health.DomesticLatencyMs = domMs
	m.health.ProxyReachable = proxyOK
	m.health.ProxyLatencyMs = proxyMs
	m.mu.Unlock()
}

type leaseInfo struct {
	ip       string
	hostname string
}

func readDHCPLeases(path string) map[string]leaseInfo {
	out := make(map[string]leaseInfo)
	raw, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		mac, err := model.NormalizeMAC(fields[1])
		if err != nil {
			continue
		}
		ip := fields[2]
		host := fields[3]
		if host == "*" {
			host = ""
		}
		out[mac] = leaseInfo{ip: ip, hostname: host}
	}
	return out
}

func readARPAndNeigh(lanIface string) []neighEntry {
	entries := make(map[string]neighEntry)

	if raw, err := os.ReadFile("/proc/net/arp"); err == nil {
		lines := strings.Split(string(raw), "\n")
		for i := 1; i < len(lines); i++ {
			fields := strings.Fields(lines[i])
			if len(fields) < 6 {
				continue
			}
			ip, flags, macRaw, dev := fields[0], fields[2], fields[3], fields[5]
			if lanIface != "" && dev != lanIface {
				continue
			}
			mac, err := model.NormalizeMAC(macRaw)
			if err != nil || mac == "00:00:00:00:00:00" {
				continue
			}
			online := flags != "0x0"
			entries[mac] = neighEntry{ip: ip, mac: mac, online: online}
		}
	}

	args := []string{"neigh", "show"}
	if lanIface != "" {
		args = append(args, "dev", lanIface)
	}
	if out, err := exec.Command("ip", args...).Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			ip := fields[0]
			if !model.IsValidIPv4(ip) {
				continue
			}
			var macRaw, state string
			for idx := 0; idx < len(fields); idx++ {
				if fields[idx] == "lladdr" && idx+1 < len(fields) {
					macRaw = fields[idx+1]
				}
			}
			state = fields[len(fields)-1]
			mac, err := model.NormalizeMAC(macRaw)
			if err != nil || mac == "00:00:00:00:00:00" {
				continue
			}
			online := state == "REACHABLE" || state == "DELAY" || state == "PROBE" || state == "STALE"
			if state == "FAILED" {
				online = false
			}
			prev, ok := entries[mac]
			if !ok {
				entries[mac] = neighEntry{ip: ip, mac: mac, online: online}
			} else {
				prev.ip = ip
				prev.online = prev.online || online
				entries[mac] = prev
			}
		}
	}

	res := make([]neighEntry, 0, len(entries))
	for _, e := range entries {
		res = append(res, e)
	}
	return res
}

type ipConnStats struct {
	conns   int
	txBytes uint64
	rxBytes uint64
}

func readConntrackStats() map[string]ipConnStats {
	out := make(map[string]ipConnStats)
	raw, err := os.ReadFile("/proc/net/nf_conntrack")
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.Contains(line, "ipv4") {
			continue
		}
		fields := strings.Fields(line)
		var origSrc string
		var bytesVals []uint64
		for _, f := range fields {
			if strings.HasPrefix(f, "src=") && origSrc == "" {
				origSrc = strings.TrimPrefix(f, "src=")
			} else if strings.HasPrefix(f, "bytes=") {
				if v, pErr := strconv.ParseUint(strings.TrimPrefix(f, "bytes="), 10, 64); pErr == nil {
					bytesVals = append(bytesVals, v)
				}
			}
		}
		if !model.IsValidIPv4(origSrc) {
			continue
		}
		st := out[origSrc]
		st.conns++
		if len(bytesVals) >= 1 {
			st.txBytes += bytesVals[0]
		}
		if len(bytesVals) >= 2 {
			st.rxBytes += bytesVals[1]
		}
		out[origSrc] = st
	}
	return out
}

func readLinuxSystemMetrics() (int64, string, float64) {
	var uptime int64
	if raw, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(raw))
		if len(fields) > 0 {
			if f, err := strconv.ParseFloat(fields[0], 64); err == nil {
				uptime = int64(f)
			}
		}
	}
	load := "0.00"
	if raw, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(raw))
		if len(fields) >= 3 {
			load = strings.Join(fields[:3], " ")
		}
	}
	var totalKB, availKB float64
	if raw, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			val, _ := strconv.ParseFloat(fields[1], 64)
			switch fields[0] {
			case "MemTotal:":
				totalKB = val
			case "MemAvailable:":
				availKB = val
			}
		}
	}
	memPct := 0.0
	if totalKB > 0 {
		memPct = ((totalKB - availKB) / totalKB) * 100
	}
	return uptime, load, memPct
}

func detectPasswall() bool {
	if _, err := os.Stat("/etc/config/passwall"); err == nil {
		if out, pErr := exec.Command("sh", "-c", "ps w | grep -E 'passwall|sing-box|xray|chinadns' | grep -v grep").Output(); pErr == nil {
			return len(strings.TrimSpace(string(out))) > 0
		}
	}
	return false
}

func probeTCP(addr string, timeout time.Duration) (bool, int64) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false, 0
	}
	_ = conn.Close()
	return true, time.Since(start).Milliseconds()
}

func probeHTTP204(rawURL string, timeout time.Duration) (bool, int64) {
	client := &http.Client{Timeout: timeout}
	start := time.Now()
	resp, err := client.Get(rawURL)
	if err != nil {
		return false, 0
	}
	_ = resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 400, time.Since(start).Milliseconds()
}
