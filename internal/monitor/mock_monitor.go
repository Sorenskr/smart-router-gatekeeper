package monitor

import (
	"context"
	"math/rand"
	"strings"
	"sync"
	"time"

	"gatekeeper/internal/firewall"
	"gatekeeper/internal/model"
	"gatekeeper/internal/store"
)

// MockMonitor 在本地 Windows 开发仿真模式中生成实时流量波形与软路由健康指标。
type MockMonitor struct {
	mu         sync.RWMutex
	store      *store.Store
	fw         firewall.Manager
	startedAt  time.Time
	adminPort  int
	portalPort int
	dnsPort    int
	health     model.SystemHealth
	onUpdate   func()
	rng        *rand.Rand
}

// NewMockMonitor 创建本地模拟仿真监控器。
func NewMockMonitor(st *store.Store, fw firewall.Manager, adminPort, portalPort, dnsPort int, onUpdate func()) *MockMonitor {
	settings := st.GetSettings()
	return &MockMonitor{
		store:      st,
		fw:         fw,
		startedAt:  time.Now().Add(-3*time.Hour - 18*time.Minute),
		adminPort:  adminPort,
		portalPort: portalPort,
		dnsPort:    dnsPort,
		onUpdate:   onUpdate,
		rng:        rand.New(rand.NewSource(time.Now().UnixNano())),
		health: model.SystemHealth{
			RouterOnline:         true,
			MockMode:             true,
			RouterIP:             settings.RouterIP,
			LanIface:             settings.LanIface,
			AdminPort:            adminPort,
			PortalPort:           portalPort,
			DNSPort:              dnsPort,
			UptimeSec:            3*3600 + 18*60,
			CPULoad:              "0.28 0.31 0.24",
			MemUsedPercent:       34.6,
			DomesticReachable:    true,
			DomesticLatencyMs:    14,
			ProxyReachable:       true,
			ProxyLatencyMs:       68,
			PasswallActive:       true,
			NFTablesActive:       true,
			ConntrackAvailable:   true,
			CloudflaredInstalled: true,
		},
	}
}

func (m *MockMonitor) Start(ctx context.Context) {
	m.tick()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.tick()
			if m.onUpdate != nil {
				m.onUpdate()
			}
		}
	}
}

func (m *MockMonitor) tick() {
	devices := m.store.GetAllDevices()
	observations := make([]model.LiveDeviceObservation, 0, len(devices))

	m.mu.Lock()
	for _, d := range devices {
		obs := model.LiveDeviceObservation{
			MAC:      d.MAC,
			IP:       d.IP,
			Hostname: d.Hostname,
			Vendor:   d.Vendor,
			Online:   d.Online,
		}
		if d.Online && (d.Status == model.StatusApproved || d.IsWhitelist) {
			rx := uint64(45*1024 + m.rng.Intn(850*1024))
			tx := uint64(8*1024 + m.rng.Intn(140*1024))
			if d.IsWhitelist {
				rx = uint64(120*1024 + m.rng.Intn(480*1024))
				tx = uint64(25*1024 + m.rng.Intn(90*1024))
			}
			obs.RxRateBps = rx
			obs.TxRateBps = tx
			obs.TotalRxBytes = d.TotalRxBytes + rx*2
			obs.TotalTxBytes = d.TotalTxBytes + tx*2
			obs.ActiveConns = 6 + m.rng.Intn(26)
		} else {
			obs.RxRateBps = 0
			obs.TxRateBps = 0
			obs.TotalRxBytes = d.TotalRxBytes
			obs.TotalTxBytes = d.TotalTxBytes
			obs.ActiveConns = 0
		}
		observations = append(observations, obs)
	}

	settings := m.store.GetSettings()
	nftActive, ctAvail, ruleCount := m.fw.Status()
	m.health.RouterOnline = true
	m.health.MockMode = true
	m.health.RouterIP = settings.RouterIP
	m.health.LanIface = settings.LanIface
	m.health.UptimeSec = int64(time.Since(m.startedAt).Seconds())
	m.health.DomesticLatencyMs = int64(11 + m.rng.Intn(8))
	m.health.ProxyLatencyMs = int64(60 + m.rng.Intn(19))
	m.health.MemUsedPercent = 33.8 + float64(m.rng.Intn(24))/10.0
	m.health.NFTablesActive = nftActive
	m.health.ConntrackAvailable = ctAvail
	m.health.FirewallRulesCount = ruleCount
	m.mu.Unlock()

	m.store.SyncObservations(observations, false)
}

func (m *MockMonitor) Health() model.SystemHealth {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.health
}

func (m *MockMonitor) ResolveMACByIP(ip string) string {
	return m.store.ResolveMACByIP(strings.TrimSpace(ip))
}
