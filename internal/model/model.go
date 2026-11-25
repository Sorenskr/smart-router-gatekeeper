package model

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

const (
	StatusUnregistered = "unregistered"
	StatusPending      = "pending"
	StatusApproved     = "approved"
	StatusPaused       = "paused"
)

var macHexPattern = regexp.MustCompile(`^[0-9A-Fa-f]{12}$`)

// NormalizeMAC 将各种分隔符的 MAC 地址校验并规范化为大写冒号格式（如 AA:BB:CC:DD:EE:FF）。
func NormalizeMAC(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("MAC 地址不能为空")
	}
	cleaned := strings.NewReplacer(":", "", "-", "", ".", "", " ", "").Replace(s)
	if !macHexPattern.MatchString(cleaned) {
		return "", fmt.Errorf("无效的 MAC 地址格式: %q", raw)
	}
	cleaned = strings.ToUpper(cleaned)
	return fmt.Sprintf("%s:%s:%s:%s:%s:%s",
		cleaned[0:2], cleaned[2:4], cleaned[4:6],
		cleaned[6:8], cleaned[8:10], cleaned[10:12]), nil
}

// IsValidIPv4 判断字符串是否为合法 IPv4 地址。
func IsValidIPv4(raw string) bool {
	ip := net.ParseIP(strings.TrimSpace(raw))
	return ip != nil && ip.To4() != nil
}

// Device 表示局域网内接入过的设备及其生命周期与实时监控指标。
type Device struct {
	MAC               string    `json:"mac"`
	IP                string    `json:"ip"`
	Hostname          string    `json:"hostname"`
	Vendor            string    `json:"vendor"`
	RequestedName     string    `json:"requested_name"`
	AdminRemark       string    `json:"admin_remark"`
	DisplayName       string    `json:"display_name"`
	Status            string    `json:"status"`
	IsWhitelist       bool      `json:"is_whitelist"`
	Online            bool      `json:"online"`
	ApprovedAt        time.Time  `json:"approved_at,omitempty"`
	RequestedAt       time.Time  `json:"requested_at,omitempty"`
	PausedAt          time.Time  `json:"paused_at,omitempty"`
	PauseUntil        *time.Time `json:"pause_until,omitempty"`
	PauseRemainingSec int64      `json:"pause_remaining_sec"`
	AutoResumeError   string     `json:"auto_resume_error,omitempty"`
	FirstSeenAt       time.Time  `json:"first_seen_at"`
	LastSeenAt        time.Time `json:"last_seen_at"`
	RxRateBps         uint64    `json:"rx_rate_bps"`
	TxRateBps         uint64    `json:"tx_rate_bps"`
	TotalRxBytes      uint64    `json:"total_rx_bytes"`
	TotalTxBytes      uint64    `json:"total_tx_bytes"`
	ActiveConns       int       `json:"active_conns"`
	OnlineDurationSec int64     `json:"online_duration_sec"`
}

// ComputeDisplayName 返回用于界面展示的设备首选名称（备注名 > 申请名 > 主机名 > MAC）。
func (d Device) ComputeDisplayName() string {
	if s := strings.TrimSpace(d.AdminRemark); s != "" {
		return s
	}
	if s := strings.TrimSpace(d.RequestedName); s != "" {
		return s
	}
	if s := strings.TrimSpace(d.Hostname); s != "" {
		return s
	}
	return d.MAC
}

// Settings 是持久化到磁盘的系统配置。
type Settings struct {
	MaxConcurrentDevices int    `json:"max_concurrent_devices"`
	GatekeeperEnabled    *bool  `json:"gatekeeper_enabled,omitempty"`
	AdminPasswordHash    string `json:"admin_password_hash"`
	AdminPasswordSalt    string `json:"admin_password_salt"`
	RouterIP             string `json:"router_ip"`
	LanIface             string `json:"lan_iface"`
	PortalTitle          string `json:"portal_title"`
	TunnelToken          string `json:"tunnel_token"`
	AllowAdminPorts      bool   `json:"allow_admin_ports"`
	SoundEnabled         bool   `json:"sound_enabled"`
}

// SettingsView 是脱敏后推送给前端的只读配置视图。
type SettingsView struct {
	MaxConcurrentDevices int    `json:"max_concurrent_devices"`
	GatekeeperEnabled    bool   `json:"gatekeeper_enabled"`
	RouterIP             string `json:"router_ip"`
	LanIface             string `json:"lan_iface"`
	PortalTitle          string `json:"portal_title"`
	HasTunnelToken       bool   `json:"has_tunnel_token"`
	TunnelTokenMasked    string `json:"tunnel_token_masked"`
	AllowAdminPorts      bool   `json:"allow_admin_ports"`
	SoundEnabled         bool   `json:"sound_enabled"`
}

// AuditEvent 记录系统防火墙、连接清理、设备审批与隧道关键事件。
type AuditEvent struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Category  string    `json:"category"`
	Action    string    `json:"action"`
	Target    string    `json:"target,omitempty"`
	Detail    string    `json:"detail"`
}

// TunnelStatus 描述 Cloudflare Tunnel 全球远程访问状态。
type TunnelStatus struct {
	Running    bool       `json:"running"`
	Connected  bool       `json:"connected"`
	Mode       string     `json:"mode"`
	PublicURL  string     `json:"public_url"`
	StatusText string     `json:"status_text"`
	Error      string     `json:"error,omitempty"`
	RecentLogs []string   `json:"recent_logs,omitempty"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
}

// SystemHealth 描述软路由及本机网络健康状态。
type SystemHealth struct {
	RouterOnline         bool    `json:"router_online"`
	MockMode             bool    `json:"mock_mode"`
	RouterIP             string  `json:"router_ip"`
	LanIface             string  `json:"lan_iface"`
	AdminPort            int     `json:"admin_port"`
	PortalPort           int     `json:"portal_port"`
	DNSPort              int     `json:"dns_port"`
	UptimeSec            int64   `json:"uptime_sec"`
	CPULoad              string  `json:"cpu_load"`
	MemUsedPercent       float64 `json:"mem_used_percent"`
	DomesticReachable    bool    `json:"domestic_reachable"`
	DomesticLatencyMs    int64   `json:"domestic_latency_ms"`
	ProxyReachable       bool    `json:"proxy_reachable"`
	ProxyLatencyMs       int64   `json:"proxy_latency_ms"`
	PasswallActive       bool    `json:"passwall_active"`
	NFTablesActive       bool    `json:"nftables_active"`
	ConntrackAvailable   bool    `json:"conntrack_available"`
	CloudflaredInstalled bool    `json:"cloudflared_installed"`
	FirewallRulesCount   int     `json:"firewall_rules_count"`
}

// KPIs 汇总管理大屏顶部核心指标。
type KPIs struct {
	AuthorizedCount       int    `json:"authorized_count"`
	AuthorizedOnlineCount int    `json:"authorized_online_count"`
	MaxConcurrent         int    `json:"max_concurrent"`
	PendingCount          int    `json:"pending_count"`
	BlockedOrPausedCount  int    `json:"blocked_or_paused_count"`
	PausedCount           int    `json:"paused_count"`
	WhitelistCount        int    `json:"whitelist_count"`
	TotalDevices          int    `json:"total_devices"`
	TotalRxRateBps        uint64 `json:"total_rx_rate_bps"`
	TotalTxRateBps        uint64 `json:"total_tx_rate_bps"`
}

// DashboardSnapshot 为管理端全量实时状态快照。
type DashboardSnapshot struct {
	ViewerIP          string       `json:"viewer_ip"`
	ViewerMAC         string       `json:"viewer_mac"`
	ViewerWhitelisted bool         `json:"viewer_whitelisted"`
	KPIs              KPIs         `json:"kpis"`
	Settings          SettingsView `json:"settings"`
	Health            SystemHealth `json:"health"`
	Tunnel            TunnelStatus `json:"tunnel"`
	Devices           []Device     `json:"devices"`
	AuditLogs         []AuditEvent `json:"audit_logs"`
	GeneratedAt       time.Time    `json:"generated_at"`
}

// ConcurrencyConflictError 表示批准/恢复连网时触发最大并发设备数限制。
type ConcurrencyConflictError struct {
	Code          string   `json:"code"`
	Message       string   `json:"message"`
	Current       int      `json:"current"`
	Max           int      `json:"max"`
	OldestDevice  *Device  `json:"oldest_device,omitempty"`
	ActiveDevices []Device `json:"active_devices"`
}

func (e *ConcurrencyConflictError) Error() string {
	return e.Message
}

// PortalStatus 为手机认证页单设备实时状态视图。
type PortalStatus struct {
	MAC               string     `json:"mac"`
	IP                string     `json:"ip"`
	Hostname          string     `json:"hostname"`
	Status            string     `json:"status"`
	GatekeeperEnabled bool       `json:"gatekeeper_enabled"`
	RequestedName     string     `json:"requested_name"`
	AdminRemark       string    `json:"admin_remark"`
	DisplayName       string    `json:"display_name"`
	IsWhitelist       bool      `json:"is_whitelist"`
	Online            bool      `json:"online"`
	PortalTitle       string    `json:"portal_title"`
	MockMode          bool      `json:"mock_mode"`
	ApprovedAt        time.Time  `json:"approved_at,omitempty"`
	RequestedAt       time.Time  `json:"requested_at,omitempty"`
	PauseUntil        *time.Time `json:"pause_until,omitempty"`
	PauseRemainingSec int64      `json:"pause_remaining_sec"`
	OnlineDurationSec int64      `json:"online_duration_sec"`
	Message           string     `json:"message"`
}

// LiveDeviceObservation 描述监控模块探测到的设备实时网卡/ARP/连接跟踪数据。
type LiveDeviceObservation struct {
	MAC          string
	IP           string
	Hostname     string
	Vendor       string
	Online       bool
	RxRateBps    uint64
	TxRateBps    uint64
	TotalRxBytes uint64
	TotalTxBytes uint64
	ActiveConns  int
}
