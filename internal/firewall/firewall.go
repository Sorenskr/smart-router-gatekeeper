package firewall

// Manager 定义跨平台防火墙与存量连接清理接口。
type Manager interface {
	SyncAll() error
	GrantMAC(mac string) error
	RevokeMAC(mac string, ips ...string) error
	EnsureHealthy() error
	KillConntrack(ips ...string) error
	CurrentScript() string
	Status() (nftActive bool, conntrackAvailable bool, ruleCount int)
	Cleanup() error
}
