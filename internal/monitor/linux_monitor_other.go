//go:build !linux

package monitor

import (
	"gatekeeper/internal/firewall"
	"gatekeeper/internal/store"
)

// NewLinuxMonitor 在非 Linux 平台构建时返回仿真监控器。
func NewLinuxMonitor(st *store.Store, fw firewall.Manager, adminPort, portalPort, dnsPort int, onUpdate func()) Monitor {
	return NewMockMonitor(st, fw, adminPort, portalPort, dnsPort, onUpdate)
}
