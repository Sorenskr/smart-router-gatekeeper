//go:build !linux

package firewall

import "gatekeeper/internal/store"

// NewLinuxManager 在非 Linux 平台构建时回退到仿真防火墙控制器。
func NewLinuxManager(st *store.Store, adminPort, portalPort, dnsPort int) Manager {
	return NewMockManager(st, adminPort, portalPort, dnsPort)
}
