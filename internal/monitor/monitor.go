package monitor

import (
	"context"
	"gatekeeper/internal/model"
)

// Monitor 定义局域网设备发现、流量采集与路由健康检查接口。
type Monitor interface {
	Start(ctx context.Context)
	Health() model.SystemHealth
	ResolveMACByIP(ip string) string
}
