package tunnel

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"gatekeeper/internal/model"
	"gatekeeper/internal/store"
)

var tryCloudflareRegex = regexp.MustCompile(`https://[a-zA-Z0-9-]+\.trycloudflare\.com`)

// Manager 管理 Cloudflare Tunnel (cloudflared) 的生命周期，并在 --mock 模式下提供完整仿真。
type Manager struct {
	mu        sync.RWMutex
	store     *store.Store
	mockMode  bool
	adminPort int
	status    model.TunnelStatus
	cancel    context.CancelFunc
	cmd       *exec.Cmd
	onChange  func()
}

// NewManager 创建 Cloudflare Tunnel 管理器。
func NewManager(st *store.Store, mockMode bool, adminPort int, onChange func()) *Manager {
	return &Manager{
		store:     st,
		mockMode:  mockMode,
		adminPort: adminPort,
		onChange:  onChange,
		status: model.TunnelStatus{
			Running:    false,
			Mode:       "none",
			StatusText: "未启动",
		},
	}
}

// Status 返回当前隧道状态快照。
func (m *Manager) Status() model.TunnelStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status
}

// Start 启动 Quick Tunnel（免域名）或 Named Tunnel（绑定 Token）。
func (m *Manager) Start(mode, token string) (model.TunnelStatus, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "quick"
	}
	if mode != "quick" && mode != "token" {
		return model.TunnelStatus{}, fmt.Errorf("不支持的隧道模式 %q，仅支持 quick 或 token", mode)
	}

	if mode == "token" {
		if strings.TrimSpace(token) != "" {
			if _, err := m.store.UpdateSettings(store.SettingsUpdate{TunnelToken: &token}); err != nil {
				return model.TunnelStatus{}, err
			}
		}
		saved := m.store.GetTunnelToken()
		if saved == "" {
			return model.TunnelStatus{}, fmt.Errorf("请先配置 Cloudflare Tunnel Token 后再启用 Token 模式")
		}
		token = saved
	}

	m.Stop()

	if m.mockMode {
		return m.startMock(mode)
	}
	return m.startReal(mode, token)
}

func (m *Manager) startMock(mode string) (model.TunnelStatus, error) {
	now := time.Now()
	var url, text string
	if mode == "quick" {
		suffix := fmt.Sprintf("%04d", now.UnixNano()%10000)
		url = fmt.Sprintf("https://gatekeeper-cloud-%s.trycloudflare.com", suffix)
		text = "[仿真模式] Quick Tunnel 已连接，实际软路由将生成实时 trycloudflare.com 公网加密地址"
	} else {
		url = "https://router-admin.example-tunnel.cf"
		text = "[仿真模式] Named Tunnel (Token) 已连接，实际软路由将绑定您的 Cloudflare 域名"
	}

	m.mu.Lock()
	m.status = model.TunnelStatus{
		Running:    true,
		Mode:       mode,
		PublicURL:  url,
		StatusText: text,
		StartedAt:  &now,
	}
	st := m.status
	m.mu.Unlock()

	m.store.AddAuditEvent("tunnel", "[MOCK] 启动全球远程访问", mode, fmt.Sprintf("仿真 Cloudflare 隧道已就绪: %s", url))
	if m.onChange != nil {
		m.onChange()
	}
	return st, nil
}

func (m *Manager) startReal(mode, token string) (model.TunnelStatus, error) {
	binPath, err := exec.LookPath("cloudflared")
	if err != nil {
		msg := "未找到 cloudflared 二进制文件。请在软路由执行 opkg/apk 安装或上传 cloudflared-linux-arm64 至 /usr/bin/cloudflared"
		m.mu.Lock()
		m.status = model.TunnelStatus{
			Running:    false,
			Mode:       mode,
			StatusText: "启动失败",
			Error:      msg,
		}
		m.mu.Unlock()
		return m.Status(), fmt.Errorf("%s", msg)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var args []string
	if mode == "quick" {
		args = []string{"tunnel", "--no-autoupdate", "--url", fmt.Sprintf("http://127.0.0.1:%d", m.adminPort)}
	} else {
		args = []string{"tunnel", "--no-autoupdate", "run", "--token", token}
	}

	cmd := exec.CommandContext(ctx, binPath, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return model.TunnelStatus{}, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return model.TunnelStatus{}, err
	}

	if err := cmd.Start(); err != nil {
		cancel()
		return model.TunnelStatus{}, fmt.Errorf("启动 cloudflared 失败: %w", err)
	}

	now := time.Now()
	statusText := "正在建立 Cloudflare 安全隧道..."
	if mode == "token" {
		statusText = "Named Tunnel 正在连接 Cloudflare 边缘节点..."
	}

	m.mu.Lock()
	m.cancel = cancel
	m.cmd = cmd
	m.status = model.TunnelStatus{
		Running:    true,
		Mode:       mode,
		StatusText: statusText,
		StartedAt:  &now,
	}
	st := m.status
	m.mu.Unlock()

	m.store.AddAuditEvent("tunnel", "启动 Cloudflare Tunnel", mode, statusText)
	if m.onChange != nil {
		m.onChange()
	}

	go m.watchOutput(stdout, mode)
	go m.watchOutput(stderr, mode)
	go m.waitProcess(ctx, cmd)
	return st, nil
}

func (m *Manager) watchOutput(r io.Reader, mode string) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if match := tryCloudflareRegex.FindString(line); match != "" {
			m.mu.Lock()
			changed := m.status.PublicURL != match
			m.status.PublicURL = match
			m.status.StatusText = "全球加密 HTTPS 访问已就绪"
			m.status.Error = ""
			m.mu.Unlock()
			if changed {
				m.store.AddAuditEvent("tunnel", "公网访问域名已生成", match, "可通过该 HTTPS 地址从世界任何角落安全管理软路由")
				if m.onChange != nil {
					m.onChange()
				}
			}
		} else if mode == "token" && (strings.Contains(line, "Registered tunnel connection") || strings.Contains(line, "Connection registered")) {
			m.mu.Lock()
			changed := m.status.StatusText != "Named Tunnel 隧道已在线"
			m.status.StatusText = "Named Tunnel 隧道已在线"
			m.status.Error = ""
			m.mu.Unlock()
			if changed && m.onChange != nil {
				m.onChange()
			}
		}
	}
}

func (m *Manager) waitProcess(ctx context.Context, cmd *exec.Cmd) {
	err := cmd.Wait()
	m.mu.Lock()
	if m.cmd != cmd {
		m.mu.Unlock()
		return
	}
	canceled := ctx.Err() != nil
	m.cmd = nil
	m.cancel = nil
	m.status.Running = false
	m.status.PublicURL = ""
	if canceled {
		m.status.Mode = "none"
		m.status.StatusText = "已停止"
		m.status.Error = ""
	} else {
		m.status.StatusText = "隧道异常退出"
		if err != nil {
			m.status.Error = err.Error()
		}
	}
	m.mu.Unlock()

	if m.onChange != nil {
		m.onChange()
	}
}

// Stop 停止当前运行的 Cloudflare 隧道。
func (m *Manager) Stop() model.TunnelStatus {
	m.mu.Lock()
	cancel := m.cancel
	wasRunning := m.status.Running
	m.cancel = nil
	m.cmd = nil
	m.status = model.TunnelStatus{
		Running:    false,
		Mode:       "none",
		StatusText: "已停止",
	}
	st := m.status
	m.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if wasRunning {
		m.store.AddAuditEvent("tunnel", "停止全球远程访问", "cloudflared", "已关闭外网远程管理隧道")
		if m.onChange != nil {
			m.onChange()
		}
	}
	return st
}
