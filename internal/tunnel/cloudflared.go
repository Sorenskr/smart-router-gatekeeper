package tunnel

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"gatekeeper/internal/model"
	"gatekeeper/internal/store"
)

var tryCloudflareRegex = regexp.MustCompile(`https://[a-zA-Z0-9-]+\.trycloudflare\.com`)

const maxTunnelLogs = 15

// Manager 管理 Cloudflare Tunnel (cloudflared) 的生命周期，强制使用 HTTP/2 + IPv4 绕开国内 QUIC 阻断并支持断线自动重连。
type Manager struct {
	mu           sync.RWMutex
	store        *store.Store
	mockMode     bool
	adminPort    int
	status       model.TunnelStatus
	cancel       context.CancelFunc
	cmd          *exec.Cmd
	doneCh       chan struct{}
	desiredRun   bool
	desiredMode  string
	desiredToken string
	retryCount   int
	onChange     func()
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
			Connected:  false,
			Mode:       "none",
			StatusText: "未启动",
		},
	}
}

// Status 返回当前隧道状态快照。
func (m *Manager) Status() model.TunnelStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cp := m.status
	if len(m.status.RecentLogs) > 0 {
		cp.RecentLogs = make([]string, len(m.status.RecentLogs))
		copy(cp.RecentLogs, m.status.RecentLogs)
	}
	return cp
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

	m.mu.Lock()
	m.desiredRun = true
	m.desiredMode = mode
	m.desiredToken = token
	m.retryCount = 0
	m.mu.Unlock()

	return m.startReal(mode, token)
}

func (m *Manager) startMock(mode string) (model.TunnelStatus, error) {
	now := time.Now()
	var url, text string
	if mode == "quick" {
		suffix := fmt.Sprintf("%04d", now.UnixNano()%10000)
		url = fmt.Sprintf("https://gatekeeper-cloud-%s.trycloudflare.com", suffix)
		text = "[仿真模式] HTTP/2 隧道已连通（真实部署后将生成实时 trycloudflare.com 公网加密网址）"
	} else {
		url = "https://router-admin.example-tunnel.cf"
		text = "[仿真模式] Named Tunnel (Token) HTTP/2 隧道已连通"
	}

	m.mu.Lock()
	m.status = model.TunnelStatus{
		Running:    true,
		Connected:  true,
		Mode:       mode,
		PublicURL:  url,
		StatusText: text,
		RecentLogs: []string{
			fmt.Sprintf("%s INF Protocol set to http2 (edge-ip-version=4)", now.Format("15:04:05")),
			fmt.Sprintf("%s INF Registered tunnel connection connIndex=0 location=sin01", now.Format("15:04:05")),
		},
		StartedAt: &now,
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
		msg := "未找到 cloudflared 组件。请点击下方「一键安装 cloudflared」按钮自动下载，或手动上传至 /usr/bin/cloudflared"
		m.mu.Lock()
		m.desiredRun = false
		m.status = model.TunnelStatus{
			Running:    false,
			Connected:  false,
			Mode:       mode,
			StatusText: "缺少 cloudflared 组件",
			Error:      msg,
		}
		m.mu.Unlock()
		return m.Status(), fmt.Errorf("%s", msg)
	}

	ctx, cancel := context.WithCancel(context.Background())
	// 强制使用 HTTP/2 + IPv4 避开国内运营商及透明代理对 QUIC UDP 7844 端口的阻断
	var args []string
	if mode == "quick" {
		args = []string{
			"tunnel", "--no-autoupdate", "--protocol", "http2", "--edge-ip-version", "4",
			"--url", fmt.Sprintf("http://127.0.0.1:%d", m.adminPort),
		}
	} else {
		args = []string{
			"tunnel", "--no-autoupdate", "--protocol", "http2", "--edge-ip-version", "4",
			"run", "--token", token,
		}
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
	statusText := "正在通过 HTTP/2 建立 Cloudflare 安全隧道..."
	if mode == "token" {
		statusText = "Named Tunnel 正在通过 HTTP/2 连接 Cloudflare 边缘节点..."
	}
	doneCh := make(chan struct{})

	m.mu.Lock()
	m.cancel = cancel
	m.cmd = cmd
	m.doneCh = doneCh
	m.status = model.TunnelStatus{
		Running:    true,
		Connected:  false,
		Mode:       mode,
		StatusText: statusText,
		RecentLogs: []string{fmt.Sprintf("%s 启动 cloudflared (%s, http2, ipv4)", now.Format("15:04:05"), mode)},
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
	go m.waitProcess(ctx, cmd, doneCh)
	return st, nil
}

func (m *Manager) appendLogLocked(line string) {
	cleaned := strings.TrimSpace(line)
	if cleaned == "" {
		return
	}
	if idx := strings.Index(cleaned, "--token"); idx >= 0 {
		cleaned = cleaned[:idx] + "--token [REDACTED]"
	}
	if len(cleaned) > 180 {
		cleaned = cleaned[:180] + "..."
	}
	m.status.RecentLogs = append(m.status.RecentLogs, cleaned)
	if len(m.status.RecentLogs) > maxTunnelLogs {
		m.status.RecentLogs = m.status.RecentLogs[len(m.status.RecentLogs)-maxTunnelLogs:]
	}
}

func (m *Manager) watchOutput(r io.Reader, mode string) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 16*1024), 256*1024)
	for scanner.Scan() {
		line := scanner.Text()
		notify := false
		var auditURL string

		m.mu.Lock()
		m.appendLogLocked(line)
		if match := tryCloudflareRegex.FindString(line); match != "" {
			if m.status.PublicURL != match {
				m.status.PublicURL = match
				if !m.status.Connected {
					m.status.StatusText = "已分配公网域名，正在握手边缘节点..."
				}
				m.status.Error = ""
				auditURL = match
				notify = true
			}
		}
		if strings.Contains(line, "Registered tunnel connection") || strings.Contains(line, "Connection registered") {
			m.retryCount = 0
			if !m.status.Connected {
				m.status.Connected = true
				if mode == "token" {
					m.status.StatusText = "Named Tunnel 已连通（HTTP/2 在线）"
				} else {
					m.status.StatusText = "全球加密 HTTPS 访问已连通（HTTP/2 在线）"
				}
				m.status.Error = ""
				notify = true
			}
		} else if strings.Contains(line, "ERR ") && m.status.Error == "" {
			m.status.Error = line
			notify = true
		}
		m.mu.Unlock()

		if auditURL != "" {
			m.store.AddAuditEvent("tunnel", "公网访问域名已生成", auditURL, "可通过该 HTTPS 地址远程管理软路由")
		}
		if notify && m.onChange != nil {
			m.onChange()
		}
	}
}

func (m *Manager) waitProcess(ctx context.Context, cmd *exec.Cmd, doneCh chan struct{}) {
	defer close(doneCh)
	err := cmd.Wait()

	m.mu.Lock()
	if m.cmd != cmd {
		m.mu.Unlock()
		return
	}
	canceled := ctx.Err() != nil
	shouldRetry := !canceled && m.desiredRun && m.retryCount < 5
	retryIdx := m.retryCount + 1
	retryMode := m.desiredMode
	retryToken := m.desiredToken

	m.cmd = nil
	m.cancel = nil
	m.doneCh = nil
	m.status.Running = false
	m.status.Connected = false
	m.status.PublicURL = ""
	if canceled {
		m.status.Mode = "none"
		m.status.StatusText = "已停止"
		m.status.Error = ""
	} else if shouldRetry {
		m.retryCount = retryIdx
		backoff := time.Duration(3*(1<<(retryIdx-1))) * time.Second
		if backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
		m.status.StatusText = fmt.Sprintf("隧道连接中断，%v 后自动第 %d 次重连...", backoff, retryIdx)
		if err != nil {
			m.status.Error = err.Error()
		}
		go func(wait time.Duration, rMode, rToken string) {
			time.Sleep(wait)
			m.mu.RLock()
			stillWant := m.desiredRun && !m.status.Running
			m.mu.RUnlock()
			if stillWant {
				_, _ = m.startReal(rMode, rToken)
			}
		}(backoff, retryMode, retryToken)
	} else {
		m.desiredRun = false
		m.status.StatusText = "隧道异常退出（请查看下方诊断日志）"
		if err != nil {
			m.status.Error = err.Error()
		}
	}
	m.mu.Unlock()

	if m.onChange != nil {
		m.onChange()
	}
}

// Stop 停止当前运行的 Cloudflare 隧道并等待进程优雅退出。
func (m *Manager) Stop() model.TunnelStatus {
	m.mu.Lock()
	m.desiredRun = false
	cancel := m.cancel
	doneCh := m.doneCh
	wasRunning := m.status.Running
	m.cancel = nil
	m.cmd = nil
	m.doneCh = nil
	m.status = model.TunnelStatus{
		Running:    false,
		Connected:  false,
		Mode:       "none",
		StatusText: "已停止",
	}
	st := m.status
	m.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if doneCh != nil {
		select {
		case <-doneCh:
		case <-time.After(2 * time.Second):
		}
	}
	if wasRunning {
		m.store.AddAuditEvent("tunnel", "停止全球远程访问", "cloudflared", "已关闭外网远程管理隧道")
		if m.onChange != nil {
			m.onChange()
		}
	}
	return st
}

// InstallCloudflared 在软路由上自动安装或修复 cloudflared-linux-arm64 二进制并校验可执行性。
func (m *Manager) InstallCloudflared(ctx context.Context) (string, error) {
	if m.mockMode {
		m.store.AddAuditEvent("tunnel", "[MOCK] 安装 cloudflared", "cloudflared", "仿真环境已内置模拟隧道组件")
		return "仿真环境已内置 cloudflared 组件，可直接开启远程访问", nil
	}
	if runtime.GOOS != "linux" {
		return "", fmt.Errorf("仅软路由 Linux 环境支持自动安装 cloudflared")
	}
	if p, err := exec.LookPath("cloudflared"); err == nil {
		if verOut, vErr := exec.CommandContext(ctx, p, "--version").CombinedOutput(); vErr == nil {
			return fmt.Sprintf("cloudflared 已就绪 (%s)", strings.TrimSpace(string(verOut))), nil
		}
	}

	// 尝试通过软路由包管理器安装
	for _, pkgCmd := range [][]string{{"apk", "add", "cloudflared"}, {"opkg", "install", "cloudflared"}} {
		if _, err := exec.LookPath(pkgCmd[0]); err == nil {
			cCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
			_ = exec.CommandContext(cCtx, pkgCmd[0], pkgCmd[1:]...).Run()
			cancel()
			if p, lErr := exec.LookPath("cloudflared"); lErr == nil {
				if verOut, vErr := exec.CommandContext(ctx, p, "--version").CombinedOutput(); vErr == nil {
					m.store.AddAuditEvent("tunnel", "安装 cloudflared 成功", p, strings.TrimSpace(string(verOut)))
					return fmt.Sprintf("已通过 %s 成功安装: %s", pkgCmd[0], strings.TrimSpace(string(verOut))), nil
				}
			}
		}
	}

	// 回退直连 GitHub Releases 与加速镜像下载官方 arm64 静态包
	archSuffix := "arm64"
	if runtime.GOARCH == "amd64" {
		archSuffix = "amd64"
	}
	officialURL := fmt.Sprintf("https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-%s", archSuffix)
	urls := []string{
		officialURL,
		"https://ghfast.top/" + officialURL,
	}

	tmpBin := "/usr/bin/cloudflared.tmp"
	targetBin := "/usr/bin/cloudflared"
	for _, dlURL := range urls {
		_ = os.Remove(tmpBin)
		dlCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
		var dlErr error
		if _, err := exec.LookPath("curl"); err == nil {
			dlErr = exec.CommandContext(dlCtx, "curl", "-fsSL", "--connect-timeout", "12", "--max-time", "80", "-o", tmpBin, dlURL).Run()
		} else if _, err := exec.LookPath("wget"); err == nil {
			dlErr = exec.CommandContext(dlCtx, "wget", "-T", "15", "-O", tmpBin, dlURL).Run()
		} else {
			cancel()
			return "", fmt.Errorf("软路由未安装 curl 或 wget，无法自动下载 cloudflared")
		}
		cancel()
		if dlErr != nil {
			continue
		}
		if err := os.Chmod(tmpBin, 0o755); err != nil {
			continue
		}
		vCtx, vCancel := context.WithTimeout(ctx, 5*time.Second)
		verOut, vErr := exec.CommandContext(vCtx, tmpBin, "--version").CombinedOutput()
		vCancel()
		if vErr != nil {
			_ = os.Remove(tmpBin)
			continue
		}
		if err := os.Rename(tmpBin, targetBin); err != nil {
			_ = os.Remove(tmpBin)
			return "", fmt.Errorf("保存 cloudflared 至 %s 失败: %w", targetBin, err)
		}
		verStr := strings.TrimSpace(string(verOut))
		m.store.AddAuditEvent("tunnel", "自动下载安装 cloudflared 成功", targetBin, verStr)
		if m.onChange != nil {
			m.onChange()
		}
		return fmt.Sprintf("cloudflared 安装并校验通过 (%s)", verStr), nil
	}

	return "", fmt.Errorf("从官方及镜像源下载 cloudflared 均失败，请确认软路由外网连通性或手动上传至 /usr/bin/cloudflared")
}
