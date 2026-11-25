package server

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gatekeeper/internal/firewall"
	"gatekeeper/internal/model"
	"gatekeeper/internal/monitor"
	"gatekeeper/internal/store"
	"gatekeeper/internal/tunnel"
	"gatekeeper/internal/ws"
	"gatekeeper/web"
)

const (
	sessionCookieName = "gk_session"
	mockMACCookieName = "gk_mock_mac"
	defaultMockMAC    = "AA:BB:CC:11:22:03"
	loginMaxFailures  = 8
	loginWindow       = 5 * time.Minute
	loginLockDuration = 5 * time.Minute
)

type loginAttempt struct {
	count       int
	windowStart time.Time
	lockedUntil time.Time
}

type loginLimiter struct {
	mu       sync.Mutex
	attempts map[string]*loginAttempt
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{
		attempts: make(map[string]*loginAttempt),
	}
}

func (l *loginLimiter) allow(ip string) (bool, int) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	att, ok := l.attempts[ip]
	if !ok {
		return true, 0
	}
	if now.Before(att.lockedUntil) {
		rem := int(math.Ceil(att.lockedUntil.Sub(now).Seconds()))
		if rem < 1 {
			rem = 1
		}
		return false, rem
	}
	if now.Sub(att.windowStart) > loginWindow {
		delete(l.attempts, ip)
	}
	return true, 0
}

func (l *loginLimiter) recordFailure(ip string) (locked bool, retryAfterSec int) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.attempts) > 256 {
		for k, v := range l.attempts {
			if now.After(v.lockedUntil) && now.Sub(v.windowStart) > 2*loginWindow {
				delete(l.attempts, k)
			}
		}
	}

	att, ok := l.attempts[ip]
	if !ok || now.Sub(att.windowStart) > loginWindow {
		l.attempts[ip] = &loginAttempt{count: 1, windowStart: now}
		return false, 0
	}
	att.count++
	if att.count >= loginMaxFailures {
		att.lockedUntil = now.Add(loginLockDuration)
		return true, int(loginLockDuration.Seconds())
	}
	return false, 0
}

func (l *loginLimiter) reset(ip string) {
	l.mu.Lock()
	delete(l.attempts, ip)
	l.mu.Unlock()
}

// Server 聚合管理大屏 HTTP/WS 路由与 Captive Portal 强制认证页路由。
type Server struct {
	store             *store.Store
	fw                firewall.Manager
	mon               monitor.Monitor
	tunnel            *tunnel.Manager
	hub               *ws.Hub
	mockMode          bool
	adminPort         int
	portalPort        int
	broadcastCh       chan struct{}
	broadcasterActive atomic.Bool
	limiter           *loginLimiter
}

// NewServer 创建服务端实例并订阅状态推送。
func NewServer(st *store.Store, fw firewall.Manager, mon monitor.Monitor, tun *tunnel.Manager, hub *ws.Hub, mockMode bool, adminPort, portalPort int) *Server {
	s := &Server{
		store:       st,
		fw:          fw,
		mon:         mon,
		tunnel:      tun,
		hub:         hub,
		mockMode:    mockMode,
		adminPort:   adminPort,
		portalPort:  portalPort,
		broadcastCh: make(chan struct{}, 1),
		limiter:     newLoginLimiter(),
	}
	st.Subscribe(func() {
		s.BroadcastAll()
	})
	return s
}

// StartScheduler 启动定时断网到期巡检与非阻塞合并广播协程。
func (s *Server) StartScheduler(ctx context.Context) {
	s.broadcasterActive.Store(true)
	go func() {
		defer s.broadcasterActive.Store(false)
		for {
			select {
			case <-ctx.Done():
				return
			case <-s.broadcastCh:
				s.flushBroadcast()
			}
		}
	}()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			resumed, blocked := s.store.ProcessExpiredPauses()
			for _, dev := range resumed {
				_ = s.fw.GrantMAC(dev.MAC)
			}
			if len(resumed) > 0 || len(blocked) > 0 {
				s.BroadcastAll()
			}
		}
	}
}

// BroadcastAll 触发一次异步合并推流（高并发写入不会阻塞 HTTP 响应）。
func (s *Server) BroadcastAll() {
	if !s.broadcasterActive.Load() {
		s.flushBroadcast()
		return
	}
	select {
	case s.broadcastCh <- struct{}{}:
	default:
	}
}

func (s *Server) flushBroadcast() {
	health := s.mon.Health()
	tunStatus := s.tunnel.Status()
	s.hub.BroadcastAdmin(func(viewerIP string) any {
		return s.store.BuildSnapshot(viewerIP, health, tunStatus)
	})
	s.hub.BroadcastPortal(func(mac, ip string) any {
		return s.store.GetPortalStatus(mac, ip)
	})
}

func applySecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

// AdminHandler 返回管理后台端口 (:8088) 的 HTTP 处理器（同时兼容挂载 /portal 便于单端口或本地快速预览）。
func (s *Server) AdminHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		applySecurityHeaders(w)
		path := r.URL.Path
		switch {
		case path == "/" || path == "/index.html":
			serveEmbedded(w, "index.html", "text/html; charset=utf-8")
		case path == "/styles.css":
			serveEmbedded(w, "styles.css", "text/css; charset=utf-8")
		case path == "/dashboard.js":
			serveEmbedded(w, "dashboard.js", "application/javascript; charset=utf-8")
		case path == "/portal" || path == "/portal.html":
			serveEmbedded(w, "portal.html", "text/html; charset=utf-8")
		case path == "/portal.js":
			serveEmbedded(w, "portal.js", "application/javascript; charset=utf-8")
		case path == "/api/portal/status" || path == "/api/portal/apply" || path == "/api/portal/ws" || path == "/api/portal/mock-devices":
			s.handlePortalAPI(w, r)
		case path == "/api/auth/login":
			s.handleLogin(w, r)
		case path == "/api/auth/logout":
			s.handleLogout(w, r)
		case path == "/api/auth/me":
			s.handleMe(w, r)
		case strings.HasPrefix(path, "/api/"):
			s.handleProtectedAdminAPI(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

// PortalHandler 返回 Captive Portal 端口 (:8089) 的 HTTP 处理器，拦截 OS 探针与任意 HTTP 跳转认证页。
func (s *Server) PortalHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		applySecurityHeaders(w)
		path := r.URL.Path
		switch {
		case path == "/portal" || path == "/portal.html":
			serveEmbedded(w, "portal.html", "text/html; charset=utf-8")
		case path == "/portal.js":
			serveEmbedded(w, "portal.js", "application/javascript; charset=utf-8")
		case path == "/styles.css":
			serveEmbedded(w, "styles.css", "text/css; charset=utf-8")
		case strings.HasPrefix(path, "/api/portal/"):
			s.handlePortalAPI(w, r)
		default:
			s.handleCaptiveProbe(w, r)
		}
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "仅支持 POST 请求")
		return
	}
	clientIP := extractViewerLANIP(r)
	if allowed, retrySec := s.limiter.allow(clientIP); !allowed {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", retrySec))
		writeError(w, http.StatusTooManyRequests, fmt.Sprintf("尝试次数过多，请 %d 秒后再试", retrySec))
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求体格式错误")
		return
	}
	if !s.store.VerifyPassword(req.Password) {
		if locked, retrySec := s.limiter.recordFailure(clientIP); locked {
			w.Header().Set("Retry-After", fmt.Sprintf("%d", retrySec))
			writeError(w, http.StatusTooManyRequests, fmt.Sprintf("密码连续错误次数过多，已临时锁定 %d 秒", retrySec))
			return
		}
		writeError(w, http.StatusUnauthorized, "管理密码错误，请重试")
		return
	}
	s.limiter.reset(clientIP)
	token, err := s.store.CreateSession()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "签发会话失败")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isRequestHTTPS(r),
		MaxAge:   86400,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"token": token,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "仅支持 POST 请求")
		return
	}
	if tok := extractSessionToken(r); tok != "" {
		s.store.RevokeSession(tok)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isRequestHTTPS(r),
		MaxAge:   -1,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	authed := s.store.ValidateSession(extractSessionToken(r))
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": authed,
		"mock_mode":     s.mockMode,
	})
}

func (s *Server) handleProtectedAdminAPI(w http.ResponseWriter, r *http.Request) {
	if !s.store.ValidateSession(extractSessionToken(r)) {
		writeError(w, http.StatusUnauthorized, "未登录或会话已过期，请先验证管理员密码")
		return
	}

	path := r.URL.Path
	viewerIP := extractViewerLANIP(r)

	switch {
	case path == "/api/ws":
		client, err := s.hub.RegisterAdmin(w, r, viewerIP)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		snap := s.store.BuildSnapshot(viewerIP, s.mon.Health(), s.tunnel.Status())
		if err := client.SendJSON(map[string]any{"type": "state", "data": snap}); err != nil {
			client.Close()
		}

	case path == "/api/state" && r.Method == http.MethodGet:
		snap := s.store.BuildSnapshot(viewerIP, s.mon.Health(), s.tunnel.Status())
		writeJSON(w, http.StatusOK, snap)

	case path == "/api/settings" && r.Method == http.MethodPut:
		var req store.SettingsUpdate
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "设置参数格式错误")
			return
		}
		updated, err := s.store.UpdateSettings(req)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if req.NewPassword != nil && strings.TrimSpace(*req.NewPassword) != "" {
			s.store.RevokeOtherSessions(extractSessionToken(r))
		}
		if err := s.fw.SyncAll(); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "settings": updated})

	case path == "/api/firewall/script" && r.Method == http.MethodGet:
		_ = s.fw.SyncAll()
		_, _, ruleCount := s.fw.Status()
		writeJSON(w, http.StatusOK, map[string]any{
			"script":      s.fw.CurrentScript(),
			"rules_count": ruleCount,
		})

	case path == "/api/whitelist/current" && r.Method == http.MethodPost:
		mac := s.mon.ResolveMACByIP(viewerIP)
		dev, err := s.store.AddWhitelistByIPOrMAC(mac, viewerIP, "我的管理主机")
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.fw.SyncAll(); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "device": dev})

	case path == "/api/tunnel/start" && r.Method == http.MethodPost:
		var req struct {
			Mode  string `json:"mode"`
			Token string `json:"token"`
		}
		_ = decodeJSON(r, &req)
		st, err := s.tunnel.Start(req.Mode, req.Token)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "tunnel": st})

	case path == "/api/tunnel/stop" && r.Method == http.MethodPost:
		st := s.tunnel.Stop()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "tunnel": st})

	case path == "/api/tunnel/install" && r.Method == http.MethodPost:
		msg, err := s.tunnel.InstallCloudflared(r.Context())
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": msg})

	case path == "/api/mock/simulate-device" && r.Method == http.MethodPost:
		if !s.mockMode {
			writeError(w, http.StatusForbidden, "仅 --mock 仿真模式可用")
			return
		}
		var req struct {
			Name     string `json:"name"`
			MAC      string `json:"mac"`
			IP       string `json:"ip"`
			Hostname string `json:"hostname"`
		}
		_ = decodeJSON(r, &req)
		if strings.TrimSpace(req.MAC) == "" {
			req.MAC = generateMockMAC()
		}
		if strings.TrimSpace(req.IP) == "" {
			req.IP = generateMockIP()
		}
		if strings.TrimSpace(req.Name) == "" {
			req.Name = "新访客手机_" + req.MAC[len(req.MAC)-5:]
		}
		if strings.TrimSpace(req.Hostname) == "" {
			req.Hostname = "Mobile-Guest"
		}
		dev, _, err := s.store.ApplyPortalRequest(req.MAC, req.IP, req.Hostname, req.Name)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "device": dev})

	case path == "/api/mock/reset" && r.Method == http.MethodPost:
		if !s.mockMode {
			writeError(w, http.StatusForbidden, "仅 --mock 仿真模式可用")
			return
		}
		if err := s.store.ResetMockData(); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		_ = s.fw.SyncAll()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})

	case strings.HasPrefix(path, "/api/devices/"):
		s.handleDeviceAction(w, r)

	default:
		writeError(w, http.StatusNotFound, "接口不存在")
	}
}

func (s *Server) handleDeviceAction(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.TrimPrefix(r.URL.Path, "/api/devices/")
	parts := strings.Split(strings.Trim(trimmed, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusBadRequest, "缺少设备 MAC 参数")
		return
	}
	rawMAC, err := url.PathUnescape(parts[0])
	if err != nil {
		rawMAC = parts[0]
	}
	mac, err := model.NormalizeMAC(rawMAC)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if len(parts) == 1 && r.Method == http.MethodDelete {
		dev, _ := s.store.GetDevice(mac)
		if err := s.store.DeleteDevice(mac); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		_ = s.fw.RevokeMAC(mac, dev.IP)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	if len(parts) != 2 {
		writeError(w, http.StatusNotFound, "无效的设备操作路径")
		return
	}

	action := parts[1]
	switch {
	case (action == "approve" || action == "resume") && r.Method == http.MethodPost:
		var req struct {
			ReplaceOldest bool   `json:"replace_oldest"`
			EvictMAC      string `json:"evict_mac"`
		}
		_ = decodeJSON(r, &req)
		dev, evicted, err := s.store.ApproveOrResume(mac, req.ReplaceOldest, req.EvictMAC)
		if err != nil {
			var conflict *model.ConcurrencyConflictError
			if errors.As(err, &conflict) {
				writeJSON(w, http.StatusConflict, conflict)
				return
			}
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if evicted != nil {
			_ = s.fw.RevokeMAC(evicted.MAC, evicted.IP)
		}
		if err := s.fw.GrantMAC(dev.MAC); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"device":  dev,
			"evicted": evicted,
		})

	case action == "pause" && r.Method == http.MethodPost:
		var req struct {
			DurationMinutes float64 `json:"duration_minutes"`
			DurationSeconds float64 `json:"duration_seconds"`
		}
		if err := decodeOptionalJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "定时断网参数格式错误")
			return
		}
		var dur time.Duration
		if req.DurationSeconds > 0 {
			dur = time.Duration(math.Round(req.DurationSeconds)) * time.Second
		} else if req.DurationMinutes > 0 {
			dur = time.Duration(math.Round(req.DurationMinutes*60)) * time.Second
		}
		dev, err := s.store.PauseDevice(mac, dur)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.fw.RevokeMAC(dev.MAC, dev.IP); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "device": dev})

	case action == "remark" && r.Method == http.MethodPut:
		var req struct {
			Remark string `json:"remark"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "备注参数格式错误")
			return
		}
		dev, err := s.store.UpdateRemark(mac, req.Remark)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "device": dev})

	case action == "whitelist" && r.Method == http.MethodPut:
		var req struct {
			IsWhitelist bool `json:"is_whitelist"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "白名单参数格式错误")
			return
		}
		dev, err := s.store.SetWhitelist(mac, req.IsWhitelist)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.fw.SyncAll(); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "device": dev})

	default:
		writeError(w, http.StatusMethodNotAllowed, "不支持的操作或请求方法")
	}
}

func (s *Server) handlePortalAPI(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	mac, ip := s.resolvePortalIdentity(r)

	switch {
	case path == "/api/portal/status" && r.Method == http.MethodGet:
		if s.mockMode && mac != "" {
			http.SetCookie(w, &http.Cookie{
				Name:     mockMACCookieName,
				Value:    mac,
				Path:     "/",
				SameSite: http.SameSiteLaxMode,
				MaxAge:   86400,
			})
		}
		writeJSON(w, http.StatusOK, s.store.GetPortalStatus(mac, ip))

	case path == "/api/portal/apply" && r.Method == http.MethodPost:
		var req struct {
			Name     string `json:"name"`
			MAC      string `json:"mac"`
			IP       string `json:"ip"`
			Hostname string `json:"hostname"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "申请内容格式错误")
			return
		}
		targetMAC := mac
		targetIP := ip
		if s.mockMode {
			if strings.TrimSpace(req.MAC) != "" {
				if norm, err := model.NormalizeMAC(req.MAC); err == nil {
					targetMAC = norm
				}
			}
			if strings.TrimSpace(req.IP) != "" && model.IsValidIPv4(req.IP) {
				targetIP = strings.TrimSpace(req.IP)
			}
		}
		if targetMAC == "" {
			writeError(w, http.StatusBadRequest, "未能识别设备 MAC 地址，请确认设备直连路由 Wi-Fi")
			return
		}
		dev, _, err := s.store.ApplyPortalRequest(targetMAC, targetIP, req.Hostname, req.Name)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if s.mockMode {
			http.SetCookie(w, &http.Cookie{
				Name:     mockMACCookieName,
				Value:    dev.MAC,
				Path:     "/",
				SameSite: http.SameSiteLaxMode,
				MaxAge:   86400,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":     true,
			"portal": s.store.GetPortalStatus(dev.MAC, dev.IP),
		})

	case path == "/api/portal/ws":
		client, err := s.hub.RegisterPortal(w, r, mac, ip)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		status := s.store.GetPortalStatus(mac, ip)
		if err := client.SendJSON(map[string]any{"type": "portal_status", "data": status}); err != nil {
			client.Close()
		}

	case path == "/api/portal/mock-devices" && r.Method == http.MethodGet:
		if !s.mockMode {
			writeJSON(w, http.StatusOK, map[string]any{"mock_mode": false, "devices": []any{}})
			return
		}
		devices := s.store.GetAllDevices()
		writeJSON(w, http.StatusOK, map[string]any{
			"mock_mode": true,
			"devices":   devices,
		})

	default:
		writeError(w, http.StatusNotFound, "门户接口不存在")
	}
}

func (s *Server) handleCaptiveProbe(w http.ResponseWriter, r *http.Request) {
	mac, ip := s.resolvePortalIdentity(r)
	allowed := s.store.IsDeviceAllowed(mac, ip)

	path := r.URL.Path
	if allowed {
		switch path {
		case "/hotspot-detect.html", "/library/test/success.html":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"))
		case "/connecttest.txt":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Microsoft Connect Test"))
		case "/ncsi.txt":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Microsoft NCSI"))
		case "/canonical.html", "/success.txt":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("success"))
		default:
			w.WriteHeader(http.StatusNoContent)
		}
		return
	}

	// 未授权或已断网设备：302 跳转至认证门户并附带状态提示
	target := s.buildPortalRedirectURL(r)
	isPaused := false
	if normMAC, err := model.NormalizeMAC(mac); err == nil {
		if dev, ok := s.store.GetDevice(normMAC); ok && dev.Status == model.StatusPaused && !dev.IsWhitelist {
			isPaused = true
			if strings.Contains(target, "?") {
				target += "&reason=paused"
			} else {
				target += "?reason=paused"
			}
		}
	}
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Location", target)
	w.WriteHeader(http.StatusFound)
	if isPaused {
		_, _ = w.Write([]byte("<!DOCTYPE html><html><head><meta charset='utf-8'><title>软路由已断网</title></head><body><h3>软路由已断网</h3><p>当前设备的连接已被管理员暂停，请查看 <a href=\"" + target + "\">状态提示页面</a></p></body></html>"))
	} else {
		_, _ = w.Write([]byte("<!DOCTYPE html><html><head><meta charset='utf-8'><title>Wi-Fi 认证</title></head><body>正在跳转至 <a href=\"" + target + "\">认证页面</a>...</body></html>"))
	}
}

func (s *Server) buildPortalRedirectURL(r *http.Request) string {
	settings := s.store.GetSettings()
	host := r.Host
	// 本地仿真调试通过 127.0.0.1 / localhost 访问时，保留本地地址方便测试与预览
	if s.mockMode && (strings.HasPrefix(host, "127.0.0.1") || strings.HasPrefix(host, "localhost")) {
		return fmt.Sprintf("http://%s/portal", host)
	}
	return fmt.Sprintf("http://%s:%d/portal", settings.RouterIP, s.portalPort)
}

func (s *Server) resolvePortalIdentity(r *http.Request) (string, string) {
	ip := extractRemoteIP(r)
	if s.mockMode {
		if q := strings.TrimSpace(r.URL.Query().Get("mac")); q != "" {
			if norm, err := model.NormalizeMAC(q); err == nil {
				if dev, ok := s.store.GetDevice(norm); ok && dev.IP != "" {
					return norm, dev.IP
				}
				return norm, "192.168.6.188"
			}
		}
		if h := strings.TrimSpace(r.Header.Get("X-Mock-MAC")); h != "" {
			if norm, err := model.NormalizeMAC(h); err == nil {
				if dev, ok := s.store.GetDevice(norm); ok && dev.IP != "" {
					return norm, dev.IP
				}
				return norm, "192.168.6.188"
			}
		}
		if c, err := r.Cookie(mockMACCookieName); err == nil {
			if norm, nErr := model.NormalizeMAC(c.Value); nErr == nil {
				if dev, ok := s.store.GetDevice(norm); ok && dev.IP != "" {
					return norm, dev.IP
				}
				return norm, "192.168.6.188"
			}
		}
		if ip == "127.0.0.1" || ip == "::1" || ip == "" {
			if dev, ok := s.store.GetDevice(defaultMockMAC); ok {
				return dev.MAC, dev.IP
			}
			return defaultMockMAC, "192.168.6.103"
		}
	}

	mac := s.mon.ResolveMACByIP(ip)
	return mac, ip
}

func serveEmbedded(w http.ResponseWriter, filename, contentType string) {
	data, err := fs.ReadFile(web.Assets, filename)
	if err != nil {
		http.Error(w, "静态资源加载失败", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func decodeOptionalJSON(r *http.Request, dst any) error {
	if r.Body == nil {
		return nil
	}
	defer r.Body.Close()
	raw, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, 1<<20))
	if err != nil {
		return err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil
	}
	return json.Unmarshal(raw, dst)
}

func decodeJSON(r *http.Request, dst any) error {
	if r.Body == nil {
		return fmt.Errorf("空请求体")
	}
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	return dec.Decode(dst)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{
		"ok":    false,
		"error": msg,
	})
}

func extractSessionToken(r *http.Request) string {
	if c, err := r.Cookie(sessionCookieName); err == nil && strings.TrimSpace(c.Value) != "" {
		return strings.TrimSpace(c.Value)
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	if q := strings.TrimSpace(r.URL.Query().Get("token")); q != "" {
		return q
	}
	return ""
}

func extractRemoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}

func extractViewerLANIP(r *http.Request) string {
	remote := extractRemoteIP(r)
	if remote == "::1" {
		return "127.0.0.1"
	}
	if remote == "127.0.0.1" {
		if cfIP := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cfIP != "" {
			return cfIP
		}
	}
	return remote
}

func isRequestHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		return true
	}
	return strings.Contains(strings.ToLower(r.Header.Get("Cf-Visitor")), "\"https\"")
}

func generateMockMAC() string {
	var b [3]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("AA:BB:CC:%02X:%02X:%02X", b[0], b[1], b[2])
}

func generateMockIP() string {
	var b [1]byte
	_, _ = rand.Read(b[:])
	last := 120 + int(b[0])%110
	return fmt.Sprintf("192.168.6.%d", last)
}
