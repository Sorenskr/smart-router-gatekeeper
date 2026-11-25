package store

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"gatekeeper/internal/model"
)

const (
	sessionTTL  = 24 * time.Hour
	maxAuditLog = 120
)

type persistedState struct {
	Version    int                     `json:"version"`
	Settings   model.Settings          `json:"settings"`
	Devices    map[string]model.Device `json:"devices"`
	AuditLogs  []model.AuditEvent      `json:"audit_logs"`
	NextLogID  int64                   `json:"next_log_id"`
	UpdatedAt  time.Time               `json:"updated_at"`
}

// Store 管理设备、系统设置、会话认证与原子化持久化状态。
type Store struct {
	mu           sync.RWMutex
	filePath     string
	mockMode     bool
	state        persistedState
	sessions     map[string]time.Time
	pinnedAdminIPs []string
	listeners    []func()
}

// NewStore 初始化或从磁盘恢复状态仓库。
func NewStore(dataDir string, mockMode bool, defaultPassword, routerIP, lanIface, adminIP, adminMAC string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("创建数据目录失败: %w", err)
	}
	if strings.TrimSpace(routerIP) == "" {
		routerIP = "192.168.6.1"
	}
	if strings.TrimSpace(lanIface) == "" {
		lanIface = "br-lan"
	}
	if strings.TrimSpace(defaultPassword) == "" {
		defaultPassword = "admin123"
	}

	defaultEnabled := true
	s := &Store{
		filePath: filepath.Join(dataDir, "state.json"),
		mockMode: mockMode,
		sessions: make(map[string]time.Time),
		state: persistedState{
			Version: 1,
			Settings: model.Settings{
				MaxConcurrentDevices: 2,
				GatekeeperEnabled:    &defaultEnabled,
				RouterIP:             routerIP,
				LanIface:             lanIface,
				PortalTitle:          "智慧网络准入认证",
				AllowAdminPorts:      true,
				SoundEnabled:         true,
			},
			Devices:   make(map[string]model.Device),
			AuditLogs: make([]model.AuditEvent, 0, 32),
			NextLogID: 1,
		},
	}

	if adminIP != "" && model.IsValidIPv4(adminIP) {
		s.pinnedAdminIPs = append(s.pinnedAdminIPs, adminIP)
	}

	loaded, err := s.loadFromDisk()
	if err != nil {
		return nil, err
	}

	// 若尚未存在持久化的密码哈希，写入初始密码哈希；已存在时保留用户配置。
	if s.state.Settings.AdminPasswordHash == "" || s.state.Settings.AdminPasswordSalt == "" {
		if err := s.setPasswordLocked(defaultPassword); err != nil {
			return nil, err
		}
	}
	if s.state.Settings.MaxConcurrentDevices <= 0 {
		s.state.Settings.MaxConcurrentDevices = 2
	}
	if s.state.Settings.GatekeeperEnabled == nil {
		enabled := true
		s.state.Settings.GatekeeperEnabled = &enabled
	}
	if strings.TrimSpace(s.state.Settings.RouterIP) == "" {
		s.state.Settings.RouterIP = routerIP
	}
	if strings.TrimSpace(s.state.Settings.LanIface) == "" {
		s.state.Settings.LanIface = lanIface
	}
	if strings.TrimSpace(s.state.Settings.PortalTitle) == "" {
		s.state.Settings.PortalTitle = "智慧网络准入认证"
	}

	if mockMode && (!loaded || len(s.state.Devices) == 0) {
		s.seedMockDevicesLocked()
		s.addAuditLocked("system", "初始化仿真环境", "MOCK", "已生成 5 台仿真测试设备（含白名单管理机、已连网手机、待审批新机及已暂停设备）")
	}

	if adminMAC != "" {
		if normMAC, mErr := model.NormalizeMAC(adminMAC); mErr == nil {
			s.ensurePinnedAdminMACLocked(normMAC, adminIP)
		}
	}

	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) loadFromDisk() (bool, error) {
	raw, err := os.ReadFile(s.filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("读取状态文件失败: %w", err)
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return false, nil
	}
	var disk persistedState
	if err := json.Unmarshal(raw, &disk); err != nil {
		return false, fmt.Errorf("解析状态文件失败: %w", err)
	}
	if disk.Devices == nil {
		disk.Devices = make(map[string]model.Device)
	}
	normalized := make(map[string]model.Device, len(disk.Devices))
	for k, d := range disk.Devices {
		normMAC, nErr := model.NormalizeMAC(d.MAC)
		if nErr != nil {
			normMAC, nErr = model.NormalizeMAC(k)
		}
		if nErr != nil {
			continue
		}
		d.MAC = normMAC
		d.DisplayName = d.ComputeDisplayName()
		normalized[normMAC] = d
	}
	disk.Devices = normalized
	if disk.NextLogID <= 0 {
		disk.NextLogID = int64(len(disk.AuditLogs) + 1)
	}
	s.state = disk
	return true, nil
}

func (s *Store) saveLocked() error {
	s.state.UpdatedAt = time.Now()
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化状态失败: %w", err)
	}
	tmpPath := s.filePath + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("创建临时状态文件失败: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("写入临时状态文件失败: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("同步临时状态文件失败: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("关闭临时状态文件失败: %w", err)
	}
	var renameErr error
	for i := 0; i < 3; i++ {
		if renameErr = os.Rename(tmpPath, s.filePath); renameErr == nil {
			return nil
		}
		time.Sleep(15 * time.Millisecond)
	}
	return fmt.Errorf("原子替换状态文件失败: %w", renameErr)
}

func (s *Store) ensurePinnedAdminMACLocked(mac, ip string) {
	now := time.Now()
	dev, ok := s.state.Devices[mac]
	if !ok {
		dev = model.Device{
			MAC:         mac,
			IP:          ip,
			Hostname:    "Admin-Host",
			AdminRemark: "管理主机（启动参数防锁死）",
			Status:      model.StatusApproved,
			IsWhitelist: true,
			Online:      true,
			ApprovedAt:  now,
			FirstSeenAt: now,
			LastSeenAt:  now,
		}
	} else {
		if ip != "" {
			dev.IP = ip
		}
		dev.Status = model.StatusApproved
		dev.IsWhitelist = true
		if dev.ApprovedAt.IsZero() {
			dev.ApprovedAt = now
		}
	}
	dev.DisplayName = dev.ComputeDisplayName()
	s.state.Devices[mac] = dev
}

func (s *Store) seedMockDevicesLocked() {
	now := time.Now()
	ipadPauseUntil := now.Add(25 * time.Minute)
	seeds := []model.Device{
		{
			MAC:          "00:1A:2B:3C:4D:01",
			IP:           "192.168.6.10",
			Hostname:     "MacBook-Pro-Admin",
			Vendor:       "Apple Inc.",
			AdminRemark:  "我的主力管理电脑",
			Status:       model.StatusApproved,
			IsWhitelist:  true,
			Online:       true,
			ApprovedAt:   now.Add(-26 * time.Hour),
			FirstSeenAt:  now.Add(-26 * time.Hour),
			LastSeenAt:   now,
			TotalRxBytes: 482 * 1024 * 1024,
			TotalTxBytes: 96 * 1024 * 1024,
			ActiveConns:  18,
		},
		{
			MAC:           "AA:BB:CC:11:22:01",
			IP:            "192.168.6.101",
			Hostname:      "iPhone-16-Pro",
			Vendor:        "Apple Inc.",
			RequestedName: "测试机_小王",
			AdminRemark:   "小王的手机",
			Status:        model.StatusApproved,
			Online:        true,
			ApprovedAt:    now.Add(-125 * time.Minute),
			RequestedAt:   now.Add(-126 * time.Minute),
			FirstSeenAt:   now.Add(-126 * time.Minute),
			LastSeenAt:    now,
			TotalRxBytes:  156 * 1024 * 1024,
			TotalTxBytes:  28 * 1024 * 1024,
			ActiveConns:   24,
		},
		{
			MAC:           "AA:BB:CC:11:22:02",
			IP:            "192.168.6.102",
			Hostname:      "Xiaomi-15-Ultra",
			Vendor:        "Xiaomi Communications",
			RequestedName: "测试机_小红",
			Status:        model.StatusApproved,
			Online:        true,
			ApprovedAt:    now.Add(-28 * time.Minute),
			RequestedAt:   now.Add(-29 * time.Minute),
			FirstSeenAt:   now.Add(-29 * time.Minute),
			LastSeenAt:    now,
			TotalRxBytes:  89 * 1024 * 1024,
			TotalTxBytes:  14 * 1024 * 1024,
			ActiveConns:   15,
		},
		{
			MAC:           "AA:BB:CC:11:22:03",
			IP:            "192.168.6.103",
			Hostname:      "Galaxy-S24",
			Vendor:        "Samsung Electronics",
			RequestedName: "新手机_小李",
			Status:        model.StatusPending,
			Online:        true,
			RequestedAt:   now.Add(-45 * time.Second),
			FirstSeenAt:   now.Add(-1 * time.Minute),
			LastSeenAt:    now,
		},
		{
			MAC:           "AA:BB:CC:11:22:04",
			IP:            "192.168.6.104",
			Hostname:      "iPad-Air",
			Vendor:        "Apple Inc.",
			RequestedName: "备用平板_老张",
			AdminRemark:   "客厅平板",
			Status:        model.StatusPaused,
			Online:        true,
			ApprovedAt:    now.Add(-2 * time.Hour),
			RequestedAt:   now.Add(-2 * time.Hour),
			PausedAt:      now.Add(-5 * time.Minute),
			PauseUntil:    &ipadPauseUntil,
			FirstSeenAt:   now.Add(-3 * time.Hour),
			LastSeenAt:    now,
			TotalRxBytes:  310 * 1024 * 1024,
			TotalTxBytes:  35 * 1024 * 1024,
		},
	}
	s.state.Devices = make(map[string]model.Device, len(seeds))
	for _, d := range seeds {
		d.DisplayName = d.ComputeDisplayName()
		s.state.Devices[d.MAC] = d
	}
}

// ResetMockData 将演示设备恢复至初始 5 台模拟机状态（保留系统设置与密码）。
func (s *Store) ResetMockData() error {
	s.mu.Lock()
	if !s.mockMode {
		s.mu.Unlock()
		return fmt.Errorf("仅仿真模式支持重置演示数据")
	}
	s.seedMockDevicesLocked()
	s.state.Settings.MaxConcurrentDevices = 2
	s.addAuditLocked("system", "重置演示设备", "MOCK", "已重置为 5 台默认仿真测试设备，最大并发上限恢复为 2")
	err := s.saveLocked()
	s.mu.Unlock()
	if err == nil {
		s.notifyListeners()
	}
	return err
}

// Subscribe 注册状态变更回调。
func (s *Store) Subscribe(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listeners = append(s.listeners, fn)
}

func (s *Store) notifyListeners() {
	s.mu.RLock()
	callbacks := make([]func(), len(s.listeners))
	copy(callbacks, s.listeners)
	s.mu.RUnlock()
	for _, cb := range callbacks {
		cb()
	}
}

func (s *Store) setPasswordLocked(plain string) error {
	saltBytes := make([]byte, 16)
	if _, err := rand.Read(saltBytes); err != nil {
		return fmt.Errorf("生成盐值失败: %w", err)
	}
	salt := hex.EncodeToString(saltBytes)
	hash := hashPassword(salt, plain)
	s.state.Settings.AdminPasswordSalt = salt
	s.state.Settings.AdminPasswordHash = hash
	return nil
}

func hashPassword(salt, plain string) string {
	sum := sha256.Sum256([]byte(salt + ":" + plain))
	return hex.EncodeToString(sum[:])
}

// VerifyPassword 校验管理员密码（常量时间比较）。
func (s *Store) VerifyPassword(plain string) bool {
	s.mu.RLock()
	salt := s.state.Settings.AdminPasswordSalt
	expected := s.state.Settings.AdminPasswordHash
	s.mu.RUnlock()
	if salt == "" || expected == "" {
		return false
	}
	actual := hashPassword(salt, plain)
	return subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) == 1
}

// CreateSession 签发新的管理员会话 Token。
func (s *Store) CreateSession() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	token := hex.EncodeToString(buf)
	s.mu.Lock()
	now := time.Now()
	for k, exp := range s.sessions {
		if now.After(exp) {
			delete(s.sessions, k)
		}
	}
	s.sessions[token] = now.Add(sessionTTL)
	s.mu.Unlock()
	return token, nil
}

// ValidateSession 校验会话 Token 是否有效。
func (s *Store) ValidateSession(token string) bool {
	if strings.TrimSpace(token) == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.sessions[token]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(s.sessions, token)
		return false
	}
	s.sessions[token] = time.Now().Add(sessionTTL)
	return true
}

// RevokeSession 销毁指定会话 Token。
func (s *Store) RevokeSession(token string) {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

// RevokeOtherSessions 在修改管理员密码等敏感操作后，立即吊销除 keepToken 外的全部旧会话。
func (s *Store) RevokeOtherSessions(keepToken string) {
	s.mu.Lock()
	for tok := range s.sessions {
		if tok != keepToken {
			delete(s.sessions, tok)
		}
	}
	s.mu.Unlock()
}

func (s *Store) addAuditLocked(category, action, target, detail string) {
	evt := model.AuditEvent{
		ID:        s.state.NextLogID,
		Timestamp: time.Now(),
		Category:  category,
		Action:    action,
		Target:    target,
		Detail:    detail,
	}
	s.state.NextLogID++
	s.state.AuditLogs = append([]model.AuditEvent{evt}, s.state.AuditLogs...)
	if len(s.state.AuditLogs) > maxAuditLog {
		s.state.AuditLogs = s.state.AuditLogs[:maxAuditLog]
	}
}

// AddAuditEvent 记录一条外部组件（如防火墙/隧道）触发的审计日志。
func (s *Store) AddAuditEvent(category, action, target, detail string) {
	s.mu.Lock()
	s.addAuditLocked(category, action, target, detail)
	_ = s.saveLocked()
	s.mu.Unlock()
	s.notifyListeners()
}

// ApplyPortalRequest 处理手机在认证页提交使用者姓名/设备代号的接入申请。
func (s *Store) ApplyPortalRequest(mac, ip, hostname, requestedName string) (model.Device, bool, error) {
	normMAC, err := model.NormalizeMAC(mac)
	if err != nil {
		return model.Device{}, false, err
	}
	name := strings.TrimSpace(requestedName)
	if name == "" {
		return model.Device{}, false, fmt.Errorf("请输入使用者姓名或设备专属代号")
	}
	if len([]rune(name)) > 36 {
		return model.Device{}, false, fmt.Errorf("名称长度请控制在 36 个字符以内")
	}

	now := time.Now()
	s.mu.Lock()
	dev, exists := s.state.Devices[normMAC]
	if !exists {
		dev = model.Device{
			MAC:         normMAC,
			IP:          strings.TrimSpace(ip),
			Hostname:    strings.TrimSpace(hostname),
			Status:      model.StatusPending,
			Online:      true,
			FirstSeenAt: now,
			LastSeenAt:  now,
		}
	} else {
		if strings.TrimSpace(ip) != "" {
			dev.IP = strings.TrimSpace(ip)
		}
		if strings.TrimSpace(hostname) != "" {
			dev.Hostname = strings.TrimSpace(hostname)
		}
		dev.Online = true
		dev.LastSeenAt = now
	}

	if dev.Status == model.StatusPaused && !dev.IsWhitelist {
		s.mu.Unlock()
		return dev, false, fmt.Errorf("您的连接已被管理员暂停，请联系管理员开启")
	}

	newlyPending := false
	if dev.Status == model.StatusApproved || dev.IsWhitelist {
		dev.Status = model.StatusApproved
		if dev.RequestedName == "" {
			dev.RequestedName = name
		}
	} else {
		if dev.Status != model.StatusPending || dev.RequestedName != name {
			newlyPending = true
		}
		dev.Status = model.StatusPending
		dev.RequestedName = name
		dev.RequestedAt = now
	}
	dev.DisplayName = dev.ComputeDisplayName()
	s.state.Devices[normMAC] = dev

	if newlyPending {
		s.addAuditLocked("auth", "新设备提交接入申请", normMAC, fmt.Sprintf("代号「%s」(%s) 提交联网申请，等待审批", name, dev.IP))
	}
	if err := s.saveLocked(); err != nil {
		s.mu.Unlock()
		return model.Device{}, false, err
	}
	s.mu.Unlock()

	s.notifyListeners()
	return dev, newlyPending, nil
}

// SyncObservations 在发现新局域网设备时注册为 unregistered，更新在线观察指标；真实路由模式下自动将超时消失设备置为离线。
func (s *Store) SyncObservations(obs []model.LiveDeviceObservation, markMissingOffline bool) bool {
	now := time.Now()
	obsMap := make(map[string]model.LiveDeviceObservation, len(obs))
	for _, o := range obs {
		normMAC, err := model.NormalizeMAC(o.MAC)
		if err != nil {
			continue
		}
		o.MAC = normMAC
		obsMap[normMAC] = o
	}

	s.mu.Lock()
	changed := false
	for mac, o := range obsMap {
		dev, ok := s.state.Devices[mac]
		if !ok {
			dev = model.Device{
				MAC:          mac,
				IP:           o.IP,
				Hostname:     o.Hostname,
				Vendor:       o.Vendor,
				Status:       model.StatusUnregistered,
				Online:       o.Online,
				FirstSeenAt:  now,
				LastSeenAt:   now,
				RxRateBps:    o.RxRateBps,
				TxRateBps:    o.TxRateBps,
				TotalRxBytes: o.TotalRxBytes,
				TotalTxBytes: o.TotalTxBytes,
				ActiveConns:  o.ActiveConns,
			}
			dev.DisplayName = dev.ComputeDisplayName()
			s.state.Devices[mac] = dev
			changed = true
			continue
		}
		if o.IP != "" && dev.IP != o.IP {
			dev.IP = o.IP
			changed = true
		}
		if o.Hostname != "" && dev.Hostname != o.Hostname {
			dev.Hostname = o.Hostname
			changed = true
		}
		if o.Vendor != "" && dev.Vendor == "" {
			dev.Vendor = o.Vendor
		}
		if dev.Online != o.Online {
			dev.Online = o.Online
			changed = true
		}
		if o.Online {
			dev.LastSeenAt = now
		}
		// 仅对已授权或白名单设备展示活跃速率和连接数
		if dev.Status == model.StatusApproved || dev.IsWhitelist {
			dev.RxRateBps = o.RxRateBps
			dev.TxRateBps = o.TxRateBps
			if o.TotalRxBytes > dev.TotalRxBytes {
				dev.TotalRxBytes = o.TotalRxBytes
			}
			if o.TotalTxBytes > dev.TotalTxBytes {
				dev.TotalTxBytes = o.TotalTxBytes
			}
			dev.ActiveConns = o.ActiveConns
		} else {
			dev.RxRateBps = 0
			dev.TxRateBps = 0
			dev.ActiveConns = 0
		}
		dev.DisplayName = dev.ComputeDisplayName()
		s.state.Devices[mac] = dev
	}

	if markMissingOffline {
		for mac, dev := range s.state.Devices {
			if _, seen := obsMap[mac]; seen {
				continue
			}
			if dev.Online && now.Sub(dev.LastSeenAt) > 30*time.Second {
				dev.Online = false
				dev.RxRateBps = 0
				dev.TxRateBps = 0
				dev.ActiveConns = 0
				s.state.Devices[mac] = dev
				changed = true
			}
		}
	}

	// 仅在有新设备或在线状态发生变化时落盘，避免每 2 秒无意义写 Flash。
	if changed {
		_ = s.saveLocked()
	}
	s.mu.Unlock()
	return changed
}

// ApproveOrResume 批准或恢复设备连网，严格校验最大并发设备上限并支持一键顶替。
func (s *Store) ApproveOrResume(mac string, replaceOldest bool, evictMAC string) (model.Device, *model.Device, error) {
	normMAC, err := model.NormalizeMAC(mac)
	if err != nil {
		return model.Device{}, nil, err
	}
	var normEvict string
	if strings.TrimSpace(evictMAC) != "" {
		normEvict, err = model.NormalizeMAC(evictMAC)
		if err != nil {
			return model.Device{}, nil, fmt.Errorf("指定的顶替设备 MAC 无效: %w", err)
		}
	}

	s.mu.Lock()
	dev, ok := s.state.Devices[normMAC]
	if !ok {
		s.mu.Unlock()
		return model.Device{}, nil, fmt.Errorf("未找到设备: %s", normMAC)
	}

	if dev.Status == model.StatusApproved {
		dev.DisplayName = dev.ComputeDisplayName()
		s.mu.Unlock()
		return dev, nil, nil
	}

	var evicted *model.Device
	if !dev.IsWhitelist {
		active := make([]model.Device, 0)
		for _, d := range s.state.Devices {
			if d.Status == model.StatusApproved && !d.IsWhitelist && d.MAC != normMAC {
				d.DisplayName = d.ComputeDisplayName()
				d.OnlineDurationSec = computeOnlineDuration(d, time.Now())
				active = append(active, d)
			}
		}
		sort.Slice(active, func(i, j int) bool {
			ti, tj := active[i].ApprovedAt, active[j].ApprovedAt
			if ti.IsZero() {
				ti = active[i].FirstSeenAt
			}
			if tj.IsZero() {
				tj = active[j].FirstSeenAt
			}
			if !ti.Equal(tj) {
				return ti.Before(tj)
			}
			return active[i].MAC < active[j].MAC
		})

		maxConc := s.state.Settings.MaxConcurrentDevices
		if len(active) >= maxConc {
			if normEvict != "" {
				foundIdx := -1
				for idx, a := range active {
					if a.MAC == normEvict {
						foundIdx = idx
						break
					}
				}
				if foundIdx < 0 {
					s.mu.Unlock()
					return model.Device{}, nil, fmt.Errorf("指定的设备 %s 当前未在占用并发配额", normEvict)
				}
				target := active[foundIdx]
				target.Status = model.StatusPaused
				target.PausedAt = time.Now()
				target.PauseUntil = nil
				target.PauseRemainingSec = 0
				target.AutoResumeError = ""
				target.RxRateBps = 0
				target.TxRateBps = 0
				target.ActiveConns = 0
				target.DisplayName = target.ComputeDisplayName()
				s.state.Devices[target.MAC] = target
				evicted = &target
			} else if replaceOldest && len(active) > 0 {
				oldest := active[0]
				oldest.Status = model.StatusPaused
				oldest.PausedAt = time.Now()
				oldest.PauseUntil = nil
				oldest.PauseRemainingSec = 0
				oldest.AutoResumeError = ""
				oldest.RxRateBps = 0
				oldest.TxRateBps = 0
				oldest.ActiveConns = 0
				oldest.DisplayName = oldest.ComputeDisplayName()
				s.state.Devices[oldest.MAC] = oldest
				evicted = &oldest
			} else {
				var oldestPtr *model.Device
				if len(active) > 0 {
					c := active[0]
					oldestPtr = &c
				}
				s.mu.Unlock()
				return model.Device{}, nil, &model.ConcurrencyConflictError{
					Code:          "CONCURRENCY_LIMIT_REACHED",
					Message:       fmt.Sprintf("当前已达上限（%d/%d），请先将某台在线设备下线，或点此一键顶替最早接入的设备", len(active), maxConc),
					Current:       len(active),
					Max:           maxConc,
					OldestDevice:  oldestPtr,
					ActiveDevices: active,
				}
			}
		}
	}

	wasPaused := dev.Status == model.StatusPaused
	now := time.Now()
	dev.Status = model.StatusApproved
	dev.ApprovedAt = now
	dev.PausedAt = time.Time{}
	dev.PauseUntil = nil
	dev.PauseRemainingSec = 0
	dev.AutoResumeError = ""
	dev.DisplayName = dev.ComputeDisplayName()
	s.state.Devices[normMAC] = dev

	if evicted != nil {
		s.addAuditLocked("auth", "并发上限顶替下线", evicted.MAC, fmt.Sprintf("顶替最早接入设备「%s」(%s)，放行「%s」", evicted.ComputeDisplayName(), evicted.IP, dev.DisplayName))
	}
	actionText := "批准连网"
	if wasPaused {
		actionText = "恢复连网"
	}
	s.addAuditLocked("auth", actionText, normMAC, fmt.Sprintf("已放行设备「%s」(%s)", dev.DisplayName, dev.IP))

	if err := s.saveLocked(); err != nil {
		s.mu.Unlock()
		return model.Device{}, nil, err
	}
	s.mu.Unlock()

	s.notifyListeners()
	return dev, evicted, nil
}

// PauseDevice 断网挂起指定设备（duration > 0 为定时断网，到期自动恢复；duration == 0 为手动永久断网）。
func (s *Store) PauseDevice(mac string, duration time.Duration) (model.Device, error) {
	normMAC, err := model.NormalizeMAC(mac)
	if err != nil {
		return model.Device{}, err
	}
	if duration < 0 {
		return model.Device{}, fmt.Errorf("断网时长不能为负数")
	}
	if duration > 30*24*time.Hour {
		return model.Device{}, fmt.Errorf("单次定时断网时长不能超过 30 天")
	}

	now := time.Now()
	s.mu.Lock()
	dev, ok := s.state.Devices[normMAC]
	if !ok {
		s.mu.Unlock()
		return model.Device{}, fmt.Errorf("未找到设备: %s", normMAC)
	}
	if dev.IsWhitelist {
		s.mu.Unlock()
		return model.Device{}, fmt.Errorf("设备 %s 处于永久白名单保护中，禁止直接断网（防止误锁）", dev.ComputeDisplayName())
	}
	dev.Status = model.StatusPaused
	dev.PausedAt = now
	dev.AutoResumeError = ""
	dev.RxRateBps = 0
	dev.TxRateBps = 0
	dev.ActiveConns = 0
	if duration > 0 {
		until := now.Add(duration)
		dev.PauseUntil = &until
		dev.PauseRemainingSec = int64(math.Ceil(duration.Seconds()))
	} else {
		dev.PauseUntil = nil
		dev.PauseRemainingSec = 0
	}
	dev.DisplayName = dev.ComputeDisplayName()
	s.state.Devices[normMAC] = dev

	if duration > 0 {
		s.addAuditLocked("auth", "定时断网挂起", normMAC,
			fmt.Sprintf("已切断「%s」(%s) 网络，将在 %s (%s) 自动恢复", dev.DisplayName, dev.IP, formatDurationZh(duration), dev.PauseUntil.Format("15:04:05")))
	} else {
		s.addAuditLocked("auth", "一键断网挂起", normMAC,
			fmt.Sprintf("已切断「%s」(%s) 所有网络权限并保留绑定记录", dev.DisplayName, dev.IP))
	}
	if err := s.saveLocked(); err != nil {
		s.mu.Unlock()
		return model.Device{}, err
	}
	s.mu.Unlock()

	s.notifyListeners()
	return dev, nil
}

// ProcessExpiredPauses 扫描并自动恢复到期的定时断网设备（受最大并发上限约束）。
func (s *Store) ProcessExpiredPauses() (resumed []model.Device, blocked []model.Device) {
	now := time.Now()
	s.mu.Lock()

	var due []model.Device
	activeCount := 0
	for _, d := range s.state.Devices {
		if d.Status == model.StatusApproved && !d.IsWhitelist {
			activeCount++
		}
		if d.Status == model.StatusPaused && d.PauseUntil != nil && !now.Before(*d.PauseUntil) {
			due = append(due, d)
		}
	}
	if len(due) == 0 {
		s.mu.Unlock()
		return nil, nil
	}

	sort.Slice(due, func(i, j int) bool {
		if !due[i].PauseUntil.Equal(*due[j].PauseUntil) {
			return due[i].PauseUntil.Before(*due[j].PauseUntil)
		}
		return due[i].MAC < due[j].MAC
	})

	maxConc := s.state.Settings.MaxConcurrentDevices
	for _, d := range due {
		if d.IsWhitelist || activeCount < maxConc {
			d.Status = model.StatusApproved
			d.ApprovedAt = now
			d.PausedAt = time.Time{}
			d.PauseUntil = nil
			d.PauseRemainingSec = 0
			d.AutoResumeError = ""
			d.DisplayName = d.ComputeDisplayName()
			s.state.Devices[d.MAC] = d
			if !d.IsWhitelist {
				activeCount++
			}
			s.addAuditLocked("auth", "定时断网到期自动恢复", d.MAC,
				fmt.Sprintf("设备「%s」(%s) 定时断网已到期，已自动恢复放行", d.DisplayName, d.IP))
			resumed = append(resumed, d)
		} else {
			d.PauseUntil = nil
			d.PauseRemainingSec = 0
			d.AutoResumeError = fmt.Sprintf("定时断网已到期，但并发连接已满（%d/%d），请手动恢复", activeCount, maxConc)
			d.DisplayName = d.ComputeDisplayName()
			s.state.Devices[d.MAC] = d
			s.addAuditLocked("auth", "定时到期恢复受限", d.MAC,
				fmt.Sprintf("设备「%s」定时到期但并发已满（%d/%d），已保留暂停状态", d.DisplayName, activeCount, maxConc))
			blocked = append(blocked, d)
		}
	}

	_ = s.saveLocked()
	s.mu.Unlock()
	s.notifyListeners()
	return resumed, blocked
}

func formatDurationZh(d time.Duration) string {
	sec := int64(math.Round(d.Seconds()))
	if sec < 60 {
		return fmt.Sprintf("%d秒", sec)
	}
	if sec < 3600 && sec%60 == 0 {
		return fmt.Sprintf("%d分钟", sec/60)
	}
	if sec%3600 == 0 {
		return fmt.Sprintf("%d小时", sec/3600)
	}
	mins := sec / 60
	if mins >= 60 {
		return fmt.Sprintf("%d小时%d分钟", mins/60, mins%60)
	}
	return fmt.Sprintf("%d分%d秒", mins, sec%60)
}

// UpdateRemark 更新管理员对设备的二次备注名并持久化。
func (s *Store) UpdateRemark(mac, remark string) (model.Device, error) {
	normMAC, err := model.NormalizeMAC(mac)
	if err != nil {
		return model.Device{}, err
	}
	cleaned := strings.TrimSpace(remark)
	if len([]rune(cleaned)) > 40 {
		return model.Device{}, fmt.Errorf("备注名长度不能超过 40 个字符")
	}

	s.mu.Lock()
	dev, ok := s.state.Devices[normMAC]
	if !ok {
		s.mu.Unlock()
		return model.Device{}, fmt.Errorf("未找到设备: %s", normMAC)
	}
	oldName := dev.ComputeDisplayName()
	dev.AdminRemark = cleaned
	dev.DisplayName = dev.ComputeDisplayName()
	s.state.Devices[normMAC] = dev
	s.addAuditLocked("system", "修改设备备注", normMAC, fmt.Sprintf("「%s」备注更新为「%s」", oldName, dev.DisplayName))
	if err := s.saveLocked(); err != nil {
		s.mu.Unlock()
		return model.Device{}, err
	}
	s.mu.Unlock()

	s.notifyListeners()
	return dev, nil
}

// SetWhitelist 设置或取消设备的永久白名单保护（设为白名单时自动放行且不占并发配额）。
func (s *Store) SetWhitelist(mac string, enabled bool) (model.Device, error) {
	normMAC, err := model.NormalizeMAC(mac)
	if err != nil {
		return model.Device{}, err
	}

	s.mu.Lock()
	dev, ok := s.state.Devices[normMAC]
	if !ok {
		s.mu.Unlock()
		return model.Device{}, fmt.Errorf("未找到设备: %s", normMAC)
	}
	dev.IsWhitelist = enabled
	if enabled {
		dev.Status = model.StatusApproved
		if dev.ApprovedAt.IsZero() {
			dev.ApprovedAt = time.Now()
		}
		s.addAuditLocked("auth", "设为永久白名单", normMAC, fmt.Sprintf("设备「%s」(%s) 已加入永久免审白名单（不占并发配额）", dev.ComputeDisplayName(), dev.IP))
	} else {
		s.addAuditLocked("auth", "移出白名单", normMAC, fmt.Sprintf("设备「%s」已移出永久白名单", dev.ComputeDisplayName()))
	}
	dev.DisplayName = dev.ComputeDisplayName()
	s.state.Devices[normMAC] = dev
	if err := s.saveLocked(); err != nil {
		s.mu.Unlock()
		return model.Device{}, err
	}
	s.mu.Unlock()

	s.notifyListeners()
	return dev, nil
}

// AddWhitelistByIPOrMAC 将当前访问管理端的控制机快速加入永久白名单。
func (s *Store) AddWhitelistByIPOrMAC(mac, ip, remark string) (model.Device, error) {
	now := time.Now()
	if strings.TrimSpace(mac) != "" {
		normMAC, err := model.NormalizeMAC(mac)
		if err != nil {
			return model.Device{}, err
		}
		s.mu.Lock()
		dev, ok := s.state.Devices[normMAC]
		if !ok {
			dev = model.Device{
				MAC:         normMAC,
				IP:          strings.TrimSpace(ip),
				Hostname:    "Admin-Workstation",
				AdminRemark: strings.TrimSpace(remark),
				Status:      model.StatusApproved,
				IsWhitelist: true,
				Online:      true,
				ApprovedAt:  now,
				FirstSeenAt: now,
				LastSeenAt:  now,
			}
		} else {
			dev.IsWhitelist = true
			dev.Status = model.StatusApproved
			if dev.ApprovedAt.IsZero() {
				dev.ApprovedAt = now
			}
			if dev.AdminRemark == "" && strings.TrimSpace(remark) != "" {
				dev.AdminRemark = strings.TrimSpace(remark)
			}
		}
		dev.DisplayName = dev.ComputeDisplayName()
		s.state.Devices[normMAC] = dev
		s.addAuditLocked("auth", "保护管理主机", normMAC, fmt.Sprintf("已将当前控制机「%s」(%s) 加入永久白名单", dev.DisplayName, dev.IP))
		if err := s.saveLocked(); err != nil {
			s.mu.Unlock()
			return model.Device{}, err
		}
		s.mu.Unlock()
		s.notifyListeners()
		return dev, nil
	}
	if model.IsValidIPv4(ip) {
		s.mu.Lock()
		exists := false
		for _, pinned := range s.pinnedAdminIPs {
			if pinned == ip {
				exists = true
				break
			}
		}
		if !exists {
			s.pinnedAdminIPs = append(s.pinnedAdminIPs, ip)
		}
		s.addAuditLocked("auth", "保护管理主机 IP", ip, fmt.Sprintf("已将来源 IP %s 加入临时内核白名单防误锁", ip))
		_ = s.saveLocked()
		s.mu.Unlock()
		s.notifyListeners()
		return model.Device{IP: ip, IsWhitelist: true, Status: model.StatusApproved}, nil
	}
	return model.Device{}, fmt.Errorf("无法识别当前管理主机 MAC 或 IPv4 地址")
}

// DeleteDevice 删除一条非白名单设备记录。
func (s *Store) DeleteDevice(mac string) error {
	normMAC, err := model.NormalizeMAC(mac)
	if err != nil {
		return err
	}
	s.mu.Lock()
	dev, ok := s.state.Devices[normMAC]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("未找到设备: %s", normMAC)
	}
	if dev.IsWhitelist {
		s.mu.Unlock()
		return fmt.Errorf("白名单受保护设备不能直接删除，请先取消白名单")
	}
	delete(s.state.Devices, normMAC)
	s.addAuditLocked("system", "移除设备记录", normMAC, fmt.Sprintf("已删除设备「%s」记录", dev.ComputeDisplayName()))
	if err := s.saveLocked(); err != nil {
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()

	s.notifyListeners()
	return nil
}

// SettingsUpdate 描述可修改的系统配置字段。
type SettingsUpdate struct {
	MaxConcurrentDevices *int    `json:"max_concurrent_devices,omitempty"`
	GatekeeperEnabled    *bool   `json:"gatekeeper_enabled,omitempty"`
	PortalTitle          *string `json:"portal_title,omitempty"`
	TunnelToken          *string `json:"tunnel_token,omitempty"`
	SoundEnabled         *bool   `json:"sound_enabled,omitempty"`
	AllowAdminPorts      *bool   `json:"allow_admin_ports,omitempty"`
	NewPassword          *string `json:"new_password,omitempty"`
}

// UpdateSettings 修改系统设置并原子持久化。
func (s *Store) UpdateSettings(u SettingsUpdate) (model.SettingsView, error) {
	s.mu.Lock()
	if u.GatekeeperEnabled != nil {
		old := s.isGatekeeperEnabledLocked()
		v := *u.GatekeeperEnabled
		s.state.Settings.GatekeeperEnabled = &v
		if old != v {
			if v {
				s.addAuditLocked("system", "开启准入认证总开关", "GLOBAL", "已恢复设备准入审批、并发上限锁与断网拦截规则")
			} else {
				s.addAuditLocked("system", "关闭准入认证总开关", "GLOBAL", "已切换为全网自由直通模式：所有设备免填昵称直接上网")
			}
		}
	}
	if u.MaxConcurrentDevices != nil {
		if *u.MaxConcurrentDevices < 1 || *u.MaxConcurrentDevices > 256 {
			s.mu.Unlock()
			return model.SettingsView{}, fmt.Errorf("最大同时连接数必须在 1 至 256 之间")
		}
		old := s.state.Settings.MaxConcurrentDevices
		s.state.Settings.MaxConcurrentDevices = *u.MaxConcurrentDevices
		if old != *u.MaxConcurrentDevices {
			s.addAuditLocked("system", "调整并发上限", fmt.Sprintf("%d -> %d", old, *u.MaxConcurrentDevices),
				fmt.Sprintf("最大同时在线授权设备数调整为 %d 台", *u.MaxConcurrentDevices))
		}
	}
	if u.PortalTitle != nil {
		title := strings.TrimSpace(*u.PortalTitle)
		if title != "" {
			s.state.Settings.PortalTitle = title
		}
	}
	if u.TunnelToken != nil {
		s.state.Settings.TunnelToken = strings.TrimSpace(*u.TunnelToken)
	}
	if u.SoundEnabled != nil {
		s.state.Settings.SoundEnabled = *u.SoundEnabled
	}
	if u.AllowAdminPorts != nil {
		s.state.Settings.AllowAdminPorts = *u.AllowAdminPorts
	}
	if u.NewPassword != nil && strings.TrimSpace(*u.NewPassword) != "" {
		if len(strings.TrimSpace(*u.NewPassword)) < 4 {
			s.mu.Unlock()
			return model.SettingsView{}, fmt.Errorf("新管理密码至少需要 4 个字符")
		}
		if err := s.setPasswordLocked(strings.TrimSpace(*u.NewPassword)); err != nil {
			s.mu.Unlock()
			return model.SettingsView{}, err
		}
		s.addAuditLocked("system", "修改管理密码", "ADMIN", "管理员登录密码已更新")
	}
	if err := s.saveLocked(); err != nil {
		s.mu.Unlock()
		return model.SettingsView{}, err
	}
	view := s.settingsViewLocked()
	s.mu.Unlock()

	s.notifyListeners()
	return view, nil
}

func (s *Store) isGatekeeperEnabledLocked() bool {
	if s.state.Settings.GatekeeperEnabled == nil {
		return true
	}
	return *s.state.Settings.GatekeeperEnabled
}

// IsGatekeeperEnabled 返回准入认证总开关当前是否开启。
func (s *Store) IsGatekeeperEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.isGatekeeperEnabledLocked()
}

func (s *Store) settingsViewLocked() model.SettingsView {
	tok := s.state.Settings.TunnelToken
	masked := ""
	if tok != "" {
		if len(tok) <= 10 {
			masked = "****"
		} else {
			masked = tok[:4] + "****" + tok[len(tok)-4:]
		}
	}
	return model.SettingsView{
		MaxConcurrentDevices: s.state.Settings.MaxConcurrentDevices,
		GatekeeperEnabled:    s.isGatekeeperEnabledLocked(),
		RouterIP:             s.state.Settings.RouterIP,
		LanIface:             s.state.Settings.LanIface,
		PortalTitle:          s.state.Settings.PortalTitle,
		HasTunnelToken:       tok != "",
		TunnelTokenMasked:    masked,
		AllowAdminPorts:      s.state.Settings.AllowAdminPorts,
		SoundEnabled:         s.state.Settings.SoundEnabled,
	}
}

// GetTunnelToken 返回内部存储的完整 Cloudflare Tunnel Token（用于启动隧道进程）。
func (s *Store) GetTunnelToken() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.Settings.TunnelToken
}

// GetSettings 获取只读脱敏设置。
func (s *Store) GetSettings() model.SettingsView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.settingsViewLocked()
}

// GetFirewallSets 返回用于生成 nftables 规则的白名单 MAC、白名单 IP 与授权 MAC 集合。
func (s *Store) GetFirewallSets() (whitelistMACs, whitelistIPs, allowedMACs []string, routerIP, lanIface string, allowAdminPorts bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	routerIP = s.state.Settings.RouterIP
	lanIface = s.state.Settings.LanIface
	allowAdminPorts = s.state.Settings.AllowAdminPorts

	ipSet := map[string]struct{}{
		"127.0.0.1": {},
	}
	if model.IsValidIPv4(routerIP) {
		ipSet[routerIP] = struct{}{}
	}
	for _, p := range s.pinnedAdminIPs {
		if model.IsValidIPv4(p) {
			ipSet[p] = struct{}{}
		}
	}

	for _, d := range s.state.Devices {
		if d.IsWhitelist {
			whitelistMACs = append(whitelistMACs, d.MAC)
			if model.IsValidIPv4(d.IP) {
				ipSet[d.IP] = struct{}{}
			}
		} else if d.Status == model.StatusApproved {
			allowedMACs = append(allowedMACs, d.MAC)
		}
	}
	for ip := range ipSet {
		whitelistIPs = append(whitelistIPs, ip)
	}
	sort.Strings(whitelistMACs)
	sort.Strings(whitelistIPs)
	sort.Strings(allowedMACs)
	return
}

// ResolveMACByIP 根据局域网 IP 反查已知设备 MAC。
func (s *Store) ResolveMACByIP(ip string) string {
	clean := strings.TrimSpace(ip)
	if clean == "" {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, d := range s.state.Devices {
		if d.IP == clean {
			return d.MAC
		}
	}
	return ""
}

// GetDevice 返回单个设备副本。
func (s *Store) GetDevice(mac string) (model.Device, bool) {
	normMAC, err := model.NormalizeMAC(mac)
	if err != nil {
		return model.Device{}, false
	}
	now := time.Now()
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.state.Devices[normMAC]
	if !ok {
		return model.Device{}, false
	}
	d.DisplayName = d.ComputeDisplayName()
	d.OnlineDurationSec = computeOnlineDuration(d, now)
	d.PauseRemainingSec = computePauseRemainingSec(d, now)
	return d, true
}

// GetDevicesSnapshot 返回排序后的全部设备及各已知 IP/MAC 列表。
func (s *Store) GetAllDevices() []model.Device {
	now := time.Now()
	s.mu.RLock()
	list := make([]model.Device, 0, len(s.state.Devices))
	for _, d := range s.state.Devices {
		d.DisplayName = d.ComputeDisplayName()
		d.OnlineDurationSec = computeOnlineDuration(d, now)
		d.PauseRemainingSec = computePauseRemainingSec(d, now)
		list = append(list, d)
	}
	s.mu.RUnlock()
	sortDevices(list)
	return list
}

// GetPortalStatus 构建指定设备在手机认证页所需的单机视图。
func (s *Store) GetPortalStatus(mac, ip string) model.PortalStatus {
	now := time.Now()
	normMAC, err := model.NormalizeMAC(mac)
	s.mu.RLock()
	defer s.mu.RUnlock()

	portalTitle := s.state.Settings.PortalTitle
	gkEnabled := s.isGatekeeperEnabledLocked()
	if err != nil {
		msg := "未识别到设备 MAC，请在下方填写姓名/代号提交接入申请"
		if !gkEnabled {
			msg = "准入管控已关闭，当前为自由直通模式，无需填写昵称即可上网"
		}
		return model.PortalStatus{
			IP:                ip,
			Status:            model.StatusUnregistered,
			GatekeeperEnabled: gkEnabled,
			PortalTitle:       portalTitle,
			MockMode:          s.mockMode,
			Message:           msg,
		}
	}

	dev, ok := s.state.Devices[normMAC]
	if !ok {
		msg := "请输入使用者姓名或设备专属代号以申请联网"
		if !gkEnabled {
			msg = "准入管控已关闭，当前为自由直通模式，无需填写昵称即可上网"
		}
		return model.PortalStatus{
			MAC:               normMAC,
			IP:                ip,
			DisplayName:       normMAC,
			Status:            model.StatusUnregistered,
			GatekeeperEnabled: gkEnabled,
			PortalTitle:       portalTitle,
			MockMode:          s.mockMode,
			Online:            true,
			Message:           msg,
		}
	}

	pauseRem := computePauseRemainingSec(dev, now)
	msg := "请输入使用者姓名或设备专属代号以申请联网"
	switch {
	case !gkEnabled:
		msg = "准入管控已关闭，当前为自由直通模式，无需填写昵称即可上网"
	case dev.IsWhitelist || dev.Status == model.StatusApproved:
		msg = "已授权联网，全速网络权限已放行"
	case dev.Status == model.StatusPending:
		msg = "等待管理员审批中..."
	case dev.Status == model.StatusPaused:
		if pauseRem > 0 {
			msg = fmt.Sprintf("软路由已断网，预计 %s 后自动恢复", formatDurationZh(time.Duration(pauseRem)*time.Second))
		} else {
			msg = "软路由已断网，请联系管理员恢复联网"
		}
	}

	displayIP := dev.IP
	if displayIP == "" {
		displayIP = ip
	}
	return model.PortalStatus{
		MAC:               dev.MAC,
		IP:                displayIP,
		Hostname:          dev.Hostname,
		Status:            dev.Status,
		GatekeeperEnabled: gkEnabled,
		RequestedName:     dev.RequestedName,
		AdminRemark:       dev.AdminRemark,
		DisplayName:       dev.ComputeDisplayName(),
		IsWhitelist:       dev.IsWhitelist,
		Online:            dev.Online,
		PortalTitle:       portalTitle,
		MockMode:          s.mockMode,
		ApprovedAt:        dev.ApprovedAt,
		RequestedAt:       dev.RequestedAt,
		PauseUntil:        dev.PauseUntil,
		PauseRemainingSec: pauseRem,
		OnlineDurationSec: computeOnlineDuration(dev, now),
		Message:           msg,
	}
}

// IsDeviceAllowed 判断给定 MAC 或 IP 是否已被放行（若总开关关闭则放行全部设备）。
func (s *Store) IsDeviceAllowed(mac, ip string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.isGatekeeperEnabledLocked() {
		return true
	}
	for _, pinned := range s.pinnedAdminIPs {
		if pinned == ip {
			return true
		}
	}
	if normMAC, err := model.NormalizeMAC(mac); err == nil {
		if d, ok := s.state.Devices[normMAC]; ok {
			return d.IsWhitelist || d.Status == model.StatusApproved
		}
	}
	for _, d := range s.state.Devices {
		if d.IP == ip && (d.IsWhitelist || d.Status == model.StatusApproved) {
			return true
		}
	}
	return false
}

// IsIPWhitelisted 判断控制端来源 IP 是否已处于白名单保护中。
func (s *Store) IsIPWhitelisted(ip string) (bool, string) {
	clean := strings.TrimSpace(ip)
	if clean == "" {
		return false, ""
	}
	if clean == "127.0.0.1" || clean == "::1" {
		// 本地环回调试访问，尝试匹配第一台白名单管理机或标记本地受保护
		s.mu.RLock()
		defer s.mu.RUnlock()
		for _, d := range s.state.Devices {
			if d.IsWhitelist {
				return true, d.MAC
			}
		}
		return true, ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, pinned := range s.pinnedAdminIPs {
		if pinned == clean {
			return true, ""
		}
	}
	for _, d := range s.state.Devices {
		if d.IP == clean {
			return d.IsWhitelist, d.MAC
		}
	}
	return false, ""
}

// BuildSnapshot 构建推送给管理大屏的完整实时快照。
func (s *Store) BuildSnapshot(viewerIP string, health model.SystemHealth, tunnel model.TunnelStatus) model.DashboardSnapshot {
	now := time.Now()
	s.mu.RLock()
	devices := make([]model.Device, 0, len(s.state.Devices))
	var kpis model.KPIs
	kpis.MaxConcurrent = s.state.Settings.MaxConcurrentDevices

	var viewerMAC string
	var viewerWhitelisted bool
	for _, pinned := range s.pinnedAdminIPs {
		if pinned == viewerIP {
			viewerWhitelisted = true
			break
		}
	}

	for _, d := range s.state.Devices {
		d.DisplayName = d.ComputeDisplayName()
		d.OnlineDurationSec = computeOnlineDuration(d, now)
		d.PauseRemainingSec = computePauseRemainingSec(d, now)
		devices = append(devices, d)

		if d.IP == viewerIP {
			viewerMAC = d.MAC
			if d.IsWhitelist {
				viewerWhitelisted = true
			}
		}

		kpis.TotalDevices++
		if d.IsWhitelist {
			kpis.WhitelistCount++
			kpis.TotalRxRateBps += d.RxRateBps
			kpis.TotalTxRateBps += d.TxRateBps
			continue
		}
		switch d.Status {
		case model.StatusApproved:
			kpis.AuthorizedCount++
			if d.Online {
				kpis.AuthorizedOnlineCount++
			}
			kpis.TotalRxRateBps += d.RxRateBps
			kpis.TotalTxRateBps += d.TxRateBps
		case model.StatusPending:
			kpis.PendingCount++
		case model.StatusPaused:
			kpis.PausedCount++
			kpis.BlockedOrPausedCount++
		case model.StatusUnregistered:
			kpis.BlockedOrPausedCount++
		}
	}

	if viewerIP == "127.0.0.1" || viewerIP == "::1" {
		viewerWhitelisted = true
	}

	logs := make([]model.AuditEvent, len(s.state.AuditLogs))
	copy(logs, s.state.AuditLogs)
	settingsView := s.settingsViewLocked()
	s.mu.RUnlock()

	sortDevices(devices)
	if len(logs) > 50 {
		logs = logs[:50]
	}

	return model.DashboardSnapshot{
		ViewerIP:          viewerIP,
		ViewerMAC:         viewerMAC,
		ViewerWhitelisted: viewerWhitelisted,
		KPIs:              kpis,
		Settings:          settingsView,
		Health:            health,
		Tunnel:            tunnel,
		Devices:           devices,
		AuditLogs:         logs,
		GeneratedAt:       now,
	}
}

func computePauseRemainingSec(d model.Device, now time.Time) int64 {
	if d.Status != model.StatusPaused || d.PauseUntil == nil {
		return 0
	}
	rem := d.PauseUntil.Sub(now)
	if rem <= 0 {
		return 0
	}
	return int64(math.Ceil(rem.Seconds()))
}

func computeOnlineDuration(d model.Device, now time.Time) int64 {
	if !d.Online || (d.Status != model.StatusApproved && !d.IsWhitelist) {
		return 0
	}
	start := d.ApprovedAt
	if start.IsZero() {
		start = d.FirstSeenAt
	}
	if start.IsZero() || now.Before(start) {
		return 0
	}
	return int64(now.Sub(start).Seconds())
}

func sortDevices(list []model.Device) {
	rank := func(d model.Device) int {
		if d.Status == model.StatusPending {
			return 0
		}
		if d.Status == model.StatusApproved && !d.IsWhitelist {
			return 1
		}
		if d.IsWhitelist {
			return 2
		}
		if d.Status == model.StatusPaused {
			return 3
		}
		return 4
	}
	sort.Slice(list, func(i, j int) bool {
		ri, rj := rank(list[i]), rank(list[j])
		if ri != rj {
			return ri < rj
		}
		if list[i].Online != list[j].Online {
			return list[i].Online
		}
		if !list[i].ApprovedAt.Equal(list[j].ApprovedAt) {
			return list[i].ApprovedAt.After(list[j].ApprovedAt)
		}
		return list[i].MAC < list[j].MAC
	})
}
