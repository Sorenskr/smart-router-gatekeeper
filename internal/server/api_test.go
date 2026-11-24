package server_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gatekeeper/internal/dns"
	"gatekeeper/internal/firewall"
	"gatekeeper/internal/model"
	"gatekeeper/internal/monitor"
	"gatekeeper/internal/server"
	"gatekeeper/internal/store"
	"gatekeeper/internal/tunnel"
	"gatekeeper/internal/ws"
)

func buildTestDNSQuery(qname string, qtype uint16, edns bool) []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00})
	if edns {
		buf.Write([]byte{0x00, 0x01})
	} else {
		buf.Write([]byte{0x00, 0x00})
	}
	for _, label := range strings.Split(qname, ".") {
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0x00)
	_ = binary.Write(&buf, binary.BigEndian, qtype)
	_ = binary.Write(&buf, binary.BigEndian, uint16(1))
	if edns {
		buf.Write([]byte{0x00, 0x00, 0x29, 0x04, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	}
	return buf.Bytes()
}

func TestCaptiveDNSResponse(t *testing.T) {
	routerIP := net.ParseIP("192.168.6.1")

	// 测试 A 记录应答 + EDNS0 OPT
	reqA := buildTestDNSQuery("connectivitycheck.gstatic.com", 1, true)
	respA, err := dns.BuildDNSResponse(reqA, routerIP)
	if err != nil {
		t.Fatalf("BuildDNSResponse(A) 失败: %v", err)
	}
	if binary.BigEndian.Uint16(respA[0:2]) != 0x1234 {
		t.Fatalf("Transaction ID 未保留")
	}
	if binary.BigEndian.Uint16(respA[6:8]) != 1 {
		t.Fatalf("期望 ANCOUNT=1, 实际=%d", binary.BigEndian.Uint16(respA[6:8]))
	}
	if binary.BigEndian.Uint16(respA[10:12]) != 1 {
		t.Fatalf("期望保留 EDNS0 ARCOUNT=1, 实际=%d", binary.BigEndian.Uint16(respA[10:12]))
	}
	if !bytes.Contains(respA, []byte{192, 168, 6, 1}) {
		t.Fatalf("A 记录应答未包含路由网关 IP 192.168.6.1")
	}

	// 测试 AAAA 查询返回 NOERROR 空应答
	reqAAAA := buildTestDNSQuery("captive.apple.com", 28, false)
	respAAAA, err := dns.BuildDNSResponse(reqAAAA, routerIP)
	if err != nil {
		t.Fatalf("BuildDNSResponse(AAAA) 失败: %v", err)
	}
	flags := binary.BigEndian.Uint16(respAAAA[2:4])
	if flags&0x000F != 0 {
		t.Fatalf("期望 AAAA RCODE=0, 实际=%d", flags&0x000F)
	}
	if binary.BigEndian.Uint16(respAAAA[6:8]) != 0 {
		t.Fatalf("期望 AAAA ANCOUNT=0, 实际=%d", binary.BigEndian.Uint16(respAAAA[6:8]))
	}
}

func TestNFTablesAntiBypassAndAntiLockout(t *testing.T) {
	script, count, err := firewall.BuildNFTablesScript(firewall.ScriptConfig{
		RouterIP:        "192.168.6.1",
		LanIface:        "br-lan",
		AdminPort:       8088,
		PortalPort:      8089,
		DNSPort:         5354,
		WhitelistMACs:   []string{"00:1a:2b:3c:4d:01", "invalid-mac; drop"},
		WhitelistIPs:    []string{"192.168.6.10", "bad-ip"},
		AllowedMACs:     []string{"AA:BB:CC:11:22:01"},
		AllowAdminPorts: true,
	})
	if err != nil {
		t.Fatalf("BuildNFTablesScript 失败: %v", err)
	}
	if count < 20 {
		t.Fatalf("规则计数异常偏少: %d", count)
	}

	required := []string{
		"table inet gatekeeper",
		"delete table inet gatekeeper",
		"type filter hook prerouting priority -170; policy accept;",
		"type nat hook prerouting priority -160; policy accept;",
		"type filter hook input priority -10; policy accept;",
		"type filter hook forward priority -10; policy accept;",
		"udp dport 53 counter redirect to :5354",
		"tcp dport 53 counter redirect to :5354",
		"tcp dport 80 counter redirect to :8089",
		"ip daddr 192.168.6.1 tcp dport { 22, 8088 } counter accept",
		"00:1a:2b:3c:4d:01",
		"192.168.6.1",
		"192.168.6.10",
		"aa:bb:cc:11:22:01",
	}
	for _, needle := range required {
		if !strings.Contains(script, needle) {
			t.Fatalf("nftables 脚本缺少关键防护语句: %q", needle)
		}
	}
	if strings.Contains(script, "invalid-mac") || strings.Contains(script, "bad-ip") {
		t.Fatalf("nftables 脚本未过滤非法输入，存在注入风险")
	}
	// 内核 prerouting 链不支持 reject，严格校验整个 prerouting 区域无 reject
	preEnd := strings.Index(script, "chain input_guard")
	if preEnd > 0 && strings.Contains(script[:preEnd], "reject") {
		t.Fatalf("prerouting 链严禁使用 reject 语句")
	}
}

func setupTestServer(t *testing.T, dataDir string) (*server.Server, *store.Store, string) {
	t.Helper()
	st, err := store.NewStore(dataDir, true, "admin123", "192.168.6.1", "br-lan", "192.168.6.10", "")
	if err != nil {
		t.Fatalf("NewStore 失败: %v", err)
	}
	fw := firewall.NewMockManager(st, 8088, 8089, 5354)
	_ = fw.SyncAll()
	mon := monitor.NewMockMonitor(st, fw, 8088, 8089, 5354, nil)
	tun := tunnel.NewManager(st, true, 8088, nil)
	hub := ws.NewHub()
	srv := server.NewServer(st, fw, mon, tun, hub, true, 8088, 8089)

	// 登录获取 token
	loginReq := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"password":"admin123"}`))
	loginRec := httptest.NewRecorder()
	srv.AdminHandler().ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("登录失败: %d %s", loginRec.Code, loginRec.Body.String())
	}
	var loginResp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(loginRec.Body.Bytes(), &loginResp)
	return srv, st, loginResp.Token
}

func TestEndToEndBusinessWorkflowAndPersistence(t *testing.T) {
	dataDir := t.TempDir()
	srv, _, token := setupTestServer(t, dataDir)
	admin := srv.AdminHandler()
	portal := srv.PortalHandler()

	doAdmin := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		admin.ServeHTTP(rec, req)
		return rec
	}

	// 测试 1：新手机提交名字“测试机_阿杰” -> 待审批
	newMAC := "AA:BB:CC:99:88:77"
	applyReq := httptest.NewRequest(http.MethodPost, "/api/portal/apply?mac="+newMAC, strings.NewReader(`{"name":"测试机_阿杰","mac":"`+newMAC+`","ip":"192.168.6.166"}`))
	applyReq.Header.Set("Content-Type", "application/json")
	applyRec := httptest.NewRecorder()
	portal.ServeHTTP(applyRec, applyReq)
	if applyRec.Code != http.StatusOK {
		t.Fatalf("门户申请失败: %d %s", applyRec.Code, applyRec.Body.String())
	}

	// 验证未授权时探针 /generate_204 返回 302 跳转门户
	probeReq := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8089/generate_204?mac="+newMAC, nil)
	probeRec := httptest.NewRecorder()
	portal.ServeHTTP(probeRec, probeReq)
	if probeRec.Code != http.StatusFound {
		t.Fatalf("未授权设备探针应返回 302，实际 %d", probeRec.Code)
	}

	// 测试 2：当前并发上限为 2（小王、小红已占用），尝试批准第 3 台应触发 409 并发冲突
	approveConflict := doAdmin(http.MethodPost, "/api/devices/"+newMAC+"/approve", `{}`)
	if approveConflict.Code != http.StatusConflict {
		t.Fatalf("期望触发 409 并发上限冲突，实际 %d: %s", approveConflict.Code, approveConflict.Body.String())
	}
	var conflict model.ConcurrencyConflictError
	_ = json.Unmarshal(approveConflict.Body.Bytes(), &conflict)
	if conflict.OldestDevice == nil || conflict.OldestDevice.MAC != "AA:BB:CC:11:22:01" {
		t.Fatalf("最早接入设备判断不准确: %+v", conflict.OldestDevice)
	}

	// 一键顶替最早设备
	approveReplace := doAdmin(http.MethodPost, "/api/devices/"+newMAC+"/approve", `{"replace_oldest":true}`)
	if approveReplace.Code != http.StatusOK {
		t.Fatalf("一键顶替放行失败: %d %s", approveReplace.Code, approveReplace.Body.String())
	}

	// 放行后探针 /generate_204 应返回 204
	probeOKReq := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8089/generate_204?mac="+newMAC, nil)
	probeOKRec := httptest.NewRecorder()
	portal.ServeHTTP(probeOKRec, probeOKReq)
	if probeOKRec.Code != http.StatusNoContent {
		t.Fatalf("已放行设备探针应返回 204，实际 %d", probeOKRec.Code)
	}

	// 测试 3：一键断网 -> 验证门户返回 paused -> 恢复连网 -> 验证恢复 approved
	pauseRec := doAdmin(http.MethodPost, "/api/devices/"+newMAC+"/pause", `{}`)
	if pauseRec.Code != http.StatusOK {
		t.Fatalf("一键断网失败: %d", pauseRec.Code)
	}
	pStatusReq := httptest.NewRequest(http.MethodGet, "/api/portal/status?mac="+newMAC, nil)
	pStatusRec := httptest.NewRecorder()
	portal.ServeHTTP(pStatusRec, pStatusReq)
	var ps model.PortalStatus
	_ = json.Unmarshal(pStatusRec.Body.Bytes(), &ps)
	if ps.Status != model.StatusPaused {
		t.Fatalf("断网后门户状态应为 paused，实际 %s", ps.Status)
	}

	resumeRec := doAdmin(http.MethodPost, "/api/devices/"+newMAC+"/resume", `{}`)
	if resumeRec.Code != http.StatusOK {
		t.Fatalf("恢复连网失败: %d %s", resumeRec.Code, resumeRec.Body.String())
	}

	// 测试 4：修改备注名并验证重启后持久化不丢失
	remarkRec := doAdmin(http.MethodPut, "/api/devices/"+newMAC+"/remark", `{"remark":"阿杰的主力测试机"}`)
	if remarkRec.Code != http.StatusOK {
		t.Fatalf("修改备注失败: %d", remarkRec.Code)
	}

	// 模拟重启服务，重新从同一个 dataDir 加载 Store
	srv2, _, token2 := setupTestServer(t, dataDir)
	stateReq := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	stateReq.Header.Set("Authorization", "Bearer "+token2)
	stateRec := httptest.NewRecorder()
	srv2.AdminHandler().ServeHTTP(stateRec, stateReq)
	var snap model.DashboardSnapshot
	_ = json.Unmarshal(stateRec.Body.Bytes(), &snap)

	var found *model.Device
	for i := range snap.Devices {
		if snap.Devices[i].MAC == newMAC {
			found = &snap.Devices[i]
			break
		}
	}
	if found == nil || found.AdminRemark != "阿杰的主力测试机" || found.Status != model.StatusApproved {
		t.Fatalf("重启后设备数据未正确持久化: %+v", found)
	}
}

func TestTimedPauseAutoResumeAndPersistence(t *testing.T) {
	dataDir := t.TempDir()
	srv, _, token := setupTestServer(t, dataDir)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.StartScheduler(ctx)

	admin := srv.AdminHandler()
	portal := srv.PortalHandler()

	doAdmin := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		admin.ServeHTTP(rec, req)
		return rec
	}

	targetMAC := "AA:BB:CC:11:22:01"
	// 1. 定时断网 1 秒，验证立即进入 paused 且具有 pause_until
	pRec := doAdmin(http.MethodPost, "/api/devices/"+targetMAC+"/pause", `{"duration_seconds":1}`)
	if pRec.Code != http.StatusOK {
		t.Fatalf("定时断网请求失败: %d %s", pRec.Code, pRec.Body.String())
	}
	var pResp struct {
		OK     bool         `json:"ok"`
		Device model.Device `json:"device"`
	}
	_ = json.Unmarshal(pRec.Body.Bytes(), &pResp)
	if pResp.Device.Status != model.StatusPaused || pResp.Device.PauseUntil == nil || pResp.Device.PauseRemainingSec <= 0 {
		t.Fatalf("定时断网字段异常: %+v", pResp.Device)
	}

	// 验证门户端返回剩余恢复秒数
	psReq := httptest.NewRequest(http.MethodGet, "/api/portal/status?mac="+targetMAC, nil)
	psRec := httptest.NewRecorder()
	portal.ServeHTTP(psRec, psReq)
	var ps model.PortalStatus
	_ = json.Unmarshal(psRec.Body.Bytes(), &ps)
	if ps.Status != model.StatusPaused || ps.PauseUntil == nil || !strings.Contains(ps.Message, "自动恢复") {
		t.Fatalf("门户端定时断网信息异常: %+v", ps)
	}

	// 2. 等待后台调度器自动恢复放行
	autoResumed := false
	for i := 0; i < 20; i++ {
		time.Sleep(200 * time.Millisecond)
		stReq := httptest.NewRequest(http.MethodGet, "/api/portal/status?mac="+targetMAC, nil)
		stRec := httptest.NewRecorder()
		portal.ServeHTTP(stRec, stReq)
		var cur model.PortalStatus
		_ = json.Unmarshal(stRec.Body.Bytes(), &cur)
		if cur.Status == model.StatusApproved && cur.PauseUntil == nil {
			autoResumed = true
			break
		}
	}
	if !autoResumed {
		t.Fatalf("定时断网到期后未自动恢复连网")
	}

	// 3. 定时断网 30 分钟后手动提前恢复
	p30 := doAdmin(http.MethodPost, "/api/devices/"+targetMAC+"/pause", `{"duration_minutes":30}`)
	if p30.Code != http.StatusOK {
		t.Fatalf("30 分钟定时断网失败: %d", p30.Code)
	}
	resRec := doAdmin(http.MethodPost, "/api/devices/"+targetMAC+"/resume", `{}`)
	if resRec.Code != http.StatusOK {
		t.Fatalf("手动提前恢复失败: %d %s", resRec.Code, resRec.Body.String())
	}

	// 4. 定时断网 60 分钟后模拟服务重启验证 pause_until 持久化
	p60 := doAdmin(http.MethodPost, "/api/devices/"+targetMAC+"/pause", `{"duration_minutes":60}`)
	if p60.Code != http.StatusOK {
		t.Fatalf("60 分钟定时断网失败: %d", p60.Code)
	}
	_, st2, _ := setupTestServer(t, dataDir)
	devAfter, ok := st2.GetDevice(targetMAC)
	if !ok || devAfter.Status != model.StatusPaused || devAfter.PauseUntil == nil || devAfter.PauseRemainingSec < 3000 {
		t.Fatalf("重启后定时断网截止时间未正确持久化: %+v", devAfter)
	}
}
