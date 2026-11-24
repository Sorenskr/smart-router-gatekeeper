package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"gatekeeper/internal/dns"
	"gatekeeper/internal/firewall"
	"gatekeeper/internal/monitor"
	"gatekeeper/internal/server"
	"gatekeeper/internal/store"
	"gatekeeper/internal/tunnel"
	"gatekeeper/internal/ws"
)

func main() {
	defaultMock := strings.EqualFold(os.Getenv("MOCK_MODE"), "true") || os.Getenv("MOCK_MODE") == "1"

	mockFlag := flag.Bool("mock", defaultMock, "启用本地模拟仿真模式（生成 5 台仿真设备，不执行系统级 nftables/conntrack 命令）")
	adminPort := flag.Int("port", 8088, "管理大屏 HTTP/WebSocket 监听端口")
	portalPort := flag.Int("portal-port", 8089, "Captive Portal 强制认证页监听端口")
	dnsPort := flag.Int("dns-port", 5354, "Captive DNS 劫持监听端口（非 mock 模式下在 Linux 启用）")
	dataDir := flag.String("data-dir", "./data", "持久化状态文件目录")
	password := flag.String("password", "admin123", "管理员初始登录密码（已在持久化文件设置后以持久化为准）")
	routerIP := flag.String("router-ip", "192.168.6.1", "软路由 LAN 网关 IPv4 地址")
	lanIface := flag.String("lan-iface", "br-lan", "软路由 LAN 桥接接口名称")
	adminIP := flag.String("admin-ip", "", "初始防锁死管理主机 IPv4 地址")
	adminMAC := flag.String("admin-mac", "", "初始永久白名单管理主机 MAC 地址")
	cleanupOnExit := flag.Bool("cleanup-on-exit", true, "服务退出时自动清理 nftables table inet gatekeeper")
	enableMockDNS := flag.Bool("mock-dns", false, "在 --mock 模式下同时监听 Captive DNS 端口")
	flag.Parse()

	mockMode := *mockFlag
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("正在启动 Smart Router Gatekeeper (平台: %s/%s, 仿真模式: %v)...", runtime.GOOS, runtime.GOARCH, mockMode)

	st, err := store.NewStore(*dataDir, mockMode, *password, *routerIP, *lanIface, *adminIP, *adminMAC)
	if err != nil {
		log.Fatalf("初始化状态仓库失败: %v", err)
	}

	var fw firewall.Manager
	if mockMode || runtime.GOOS != "linux" {
		fw = firewall.NewMockManager(st, *adminPort, *portalPort, *dnsPort)
	} else {
		fw = firewall.NewLinuxManager(st, *adminPort, *portalPort, *dnsPort)
	}
	if err := fw.SyncAll(); err != nil {
		log.Printf("警告: 初次同步防火墙规则失败: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 启动 Captive DNS（真实 Linux 环境默认启用，--mock 模式默认跳过以免与本地系统冲突，除非显式传 --mock-dns）
	if (!mockMode && runtime.GOOS == "linux") || *enableMockDNS {
		dnsSrv, err := dns.NewServer(fmt.Sprintf(":%d", *dnsPort), *routerIP)
		if err != nil {
			log.Fatalf("创建 Captive DNS 服务失败: %v", err)
		}
		if err := dnsSrv.Start(ctx); err != nil {
			log.Fatalf("启动 Captive DNS 服务失败: %v", err)
		}
		log.Printf("Captive DNS 应答器已监听 :%d -> %s", *dnsPort, *routerIP)
	}

	hub := ws.NewHub()
	var srvRef *server.Server

	var mon monitor.Monitor
	onUpdate := func() {
		if srvRef != nil {
			srvRef.BroadcastAll()
		}
	}
	if mockMode || runtime.GOOS != "linux" {
		mon = monitor.NewMockMonitor(st, fw, *adminPort, *portalPort, *dnsPort, onUpdate)
	} else {
		mon = monitor.NewLinuxMonitor(st, fw, *adminPort, *portalPort, *dnsPort, onUpdate)
	}

	tun := tunnel.NewManager(st, mockMode, *adminPort, onUpdate)
	srvRef = server.NewServer(st, fw, mon, tun, hub, mockMode, *adminPort, *portalPort)

	go mon.Start(ctx)
	go srvRef.StartScheduler(ctx)

	adminHTTP := &http.Server{
		Addr:              fmt.Sprintf(":%d", *adminPort),
		Handler:           srvRef.AdminHandler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	portalHTTP := &http.Server{
		Addr:              fmt.Sprintf(":%d", *portalPort),
		Handler:           srvRef.PortalHandler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 2)
	go func() {
		log.Printf("管理后台已就绪: http://127.0.0.1:%d （默认密码: %s）", *adminPort, *password)
		if err := adminHTTP.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("管理端端口 :%d 监听异常: %w", *adminPort, err)
		}
	}()
	go func() {
		log.Printf("手机强制认证页 (Captive Portal) 已就绪: http://127.0.0.1:%d/portal", *portalPort)
		if err := portalHTTP.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("门户端口 :%d 监听异常: %w", *portalPort, err)
		}
	}()

	select {
	case <-ctx.Done():
		log.Println("收到退出信号，正在优雅关闭服务...")
	case fatalErr := <-errCh:
		log.Printf("服务端异常: %v", fatalErr)
		stop()
	}

	tun.Stop()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = adminHTTP.Shutdown(shutdownCtx)
	_ = portalHTTP.Shutdown(shutdownCtx)
	if *cleanupOnExit && !mockMode && runtime.GOOS == "linux" {
		if err := fw.Cleanup(); err != nil {
			log.Printf("清理 nftables gatekeeper 表时遇到提示: %v", err)
		} else {
			log.Println("已清理 table inet gatekeeper 防火墙规则")
		}
	}
	log.Println("服务已安全退出。")
}
