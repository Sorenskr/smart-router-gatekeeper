package dns

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Server 提供轻量 Captive Portal DNS 服务（UDP + TCP），将未授权设备的 A 查询劫持至网关 IP。
type Server struct {
	addr     string
	targetIP net.IP
	udpConn  *net.UDPConn
	tcpLn    net.Listener
	wg       sync.WaitGroup
}

// NewServer 创建 Captive DNS 应答服务。
func NewServer(listenAddr, routerIP string) (*Server, error) {
	ip := net.ParseIP(routerIP).To4()
	if ip == nil {
		return nil, fmt.Errorf("无效的路由器 IPv4 地址: %q", routerIP)
	}
	return &Server{
		addr:     listenAddr,
		targetIP: ip,
	}, nil
}

// Start 启动 UDP 与 TCP DNS 监听。
func (s *Server) Start(ctx context.Context) error {
	udpAddr, err := net.ResolveUDPAddr("udp4", s.addr)
	if err != nil {
		return err
	}
	udpConn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		return fmt.Errorf("监听 Captive DNS UDP %s 失败: %w", s.addr, err)
	}
	s.udpConn = udpConn

	tcpLn, err := net.Listen("tcp4", s.addr)
	if err != nil {
		_ = udpConn.Close()
		return fmt.Errorf("监听 Captive DNS TCP %s 失败: %w", s.addr, err)
	}
	s.tcpLn = tcpLn

	s.wg.Add(2)
	go s.serveUDP(ctx)
	go s.serveTCP(ctx)
	go func() {
		<-ctx.Done()
		_ = udpConn.Close()
		_ = tcpLn.Close()
	}()
	return nil
}

// Wait 等待所有 DNS 监听协程退出。
func (s *Server) Wait() {
	s.wg.Wait()
}

func (s *Server) serveUDP(ctx context.Context) {
	defer s.wg.Done()
	buf := make([]byte, 2048)
	for {
		n, peer, err := s.udpConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				return
			}
		}
		req := make([]byte, n)
		copy(req, buf[:n])
		if resp, bErr := BuildDNSResponse(req, s.targetIP); bErr == nil {
			_, _ = s.udpConn.WriteToUDP(resp, peer)
		}
	}
}

func (s *Server) serveTCP(ctx context.Context) {
	defer s.wg.Done()
	for {
		conn, err := s.tcpLn.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				return
			}
		}
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			var lenBuf [2]byte
			if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
				return
			}
			msgLen := int(binary.BigEndian.Uint16(lenBuf[:]))
			if msgLen < 12 || msgLen > 4096 {
				return
			}
			req := make([]byte, msgLen)
			if _, err := io.ReadFull(c, req); err != nil {
				return
			}
			resp, err := BuildDNSResponse(req, s.targetIP)
			if err != nil {
				return
			}
			out := make([]byte, 2+len(resp))
			binary.BigEndian.PutUint16(out[:2], uint16(len(resp)))
			copy(out[2:], resp)
			_, _ = c.Write(out)
		}(conn)
	}
}

// BuildDNSResponse 根据 RFC 1035 构造轻量 Captive DNS 响应包。
// 对 IN A 查询返回 TTL=5s 的 targetIP；对 AAAA 等查询返回 NOERROR 空应答；保留 RD 标志并支持 EDNS0 OPT。
func BuildDNSResponse(req []byte, targetIP net.IP) ([]byte, error) {
	ip4 := targetIP.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("需要合法 IPv4 地址")
	}
	if len(req) < 12 {
		return nil, fmt.Errorf("DNS 报文过短: %d", len(req))
	}

	qdCount := binary.BigEndian.Uint16(req[4:6])
	arCount := binary.BigEndian.Uint16(req[10:12])
	reqFlags := binary.BigEndian.Uint16(req[2:4])
	rd := reqFlags & 0x0100

	offset := 12
	var qEnd int
	var qType, qClass uint16
	if qdCount >= 1 {
		next, err := skipDNSName(req, offset)
		if err != nil {
			return nil, err
		}
		if next+4 > len(req) {
			return nil, fmt.Errorf("DNS 问题段越界")
		}
		qType = binary.BigEndian.Uint16(req[next : next+2])
		qClass = binary.BigEndian.Uint16(req[next+2 : next+4])
		qEnd = next + 4
	} else {
		qEnd = 12
	}

	hasEDNS := arCount > 0 && hasOPTRecord(req, qEnd, int(binary.BigEndian.Uint16(req[6:8]))+int(binary.BigEndian.Uint16(req[8:10])), int(arCount))

	resp := make([]byte, 0, qEnd+40)
	resp = append(resp, req[:12]...)
	// QR=1 (0x8000), AA=1 (0x0400), RA=1 (0x0080), 保留 RD，RCODE=0
	respFlags := uint16(0x8480) | rd
	binary.BigEndian.PutUint16(resp[2:4], respFlags)
	if qdCount >= 1 {
		binary.BigEndian.PutUint16(resp[4:6], 1)
	} else {
		binary.BigEndian.PutUint16(resp[4:6], 0)
	}
	binary.BigEndian.PutUint16(resp[8:10], 0) // NSCOUNT = 0

	if qdCount >= 1 {
		resp = append(resp, req[12:qEnd]...)
	}

	if qdCount >= 1 && qType == 1 && (qClass == 1 || qClass == 255) {
		binary.BigEndian.PutUint16(resp[6:8], 1) // ANCOUNT = 1
		// Answer RR: Name pointer 0xC00C, Type=A(1), Class=IN(1), TTL=5s, RDLength=4, IPv4
		resp = append(resp,
			0xC0, 0x0C,
			0x00, 0x01,
			0x00, 0x01,
			0x00, 0x00, 0x00, 0x05,
			0x00, 0x04,
			ip4[0], ip4[1], ip4[2], ip4[3],
		)
	} else {
		binary.BigEndian.PutUint16(resp[6:8], 0) // ANCOUNT = 0 (如 AAAA 返回 NOERROR 空应答)
	}

	if hasEDNS {
		binary.BigEndian.PutUint16(resp[10:12], 1) // ARCOUNT = 1 (EDNS0 OPT)
		resp = append(resp,
			0x00,       // Root domain
			0x00, 0x29, // TYPE = OPT (41)
			0x04, 0xD0, // UDP payload size = 1232
			0x00,       // Extended RCODE
			0x00,       // EDNS version 0
			0x00, 0x00, // Z flags
			0x00, 0x00, // RDLEN = 0
		)
	} else {
		binary.BigEndian.PutUint16(resp[10:12], 0)
	}

	return resp, nil
}

func skipDNSName(msg []byte, offset int) (int, error) {
	jumps := 0
	for {
		if offset >= len(msg) {
			return 0, fmt.Errorf("DNS 域名解析越界")
		}
		l := msg[offset]
		if l == 0 {
			return offset + 1, nil
		}
		if l&0xC0 == 0xC0 {
			if offset+1 >= len(msg) {
				return 0, fmt.Errorf("DNS 压缩指针截断")
			}
			return offset + 2, nil
		}
		if l > 63 {
			return 0, fmt.Errorf("非法 DNS 标签长度: %d", l)
		}
		offset += 1 + int(l)
		jumps++
		if jumps > 64 {
			return 0, fmt.Errorf("DNS 域名标签过多")
		}
	}
}

func hasOPTRecord(msg []byte, offset int, skipOther int, arCount int) bool {
	pos := offset
	for i := 0; i < skipOther; i++ {
		next, err := skipRR(msg, pos)
		if err != nil {
			return false
		}
		pos = next
	}
	for i := 0; i < arCount; i++ {
		nextName, err := skipDNSName(msg, pos)
		if err != nil || nextName+10 > len(msg) {
			return false
		}
		rrType := binary.BigEndian.Uint16(msg[nextName : nextName+2])
		if rrType == 41 {
			return true
		}
		next, err := skipRR(msg, pos)
		if err != nil {
			return false
		}
		pos = next
	}
	return false
}

func skipRR(msg []byte, pos int) (int, error) {
	next, err := skipDNSName(msg, pos)
	if err != nil {
		return 0, err
	}
	if next+10 > len(msg) {
		return 0, fmt.Errorf("RR 头部截断")
	}
	rdLen := int(binary.BigEndian.Uint16(msg[next+8 : next+10]))
	if next+10+rdLen > len(msg) {
		return 0, fmt.Errorf("RR 数据截断")
	}
	return next + 10 + rdLen, nil
}
