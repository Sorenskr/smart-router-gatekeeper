package ws

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// Client 表示一个已握手的 RFC 6455 WebSocket 长连接。
type Client struct {
	conn    net.Conn
	reader  *bufio.Reader
	writeMu sync.Mutex
	closed  bool
	done    chan struct{}
	onClose func(*Client)
}

// Upgrade 将 HTTP 请求升级为 WebSocket 连接并启动读写保活。
func Upgrade(w http.ResponseWriter, r *http.Request, onClose func(*Client)) (*Client, error) {
	if !headerContains(r.Header, "Connection", "upgrade") || !headerContains(r.Header, "Upgrade", "websocket") {
		return nil, fmt.Errorf("缺少合法的 WebSocket 升级请求头")
	}
	key := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	if key == "" {
		return nil, fmt.Errorf("缺少 Sec-WebSocket-Key")
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, fmt.Errorf("当前 HTTP ResponseWriter 不支持 Hijack")
	}
	conn, bufrw, err := hj.Hijack()
	if err != nil {
		return nil, fmt.Errorf("Hijack 连接失败: %w", err)
	}

	sum := sha1.Sum([]byte(key + wsGUID))
	accept := base64.StdEncoding.EncodeToString(sum[:])

	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"

	if _, err := bufrw.WriteString(resp); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := bufrw.Flush(); err != nil {
		_ = conn.Close()
		return nil, err
	}

	client := &Client{
		conn:    conn,
		reader:  bufrw.Reader,
		done:    make(chan struct{}),
		onClose: onClose,
	}
	go client.readLoop()
	go client.pingLoop()
	return client, nil
}

// SendJSON 将任意结构序列化为 JSON 文本帧并线程安全发送。
func (c *Client) SendJSON(v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return c.writeFrame(0x1, payload)
}

// Close 主动关闭连接并立即唤醒终止心跳协程。
func (c *Client) Close() {
	c.writeMu.Lock()
	if c.closed {
		c.writeMu.Unlock()
		return
	}
	c.closed = true
	close(c.done)
	_ = c.writeFrameRaw(0x8, nil)
	_ = c.conn.Close()
	c.writeMu.Unlock()

	if c.onClose != nil {
		c.onClose(c)
	}
}

func (c *Client) writeFrame(opcode byte, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed {
		return errors.New("WebSocket 已关闭")
	}
	return c.writeFrameRaw(opcode, payload)
}

func (c *Client) writeFrameRaw(opcode byte, payload []byte) error {
	_ = c.conn.SetWriteDeadline(time.Now().Add(4 * time.Second))
	header := make([]byte, 0, 10)
	header = append(header, 0x80|opcode)
	n := len(payload)
	switch {
	case n < 126:
		header = append(header, byte(n))
	case n <= 65535:
		header = append(header, 126, byte(n>>8), byte(n))
	default:
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(n))
		header = append(header, 127)
		header = append(header, ext[:]...)
	}
	if _, err := c.conn.Write(header); err != nil {
		return err
	}
	if n > 0 {
		if _, err := c.conn.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) pingLoop() {
	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			if err := c.writeFrame(0x9, []byte("ping")); err != nil {
				c.Close()
				return
			}
		}
	}
}

func (c *Client) readLoop() {
	defer c.Close()
	for {
		_ = c.conn.SetReadDeadline(time.Now().Add(65 * time.Second))
		opcode, payload, err := c.readFrame()
		if err != nil {
			return
		}
		switch opcode {
		case 0x8: // Close
			return
		case 0x9: // Ping -> Pong
			if err := c.writeFrame(0xA, payload); err != nil {
				return
			}
		case 0xA: // Pong
			// 已刷新读超时
		}
	}
}

func (c *Client) readFrame() (byte, []byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(c.reader, hdr[:]); err != nil {
		return 0, nil, err
	}
	opcode := hdr[0] & 0x0F
	masked := hdr[1]&0x80 != 0
	length := uint64(hdr[1] & 0x7F)

	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(c.reader, ext[:]); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(c.reader, ext[:]); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}

	if length > 1024*1024 {
		return 0, nil, fmt.Errorf("WebSocket 帧过大: %d", length)
	}

	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(c.reader, maskKey[:]); err != nil {
			return 0, nil, err
		}
	}

	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(c.reader, payload); err != nil {
			return 0, nil, err
		}
	}
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}
	return opcode, payload, nil
}

func headerContains(h http.Header, name, token string) bool {
	for _, val := range h.Values(name) {
		for _, part := range strings.Split(val, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

// Hub 管理管理端与门户端的所有实时 WebSocket 订阅者。
type Hub struct {
	mu            sync.RWMutex
	adminClients  map[*Client]string
	portalClients map[*Client]portalIdentity
}

type portalIdentity struct {
	mac string
	ip  string
}

// NewHub 创建 WebSocket 连接池。
func NewHub() *Hub {
	return &Hub{
		adminClients:  make(map[*Client]string),
		portalClients: make(map[*Client]portalIdentity),
	}
}

// RegisterAdmin 注册一个管理端 WebSocket 客户端。
func (h *Hub) RegisterAdmin(w http.ResponseWriter, r *http.Request, viewerIP string) (*Client, error) {
	var client *Client
	client, err := Upgrade(w, r, func(c *Client) {
		h.mu.Lock()
		delete(h.adminClients, c)
		h.mu.Unlock()
	})
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	h.adminClients[client] = viewerIP
	h.mu.Unlock()
	return client, nil
}

// RegisterPortal 注册一个手机认证页 WebSocket 客户端。
func (h *Hub) RegisterPortal(w http.ResponseWriter, r *http.Request, mac, ip string) (*Client, error) {
	client, err := Upgrade(w, r, func(c *Client) {
		h.mu.Lock()
		delete(h.portalClients, c)
		h.mu.Unlock()
	})
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	h.portalClients[client] = portalIdentity{mac: mac, ip: ip}
	h.mu.Unlock()
	return client, nil
}

// BroadcastAdmin 向所有在线管理端按其各自 viewerIP 推送完整快照。
func (h *Hub) BroadcastAdmin(buildFn func(viewerIP string) any) {
	h.mu.RLock()
	targets := make(map[*Client]string, len(h.adminClients))
	for c, ip := range h.adminClients {
		targets[c] = ip
	}
	h.mu.RUnlock()

	for c, ip := range targets {
		msg := map[string]any{
			"type": "state",
			"data": buildFn(ip),
		}
		if err := c.SendJSON(msg); err != nil {
			c.Close()
		}
	}
}

// BroadcastPortal 向所有认证页客户端推送各自最新状态。
func (h *Hub) BroadcastPortal(buildFn func(mac, ip string) any) {
	h.mu.RLock()
	targets := make(map[*Client]portalIdentity, len(h.portalClients))
	for c, id := range h.portalClients {
		targets[c] = id
	}
	h.mu.RUnlock()

	for c, id := range targets {
		msg := map[string]any{
			"type": "portal_status",
			"data": buildFn(id.mac, id.ip),
		}
		if err := c.SendJSON(msg); err != nil {
			c.Close()
		}
	}
}
