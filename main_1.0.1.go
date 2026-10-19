package main

import (
	"bufio"
	"bytes"
	"context"
	crypto_rand "crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Khai báo các hằng số tinh chỉnh hạ tầng nội bộ (Hard-coded system tuning constants)
const (
	defaultDialTimeout                    = 5 * time.Second  // Thời gian chờ kết nối TCP ra máy chủ đích / TCP Dial connection timeout
	defaultDNSTimeout                     = 5 * time.Second  // Thời gian chờ truy vấn UDP DNS / UDP DNS query timeout
	defaultTransportResponseHeaderTimeout = 30 * time.Second // Thời gian chờ nhận HTTP Response Header / HTTP Response Header timeout
	defaultTransportIdleConnTimeout       = 90 * time.Second // Thời gian duy trì kết nối rỗi trong HTTP Transport pool / HTTP Transport idle connection pool timeout
)

// Định nghĩa cấu trúc lưu trữ toàn bộ tham số cấu hình hệ thống proxy
// Configuration structure storing all system proxy parameters
type Config struct {
	LogShow         bool
	ListenAddress   string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ClientTimeout   time.Duration
	DNSFallback     string
	DNSIP           string
	DNSDOH          string
	DNSDOT          string
	DNSCache        bool
	DNSCacheSize    int64 // Lưu trữ dung lượng cache dưới dạng bytes / Storage cache size in bytes
	DNSCacheExp     time.Duration
	ClientAllowlist string // Danh sách IP cho phép, phân tách bằng dấu chấm phẩy / Allowed IPs separated by semicolon
	AllowPrivateIP  bool   // Cho phép proxy truy cập IP nội bộ (LAN/Loopback) hay không / Allow accessing private IPs
}

// Cấu trúc lưu trữ bản ghi DNS Cache kèm thời gian hết hạn và kích thước
// DNS Cache record structure with expiration time and size
type DNSCacheItem struct {
	IPs        []string
	ExpireTime time.Time
	Size       int64
}

var (
	// Bộ nhớ cache DNS toàn cục và cơ chế khóa đồng thời
	// Global DNS cache storage and concurrency locking mechanism
	dnsCacheStore    = make(map[string]DNSCacheItem)
	dnsCacheMutex    sync.RWMutex
	currentCacheSize int64

	// Khai báo Buffer Pool toàn cục (32KB mỗi buffer) để tái sử dụng, giảm áp lực cho GC
	// Global Buffer Pool declaration (32KB per buffer) for reuse and GC pressure reduction
	bufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 32*1024)
		},
	}

	// Semaphore giới hạn tối đa 8192 kết nối đồng thời để bảo vệ File Descriptors
	// Semaphore limiting up to 8,192 concurrent connections to protect File Descriptors
	maxConnsChan = make(chan struct{}, 8192)

	// Transport dùng chung cho HTTP requests
	// Shared Transport for HTTP requests
	httpTransport *http.Transport
)

// Biến cấu hình toàn cục của ứng dụng
// Global application configuration variable
var config Config

func main() {
	// Tải file cấu hình từ config.conf
	// Load configuration values from config.conf
	loadConfig("config.conf")

	// Khởi tạo httpTransport sử dụng các hằng số nội bộ
	// Initialize httpTransport using internal constants
	initHTTPTransport()

	// Lắng nghe TCP trên ListenAddress hỗ trợ cả IPv4 và IPv6 (Dual-stack)
	// Listen on TCP supporting both IPv4 and IPv6 (Dual-stack)
	listener, err := net.Listen("tcp", config.ListenAddress)
	if err != nil {
		log.Fatalf("Can not start the server: %v", err)
	}
	defer listener.Close()

	log.Printf("Proxy (HTTP & SOCKS5 Dual-Stack TCP/UDP) is running at: %s\n", config.ListenAddress)
	log.Printf("Log show status: %v\n", config.LogShow)
	log.Printf("Timeouts -> Read: %v, Write: %v, Idle: %v, Client: %v\n", config.ReadTimeout, config.WriteTimeout, config.IdleTimeout, config.ClientTimeout)
	log.Printf("DNS Cache status: %v (Size limit: %d bytes, Expire: %v)\n", config.DNSCache, config.DNSCacheSize, config.DNSCacheExp)
	log.Printf("Client Allowlist: [%s], Allow Private IP: %v\n", config.ClientAllowlist, config.AllowPrivateIP)

	// Thực hiện kiểm tra sức khỏe DNS nội bộ khởi động
	// Run initial internal DNS health check
	runClientDNSHealthCheckWithInternal("google.com")

	// Vòng lặp chấp nhận kết nối từ client có kiểm soát Semaphore và Allowlist IP
	// Accept incoming connections loop with Semaphore and IP Allowlist check
	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}

		// Kiểm tra danh sách IP client được phép kết nối
		// Check if client IP is authorized
		if !isClientAllowed(conn.RemoteAddr()) {
			if config.LogShow {
				log.Printf("[SECURITY] Rejected connection from unauthorized IP: %s\n", conn.RemoteAddr())
			}
			conn.Close()
			continue
		}

		maxConnsChan <- struct{}{}
		go func(c net.Conn) {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[RECOVER] Panic recovered in connection handler: %v\n", r)
				}
				<-maxConnsChan
			}()
			handleIncomingConnection(c)
		}(conn)
	}
}

// Khởi tạo HTTP Transport dùng chung từ các hằng số nội bộ
// Initialize shared HTTP Transport using internal constants
func initHTTPTransport() {
	httpTransport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := resolveDomainPriority(host)
			if err != nil || len(ips) == 0 {
				return nil, fmt.Errorf("could not resolve domain: %s", host)
			}

			conn, _, err := dialWithFallback(ips, port)
			return conn, err
		},
		DisableCompression:    true,
		DisableKeepAlives:     true, // Ép tạo kết nối mới hoàn toàn cho mỗi request HTTP thuần / Force new connection for each HTTP request
		ResponseHeaderTimeout: defaultTransportResponseHeaderTimeout,
		IdleConnTimeout:       defaultTransportIdleConnTimeout,
	}
}

// Kiểm tra xem IP của client có nằm trong danh sách cho phép hay không (hỗ trợ IPv4/IPv6 CIDR và IP đơn)
// Check if client IP is allowed (supports IPv4/IPv6 single IPs and CIDRs separated by semicolons)
func isClientAllowed(remoteAddr net.Addr) bool {
	if config.ClientAllowlist == "" || config.ClientAllowlist == "*" {
		return true
	}

	host, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		host = remoteAddr.String()
	}

	clientIP := net.ParseIP(host)
	if clientIP == nil {
		return false
	}

	rules := strings.Split(config.ClientAllowlist, ";")
	for _, rule := range rules {
		rule = strings.TrimSpace(rule)
		if rule == "" {
			continue
		}

		if strings.Contains(rule, "/") {
			_, subnet, err := net.ParseCIDR(rule)
			if err == nil && subnet.Contains(clientIP) {
				return true
			}
		} else {
			allowedIP := net.ParseIP(rule)
			if allowedIP != nil && allowedIP.Equal(clientIP) {
				return true
			}
		}
	}
	return false
}

// Kiểm tra xem một IP (v4 hoặc v6) có thuộc dải mạng nội bộ (Loopback, Private, Link-Local) hay không
// Check if an IP (v4 or v6) belongs to internal/private networks (Loopback, Private, Link-Local)
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	if ip.To4() == nil {
		if len(ip) == net.IPv6len && (ip[0]&0xfe) == 0xfc {
			return true
		}
		return false
	}

	ipv4 := ip.To4()
	if ipv4[0] == 10 || (ipv4[0] == 172 && ipv4[1] >= 16 && ipv4[1] <= 31) || (ipv4[0] == 192 && ipv4[1] == 168) || ipv4[0] == 127 {
		return true
	}

	return false
}

type timeoutConn struct {
	net.Conn
	readTimeout  time.Duration
	writeTimeout time.Duration
	idleTimeout  time.Duration
	lastActivity time.Time
	mu           sync.Mutex
}

func (c *timeoutConn) updateActivity() {
	c.mu.Lock()
	c.lastActivity = time.Now()
	c.mu.Unlock()
}

func (c *timeoutConn) Read(b []byte) (int, error) {
	if c.readTimeout > 0 {
		c.SetReadDeadline(time.Now().Add(c.readTimeout))
	} else if c.idleTimeout > 0 {
		c.mu.Lock()
		idle := c.idleTimeout
		c.mu.Unlock()
		c.SetReadDeadline(time.Now().Add(idle))
	}
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.updateActivity()
	}
	return n, err
}

func (c *timeoutConn) Write(b []byte) (int, error) {
	if c.writeTimeout > 0 {
		c.SetWriteDeadline(time.Now().Add(c.writeTimeout))
	}
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.updateActivity()
	}
	return n, err
}

type peekReaderConn struct {
	*timeoutConn
	reader *bufio.Reader
}

func (c *peekReaderConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

// Phân luồng kết nối đến dựa trên byte đầu tiên (0x05 là SOCKS5, ngược lại là HTTP Proxy)
// Dispatch incoming connection based on the first byte (0x05 is SOCKS5, otherwise HTTP Proxy)
func handleIncomingConnection(clientConn net.Conn) {
	tConn := &timeoutConn{
		Conn:         clientConn,
		readTimeout:  config.ReadTimeout,
		writeTimeout: config.WriteTimeout,
		idleTimeout:  config.IdleTimeout,
		lastActivity: time.Now(),
	}

	// Áp dụng clientTimeout làm mốc thời gian tổng thể cho phiên kết nối
	// Apply clientTimeout as the hard limit for the overall connection lifetime
	if config.ClientTimeout > 0 {
		time.AfterFunc(config.ClientTimeout, func() {
			tConn.Close()
		})
	}

	// Định kỳ kiểm tra kết nối rỗi dựa trên idleTimeout
	// Periodically check for idle connection timeout based on idleTimeout
	if config.IdleTimeout > 0 {
		done := make(chan struct{})
		defer close(done)
		go func() {
			ticker := time.NewTicker(config.IdleTimeout / 2)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					tConn.mu.Lock()
					inactive := time.Since(tConn.lastActivity)
					tConn.mu.Unlock()
					if inactive >= config.IdleTimeout {
						tConn.Close()
						return
					}
				case <-done:
					return
				}
			}
		}()
	}

	tConn.SetReadDeadline(time.Now().Add(config.ReadTimeout))

	reader := bufio.NewReader(tConn)
	firstByte, err := reader.Peek(1)
	if err != nil {
		tConn.Close()
		return
	}

	peeledConn := &peekReaderConn{
		timeoutConn: tConn,
		reader:      reader,
	}

	if firstByte[0] == 0x05 {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[RECOVER] Panic in SOCKS5 handler: %v\n", r)
				}
			}()
			handleSocks5Direct(peeledConn)
		}()
	} else {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[RECOVER] Panic in HTTP Proxy handler: %v\n", r)
				}
			}()
			handleHTTPProxyDirect(peeledConn, reader)
		}()
	}
}

// Xử lý kết nối HTTP Proxy trực tiếp (hỗ trợ CONNECT tunneling và HTTP request thông thường)
// Handle direct HTTP proxy connection (supports CONNECT tunneling and standard HTTP requests)
func handleHTTPProxyDirect(clientConn net.Conn, reader *bufio.Reader) {
	defer clientConn.Close()

	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	if req.Method == http.MethodConnect {
		handleConnectDirect(clientConn, req.Host)
	} else {
		handleHTTPDirect(clientConn, req)
	}
}

// Dial tới danh sách IP thu được với defaultDialTimeout (Ưu tiên IPv6 trước, fallback IPv4 sau)
// Dial to list of resolved IPs with defaultDialTimeout (Prioritizing IPv6 first, falling back to IPv4 on failure)
func dialWithFallback(ips []string, port string) (net.Conn, string, error) {
	var lastErr error
	for _, ip := range ips {
		if !config.AllowPrivateIP && isPrivateIP(ip) {
			continue
		}
		targetAddr := net.JoinHostPort(ip, port)
		conn, err := net.DialTimeout("tcp", targetAddr, defaultDialTimeout)
		if err == nil {
			return conn, targetAddr, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no valid or allowed destination IP address")
	}
	return nil, "", lastErr
}

// Xử lý HTTPS TUNNEL (Hỗ trợ IPv6 First + Fallback IPv4 kèm chống kiểm duyệt SNI)
// Handle HTTPS Tunnel (Supporting IPv6 First + IPv4 Fallback with SNI fragmentation)
func handleConnectDirect(clientConn net.Conn, rawTarget string) {
	hostname, port, err := net.SplitHostPort(rawTarget)
	if err != nil {
		hostname = rawTarget
		port = "443"
	}

	targetIPs, err := resolveDomainPriority(hostname)
	if err != nil || len(targetIPs) == 0 {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	destConn, connectedAddr, err := dialWithFallback(targetIPs, port)
	if err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer destConn.Close()

	if tcpConn, ok := destConn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	if config.LogShow {
		log.Printf("[HTTP CONNECT] Established connection to %s (%s)\n", rawTarget, connectedAddr)
	}

	buf1 := bufferPool.Get().([]byte)
	buf2 := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf1)
	defer bufferPool.Put(buf2)

	clientConn.SetReadDeadline(time.Time{})
	destConn.SetReadDeadline(time.Time{})

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[RECOVER] Panic in CONNECT copy client->dest: %v\n", r)
			}
		}()
		io.CopyBuffer(clientConn, destConn, buf1)
	}()

	clientBuf := bufferPool.Get().([]byte)
	defer bufferPool.Put(clientBuf)

	clientConn.SetReadDeadline(time.Now().Add(config.ReadTimeout))
	n, err := clientConn.Read(clientBuf)
	clientConn.SetReadDeadline(time.Time{})
	if err != nil {
		return
	}

	// Phân mảnh gói tin TLS Client Hello (0x16) để chống DPI / SNI blocking
	// Fragment TLS Client Hello packet (0x16) to bypass DPI / SNI blocking
	if n > 5 && clientBuf[0] == 0x16 {
		splitPos := 2 + rand.Intn(4)

		_, err = destConn.Write(clientBuf[:splitPos])
		if err != nil {
			return
		}

		randomSleep := time.Duration(5+rand.Intn(21)) * time.Millisecond
		time.Sleep(randomSleep)

		_, err = destConn.Write(clientBuf[splitPos:n])
		if err != nil {
			return
		}
	} else {
		_, err = destConn.Write(clientBuf[:n])
		if err != nil {
			return
		}
	}

	io.CopyBuffer(destConn, clientConn, buf2)
}

// Xử lý HTTP request thông thường thông qua Transport chung
// Handle standard HTTP request via shared Transport
func handleHTTPDirect(clientConn net.Conn, req *http.Request) {
	req.RequestURI = ""
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}

	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")
	req.Close = true

	resp, err := httpTransport.RoundTrip(req)
	if err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer resp.Body.Close()

	resp.Close = true
	resp.Write(clientConn)
}

// Xử lý giao thức SOCKS5 trực tiếp (hỗ trợ cả TCP Stream và UDP Associate)
// Handle SOCKS5 protocol directly (supporting both TCP Stream and UDP Associate)
func handleSocks5Direct(clientConn net.Conn) {
	defer clientConn.Close()

	if config.LogShow {
		log.Printf("[SOCKS5] New connection from %s\n", clientConn.RemoteAddr())
	}

	verBuf := make([]byte, 1)
	if _, err := io.ReadFull(clientConn, verBuf); err != nil {
		return
	}
	if verBuf[0] != 0x05 {
		return
	}

	nmethodsBuf := make([]byte, 1)
	if _, err := io.ReadFull(clientConn, nmethodsBuf); err != nil {
		return
	}
	nmethods := int(nmethodsBuf[0])

	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(clientConn, methods); err != nil {
		return
	}

	_, err := clientConn.Write([]byte{0x05, 0x00})
	if err != nil {
		return
	}

	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(clientConn, reqHeader); err != nil {
		return
	}

	ver := reqHeader[0]
	cmd := reqHeader[1]
	atyp := reqHeader[3]

	if ver != 0x05 {
		return
	}

	if cmd != 0x01 && cmd != 0x03 {
		clientConn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var host string
	switch atyp {
	case 0x01: // IPv4
		ipBuf := make([]byte, 4)
		if _, err := io.ReadFull(clientConn, ipBuf); err != nil {
			return
		}
		host = net.IP(ipBuf).String()

	case 0x03: // Domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(clientConn, lenBuf); err != nil {
			return
		}
		domainLen := int(lenBuf[0])
		domainBuf := make([]byte, domainLen)
		if _, err := io.ReadFull(clientConn, domainBuf); err != nil {
			return
		}
		host = string(domainBuf)

	case 0x04: // IPv6
		ipBuf := make([]byte, 16)
		if _, err := io.ReadFull(clientConn, ipBuf); err != nil {
			return
		}
		host = net.IP(ipBuf).String()

	default:
		clientConn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, portBuf); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf)
	portStr := fmt.Sprintf("%d", port)

	if cmd == 0x03 {
		handleSocks5UDP(clientConn, clientConn.RemoteAddr())
		return
	}

	// --- NHÁNH XỬ LÝ TCP (CMD = 0x01) ---
	// --- TCP HANDLING BRANCH (CMD = 0x01) ---
	targetIPs, err := resolveDomainPriority(host)
	if err != nil || len(targetIPs) == 0 {
		if config.LogShow {
			log.Printf("[SOCKS5 ERROR] DNS resolution failed for %s: %v\n", host, err)
		}
		clientConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	destConn, targetAddr, err := dialWithFallback(targetIPs, portStr)
	if err != nil {
		if config.LogShow {
			log.Printf("[SOCKS5 ERROR] Connect to %s failed: %v\n", host, err)
		}
		clientConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer destConn.Close()

	if tcpConn, ok := destConn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	reply := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := clientConn.Write(reply); err != nil {
		return
	}

	if config.LogShow {
		log.Printf("[SOCKS5 CONNECT] Established TCP connection to %s (%s)\n", host, targetAddr)
	}

	clientConn.SetReadDeadline(time.Time{})
	destConn.SetReadDeadline(time.Time{})

	buf1 := bufferPool.Get().([]byte)
	buf2 := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf1)
	defer bufferPool.Put(buf2)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[RECOVER] Panic in SOCKS5 TCP copy: %v\n", r)
			}
		}()
		io.CopyBuffer(clientConn, destConn, buf1)
	}()

	clientBuf := bufferPool.Get().([]byte)
	defer bufferPool.Put(clientBuf)

	clientConn.SetReadDeadline(time.Now().Add(config.ReadTimeout))
	n, err := clientConn.Read(clientBuf)
	clientConn.SetReadDeadline(time.Time{})
	if err != nil {
		return
	}

	if n > 5 && clientBuf[0] == 0x16 {
		splitPos := 2 + rand.Intn(4)

		_, err = destConn.Write(clientBuf[:splitPos])
		if err != nil {
			return
		}

		randomSleep := time.Duration(5+rand.Intn(21)) * time.Millisecond
		time.Sleep(randomSleep)

		_, err = destConn.Write(clientBuf[splitPos:n])
		if err != nil {
			return
		}
	} else {
		_, err = destConn.Write(clientBuf[:n])
		if err != nil {
			return
		}
	}

	io.CopyBuffer(destConn, clientConn, buf2)
}

// Xử lý gói tin UDP Relay cho SOCKS5 (UDP Associate)
// Handle SOCKS5 UDP Relay (UDP Associate)
func handleSocks5UDP(clientConn net.Conn, clientRemoteAddr net.Addr) {
	clientTCPHost, _, err := net.SplitHostPort(clientRemoteAddr.String())
	if err != nil {
		clientTCPHost = clientRemoteAddr.String()
	}

	listenHost := "127.0.0.1"
	if h, _, err := net.SplitHostPort(config.ListenAddress); err == nil && h != "" && h != "0.0.0.0" {
		listenHost = h
	}

	networkType := "udp4"
	if strings.Contains(listenHost, ":") && !strings.HasPrefix(listenHost, "[") {
		networkType = "udp6"
	}

	udpListener, err := net.ListenUDP(networkType, &net.UDPAddr{IP: net.ParseIP(strings.Trim(listenHost, "[]")), Port: 0})
	if err != nil {
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer udpListener.Close()

	localAddr := udpListener.LocalAddr().(*net.UDPAddr)
	serverIP := localAddr.IP

	reply := make([]byte, 10)
	reply[0] = 0x05
	reply[1] = 0x00
	reply[2] = 0x00
	if serverIP.To4() != nil {
		reply[3] = 0x01
		reply = append(reply[:4], serverIP.To4()...)
	} else {
		reply[3] = 0x04
		reply = append(reply[:4], serverIP.To16()...)
	}
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(localAddr.Port))
	reply = append(reply, portBytes...)

	if _, err := clientConn.Write(reply); err != nil {
		return
	}

	if config.LogShow {
		log.Printf("[SOCKS5 UDP] Associate established on %s, relay listening on port %d\n", listenHost, localAddr.Port)
	}

	udpConns := make(map[string]*net.UDPConn)
	var udpConnsMutex sync.Mutex
	defer func() {
		udpConnsMutex.Lock()
		for _, c := range udpConns {
			c.Close()
		}
		udpConnsMutex.Unlock()
	}()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[RECOVER] Panic in SOCKS5 UDP listener cleanup: %v\n", r)
			}
		}()
		io.Copy(io.Discard, clientConn)
		udpListener.Close()
	}()

	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)
	var clientUDPAddr *net.UDPAddr

	for {
		udpListener.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, remoteAddr, err := udpListener.ReadFromUDP(buf)
		if err != nil {
			break
		}

		senderHost := remoteAddr.IP.String()
		if senderHost != clientTCPHost {
			continue
		}

		if clientUDPAddr == nil {
			clientUDPAddr = remoteAddr
		}

		if n < 10 {
			continue
		}

		if buf[2] != 0x00 {
			continue
		}

		atyp := buf[3]
		var targetHost string
		var headerLen int

		switch atyp {
		case 0x01:
			if n < 10 {
				continue
			}
			targetHost = net.IP(buf[4:8]).String()
			headerLen = 4 + 4 + 2
		case 0x03:
			domainLen := int(buf[4])
			if n < 5+domainLen+2 {
				continue
			}
			targetHost = string(buf[5 : 5+domainLen])
			headerLen = 4 + 1 + domainLen + 2
		case 0x04:
			if n < 22 {
				continue
			}
			targetHost = net.IP(buf[4:20]).String()
			headerLen = 4 + 16 + 2
		default:
			continue
		}

		destPort := binary.BigEndian.Uint16(buf[headerLen-2 : headerLen])
		payload := buf[headerLen:n]

		resolvedIPs, err := resolveDomainPriority(targetHost)
		if err != nil || len(resolvedIPs) == 0 {
			continue
		}

		var selectedIP string
		for _, ip := range resolvedIPs {
			if config.AllowPrivateIP || !isPrivateIP(ip) {
				selectedIP = ip
				break
			}
		}
		if selectedIP == "" {
			continue
		}

		destUDPAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(selectedIP, fmt.Sprintf("%d", destPort)))
		if err != nil {
			continue
		}

		destKey := destUDPAddr.String()

		udpConnsMutex.Lock()
		outConn, exists := udpConns[destKey]
		if !exists {
			outConn, err = net.DialUDP("udp", nil, destUDPAddr)
			if err != nil {
				udpConnsMutex.Unlock()
				continue
			}
			udpConns[destKey] = outConn

			go func(targetConn *net.UDPConn, targetKey string) {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("[RECOVER] Panic in UDP target reader worker: %v\n", r)
					}
					targetConn.Close()
					udpConnsMutex.Lock()
					delete(udpConns, targetKey)
					udpConnsMutex.Unlock()
				}()

				respBuf := bufferPool.Get().([]byte)
				defer bufferPool.Put(respBuf)

				for {
					targetConn.SetReadDeadline(time.Now().Add(30 * time.Second))
					rn, rAddr, rerr := targetConn.ReadFromUDP(respBuf)
					if rerr != nil || rn <= 0 {
						break
					}

					var header []byte
					if rAddr != nil {
						if ip4 := rAddr.IP.To4(); ip4 != nil {
							header = []byte{0x00, 0x00, 0x00, 0x01}
							header = append(header, ip4...)
						} else {
							header = []byte{0x00, 0x00, 0x00, 0x04}
							header = append(header, rAddr.IP.To16()...)
						}
						portBuf := make([]byte, 2)
						binary.BigEndian.PutUint16(portBuf, uint16(rAddr.Port))
						header = append(header, portBuf...)
					} else {
						continue
					}

					responseDatagram := append(header, respBuf[:rn]...)
					if clientUDPAddr != nil {
						udpListener.WriteToUDP(responseDatagram, clientUDPAddr)
					}
				}
			}(outConn, destKey)
		}
		udpConnsMutex.Unlock()

		outConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		_, err = outConn.Write(payload)
		if err != nil {
			outConn.Close()
			udpConnsMutex.Lock()
			delete(udpConns, destKey)
			udpConnsMutex.Unlock()
			continue
		}
	}
}

// Phân giải IP ưu tiên (Trả về danh sách IPs với IPv6 đứng đầu, IPv4 đứng sau làm dự phòng, có hỗ trợ Cache)
// Resolve IP by priority (Returns slice of IPs with IPv6 first, IPv4 as fallback, with Cache support)
func resolveDomainPriority(domain string) ([]string, error) {
	if net.ParseIP(domain) != nil {
		return []string{domain}, nil
	}

	if config.DNSCache {
		dnsCacheMutex.Lock()
		if item, found := dnsCacheStore[domain]; found {
			if time.Now().Before(item.ExpireTime) {
				dnsCacheMutex.Unlock()
				if config.LogShow {
					log.Printf("[DNS CACHE HIT] Resolved %s -> [%s] from cache\n", domain, strings.Join(item.IPs, " "))
				}
				return item.IPs, nil
			} else {
				currentCacheSize -= item.Size
				delete(dnsCacheStore, domain)
			}
		}
		dnsCacheMutex.Unlock()
	}

	ips, err := resolveDomainActual(domain)
	if err != nil || len(ips) == 0 {
		return nil, err
	}

	if config.DNSCache {
		dnsCacheMutex.Lock()

		if oldItem, exists := dnsCacheStore[domain]; exists {
			currentCacheSize -= oldItem.Size
			delete(dnsCacheStore, domain)
		}

		totalLen := len(domain) + 32
		for _, ip := range ips {
			totalLen += len(ip)
		}
		itemSize := int64(totalLen)

		for k, v := range dnsCacheStore {
			if time.Now().After(v.ExpireTime) {
				currentCacheSize -= v.Size
				delete(dnsCacheStore, k)
			}
		}

		if config.DNSCacheSize > 0 && (currentCacheSize+itemSize) <= config.DNSCacheSize {
			dnsCacheStore[domain] = DNSCacheItem{
				IPs:        ips,
				ExpireTime: time.Now().Add(config.DNSCacheExp),
				Size:       itemSize,
			}
			currentCacheSize += itemSize
			if config.LogShow {
				log.Printf("[DNS CACHE STORE] Cached %s -> [%s] (Exp: %v)\n", domain, strings.Join(ips, " "), config.DNSCacheExp)
			}
		}
		dnsCacheMutex.Unlock()
	}

	return ips, nil
}

// Thực hiện phân giải DNS thực tế qua các kênh (DoH -> DoT -> Direct UDP -> Fallback UDP)
// Actual DNS resolution through channels (DoH -> DoT -> Direct UDP -> Fallback UDP)
func resolveDomainActual(domain string) ([]string, error) {
	if config.DNSDOH != "" {
		if ips, err := queryDoH(config.DNSDOH, domain); err == nil && len(ips) > 0 {
			if config.LogShow {
				log.Printf("[DNS SUCCESS] Resolved %s -> [%s] via DoH (%s)\n", domain, strings.Join(ips, " "), config.DNSDOH)
			}
			return ips, nil
		}
	}

	if config.DNSDOT != "" {
		if ips, err := queryDoT(config.DNSDOT, domain); err == nil && len(ips) > 0 {
			if config.LogShow {
				log.Printf("[DNS SUCCESS] Resolved %s -> [%s] via DoT (%s)\n", domain, strings.Join(ips, " "), config.DNSDOT)
			}
			return ips, nil
		}
	}

	if config.DNSIP != "" {
		if ips, err := queryUDP(config.DNSIP, domain); err == nil && len(ips) > 0 {
			if config.LogShow {
				log.Printf("[DNS SUCCESS] Resolved %s -> [%s] via Direct UDP (%s)\n", domain, strings.Join(ips, " "), config.DNSIP)
			}
			return ips, nil
		}
	}

	if config.DNSFallback != "" {
		if ips, err := queryUDP(config.DNSFallback, domain); err == nil && len(ips) > 0 {
			if config.LogShow {
				log.Printf("[DNS SUCCESS] Resolved %s -> [%s] via Fallback UDP (%s)\n", domain, strings.Join(ips, " "), config.DNSFallback)
			}
			return ips, nil
		}
	}

	return nil, fmt.Errorf("unable to resolve domain %s using all configured DNS servers", domain)
}

// Kiểm tra sức khỏe DNS hệ thống và in kết quả ra log
// Check system DNS health and print results to log
func runClientDNSHealthCheckWithInternal(domain string) {
	directIPOk := false
	fallbackOk := false
	dohOk := false
	dotOk := false

	if config.DNSIP != "" {
		if ips, err := queryUDP(config.DNSIP, domain); err == nil && len(ips) > 0 {
			directIPOk = true
		}
	}

	if config.DNSFallback != "" {
		if ips, err := queryUDP(config.DNSFallback, domain); err == nil && len(ips) > 0 {
			fallbackOk = true
		}
	}

	if config.DNSDOH != "" {
		if ips, err := queryDoH(config.DNSDOH, domain); err == nil && len(ips) > 0 {
			dohOk = true
		}
	}

	if config.DNSDOT != "" {
		if ips, err := queryDoT(config.DNSDOT, domain); err == nil && len(ips) > 0 {
			dotOk = true
		}
	}

	fmt.Println("DNS Priority Order for Client:")

	if config.DNSDOH != "" {
		if dohOk {
			fmt.Printf("- DoH (%s): OK\n", config.DNSDOH)
		} else {
			fmt.Printf("- DoH (%s): FAILED\n", config.DNSDOH)
		}
	} else {
		fmt.Println("- DoH: NOT CONFIGURED")
	}

	if config.DNSDOT != "" {
		if dotOk {
			fmt.Printf("- DoT (%s): OK\n", config.DNSDOT)
		} else {
			fmt.Printf("- DoT (%s): FAILED\n", config.DNSDOT)
		}
	} else {
		fmt.Println("- DoT: NOT CONFIGURED")
	}

	if config.DNSIP != "" {
		if directIPOk {
			fmt.Printf("- Direct IP (%s): OK\n", config.DNSIP)
		} else {
			fmt.Printf("- Direct IP (%s): FAILED\n", config.DNSIP)
		}
	} else {
		fmt.Println("- Direct IP: NOT CONFIGURED")
	}

	if config.DNSFallback != "" {
		if fallbackOk {
			fmt.Printf("- Fallback (%s): OK\n", config.DNSFallback)
		} else {
			fmt.Printf("- Fallback (%s): FAILED\n", config.DNSFallback)
		}
	} else {
		fmt.Println("- Fallback: NOT CONFIGURED")
	}
}

// Truy vấn DNS qua DoH (DNS-over-HTTPS) đồng thời cả A (IPv4) và AAAA (IPv6), ưu tiên IPv6 trước
// Query DNS via DoH (DNS-over-HTTPS) concurrently for A (IPv4) and AAAA (IPv6), prioritizing IPv6
func queryDoH(dohURL, domain string) ([]string, error) {
	var wg sync.WaitGroup
	var v4Res, v6Res []string
	var idV4, idV6 uint16
	var errV4, errV6 error

	qV4, idV4 := buildDNSQueryWithType(domain, 1)  // Type 1 = A (IPv4)
	qV6, idV6 := buildDNSQueryWithType(domain, 28) // Type 28 = AAAA (IPv6)

	wg.Add(2)
	go func() {
		defer wg.Done()
		v6Res, errV6 = executeDoHRequest(dohURL, qV6, idV6)
	}()
	go func() {
		defer wg.Done()
		v4Res, errV4 = executeDoHRequest(dohURL, qV4, idV4)
	}()
	wg.Wait()

	// Xếp IPv6 lên đầu, IPv4 nối phía sau làm dự phòng
	// Append IPv6 first, IPv4 following as fallback
	var finalIPs []string
	if errV6 == nil {
		finalIPs = append(finalIPs, v6Res...)
	}
	if errV4 == nil {
		finalIPs = append(finalIPs, v4Res...)
	}

	if len(finalIPs) > 0 {
		return finalIPs, nil
	}
	return nil, fmt.Errorf("DoH resolution failed for both IPv4 and IPv6")
}

func executeDoHRequest(dohURL string, query []byte, expectedID uint16) ([]string, error) {
	req, err := http.NewRequest("POST", dohURL, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return parseDNSResponse(body, expectedID)
}

// Truy vấn DNS qua DoT (DNS-over-TLS) song song IPv4 và IPv6, ưu tiên IPv6 trước
// Query DNS via DoT (DNS-over-TLS) concurrently for IPv4 and IPv6, prioritizing IPv6
func queryDoT(dotHost, domain string) ([]string, error) {
	var wg sync.WaitGroup
	var v4Res, v6Res []string
	var errV4, errV6 error

	qV4, idV4 := buildDNSQueryWithType(domain, 1)  // A
	qV6, idV6 := buildDNSQueryWithType(domain, 28) // AAAA

	wg.Add(2)
	go func() {
		defer wg.Done()
		v6Res, errV6 = executeDoTRequest(dotHost, qV6, idV6)
	}()
	go func() {
		defer wg.Done()
		v4Res, errV4 = executeDoTRequest(dotHost, qV4, idV4)
	}()
	wg.Wait()

	var finalIPs []string
	if errV6 == nil {
		finalIPs = append(finalIPs, v6Res...)
	}
	if errV4 == nil {
		finalIPs = append(finalIPs, v4Res...)
	}

	if len(finalIPs) > 0 {
		return finalIPs, nil
	}
	return nil, fmt.Errorf("DoT resolution failed for both IPv4 and IPv6")
}

func executeDoTRequest(dotHost string, query []byte, expectedID uint16) ([]string, error) {
	targetHost := dotHost
	if !strings.Contains(targetHost, ":") {
		targetHost = targetHost + ":853"
	}

	serverName := strings.Split(dotHost, ":")[0]
	tlsConfig := &tls.Config{ServerName: serverName}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", targetHost, tlsConfig)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	lengthBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthBuf, uint16(len(query)))

	if _, err := conn.Write(append(lengthBuf, query...)); err != nil {
		return nil, err
	}

	respLenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, respLenBuf); err != nil {
		return nil, err
	}
	respLen := binary.BigEndian.Uint16(respLenBuf)

	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		return nil, err
	}

	return parseDNSResponse(respBuf, expectedID)
}

// Truy vấn DNS qua UDP trực tiếp song song IPv4 và IPv6 với defaultDNSTimeout, ưu tiên IPv6 trước
// Query DNS via direct UDP concurrently for IPv4 and IPv6 with defaultDNSTimeout, prioritizing IPv6
func queryUDP(dnsServer, domain string) ([]string, error) {
	var wg sync.WaitGroup
	var v4Res, v6Res []string
	var errV4, errV6 error

	qV4, idV4 := buildDNSQueryWithType(domain, 1)  // A
	qV6, idV6 := buildDNSQueryWithType(domain, 28) // AAAA

	wg.Add(2)
	go func() {
		defer wg.Done()
		v6Res, errV6 = executeUDPRequest(dnsServer, qV6, idV6)
	}()
	go func() {
		defer wg.Done()
		v4Res, errV4 = executeUDPRequest(dnsServer, qV4, idV4)
	}()
	wg.Wait()

	var finalIPs []string
	if errV6 == nil {
		finalIPs = append(finalIPs, v6Res...)
	}
	if errV4 == nil {
		finalIPs = append(finalIPs, v4Res...)
	}

	if len(finalIPs) > 0 {
		return finalIPs, nil
	}
	return nil, fmt.Errorf("UDP DNS resolution failed for both IPv4 and IPv6")
}

func executeUDPRequest(dnsServer string, query []byte, expectedID uint16) ([]string, error) {
	serverAddr := dnsServer
	if !strings.Contains(serverAddr, ":") {
		serverAddr = serverAddr + ":53"
	}

	conn, err := net.DialTimeout("udp", serverAddr, defaultDNSTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	respBuf := make([]byte, 512)
	conn.SetReadDeadline(time.Now().Add(defaultDNSTimeout))
	n, err := conn.Read(respBuf)
	if err != nil {
		return nil, err
	}

	return parseDNSResponse(respBuf[:n], expectedID)
}

// Hàm dựng gói tin DNS linh hoạt theo Type (1: IPv4 A, 28: IPv6 AAAA)
// Flexible DNS query builder by record type (1: IPv4 A, 28: IPv6 AAAA)
func buildDNSQueryWithType(domain string, qtype uint16) ([]byte, uint16) {
	var buf bytes.Buffer

	var idBytes [2]byte
	_, _ = crypto_rand.Read(idBytes[:])
	id := binary.BigEndian.Uint16(idBytes[:])

	binary.Write(&buf, binary.BigEndian, id)
	binary.Write(&buf, binary.BigEndian, uint16(0x0100))
	binary.Write(&buf, binary.BigEndian, uint16(1))
	binary.Write(&buf, binary.BigEndian, uint16(0))
	binary.Write(&buf, binary.BigEndian, uint16(0))
	binary.Write(&buf, binary.BigEndian, uint16(0))

	parts := strings.Split(domain, ".")
	for _, part := range parts {
		buf.WriteByte(byte(len(part)))
		buf.WriteString(part)
	}
	buf.WriteByte(0)

	binary.Write(&buf, binary.BigEndian, qtype)      // QTYPE
	binary.Write(&buf, binary.BigEndian, uint16(1)) // QCLASS = IN

	return buf.Bytes(), id
}

// Bóc tách toàn bộ danh sách IP từ phản hồi DNS (Sắp xếp IPv6 đứng trước, IPv4 đứng sau làm dự phòng)
// Parse all IP addresses from DNS response (Arranging IPv6 first, IPv4 after as fallback)
func parseDNSResponse(data []byte, expectedID uint16) ([]string, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("response too short")
	}

	respID := binary.BigEndian.Uint16(data[0:2])
	if respID != expectedID {
		return nil, fmt.Errorf("DNS transaction ID mismatch")
	}

	ancount := binary.BigEndian.Uint16(data[6:8])
	if ancount == 0 {
		return nil, fmt.Errorf("no answers found in DNS response")
	}

	offset := 12
	for {
		if offset >= len(data) {
			return nil, fmt.Errorf("malformed DNS question")
		}
		if data[offset] == 0 {
			offset += 1
			break
		}
		if data[offset]&0xC0 == 0xC0 {
			offset += 2
			break
		}
		length := int(data[offset])
		if offset+1+length >= len(data) {
			return nil, fmt.Errorf("DNS label out of bounds")
		}
		offset += length + 1
	}

	if offset+4 > len(data) {
		return nil, fmt.Errorf("DNS footer out of bounds")
	}
	offset += 4

	var ipv6List []string
	var ipv4List []string

	for i := 0; i < int(ancount); i++ {
		if offset >= len(data) {
			break
		}

		if data[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for {
				if offset >= len(data) {
					return nil, fmt.Errorf("DNS name out of bounds")
				}
				if data[offset] == 0 {
					offset++
					break
				}
				if data[offset]&0xC0 == 0xC0 {
					offset += 2
					break
				}
				length := int(data[offset])
				if offset+1+length >= len(data) {
					return nil, fmt.Errorf("DNS label out of bounds")
				}
				offset += length + 1
			}
		}

		if offset+10 > len(data) {
			return nil, fmt.Errorf("DNS header out of bounds")
		}

		qtype := binary.BigEndian.Uint16(data[offset : offset+2])
		rdlength := binary.BigEndian.Uint16(data[offset+8 : offset+10])
		offset += 10

		if offset+int(rdlength) > len(data) {
			return nil, fmt.Errorf("DNS RDATA out of bounds")
		}

		if qtype == 28 && rdlength == 16 {
			ip := net.IP(data[offset : offset+16])
			ipv6List = append(ipv6List, ip.String())
		}

		if qtype == 1 && rdlength == 4 {
			ip := net.IP(data[offset : offset+4])
			ipv4List = append(ipv4List, ip.String())
		}

		offset += int(rdlength)
	}

	// Đưa IPv6 lên trước, IPv4 theo sau làm dự phòng
	// Put IPv6 first, IPv4 following as fallback
	resultIPs := append(ipv6List, ipv4List...)
	if len(resultIPs) > 0 {
		return resultIPs, nil
	}

	return nil, fmt.Errorf("no usable IP address found")
}

// Tải cấu hình từ tệp tin (sử dụng dấu bằng '=' cho config)
// Load configuration from file (using '=' for config key-value pairs)
func loadConfig(filepath string) {
	config = Config{
		LogShow:         false,
		ListenAddress:   "127.0.0.1:3979",
		ReadTimeout:     10 * time.Second,
		WriteTimeout:    10 * time.Second,
		IdleTimeout:     10 * time.Second,
		ClientTimeout:   60 * time.Second,
		DNSFallback:     "208.67.222.222",
		DNSIP:           "8.8.8.8",
		DNSDOH:          "https://cloudflare-dns.com/dns-query",
		DNSDOT:          "1.1.1.1",
		DNSCache:        true,
		DNSCacheSize:    1024 * 1024,
		DNSCacheExp:     60 * time.Second,
		ClientAllowlist: "127.0.0.1; ::1",
		AllowPrivateIP:  false,
	}

	file, err := os.Open(filepath)
	if err != nil {
		fmt.Printf("The config file %s is missing, use default hard code.\n", filepath)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "logshow", "logShow":
			config.LogShow = strings.ToLower(val) == "yes" || strings.ToLower(val) == "true"
		case "listenAddress":
			config.ListenAddress = val
		case "readTimeout":
			config.ReadTimeout = parseDuration(val)
		case "writeTimeout":
			config.WriteTimeout = parseDuration(val)
		case "idleTimeout":
			config.IdleTimeout = parseDuration(val)
		case "clientTimeout":
			config.ClientTimeout = parseDuration(val)
		case "dnsFallback":
			config.DNSFallback = val
		case "dnsIP":
			config.DNSIP = val
		case "dnsDOH":
			config.DNSDOH = val
		case "dnsDOT":
			config.DNSDOT = val
		case "dnsCache":
			config.DNSCache = strings.ToLower(val) == "yes" || strings.ToLower(val) == "true"
		case "dnsCacheSize":
			config.DNSCacheSize = parseCacheSize(val)
		case "dnsCacheExp":
			config.DNSCacheExp = parseDuration(val)
		case "clientAllowlist":
			config.ClientAllowlist = val
		case "allowPrivateIP":
			config.AllowPrivateIP = strings.ToLower(val) == "yes" || strings.ToLower(val) == "true"
		}
	}
}

// Chuyển đổi dung lượng cache (VD: 1MB, 512KB) sang định dạng bytes
// Convert cache size string (e.g., 1MB, 512KB) into bytes
func parseCacheSize(s string) int64 {
	s = strings.ToUpper(strings.TrimSpace(s))
	var multiplier int64 = 1
	if strings.HasSuffix(s, "KB") {
		multiplier = 1024
		s = strings.TrimSuffix(s, "KB")
	} else if strings.HasSuffix(s, "MB") {
		multiplier = 1024 * 1024
		s = strings.TrimSuffix(s, "MB")
	} else if strings.HasSuffix(s, "GB") {
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, "GB")
	} else if strings.HasSuffix(s, "B") {
		s = strings.TrimSuffix(s, "B")
	}

	var size int64
	fmt.Sscanf(s, "%d", &size)
	if size == 0 {
		return 1024 * 1024
	}
	return size * multiplier
}

// Chuyển đổi chuỗi thời gian thành time.Duration
// Convert time string to time.Duration
func parseDuration(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 10 * time.Second
	}
	return d
}
