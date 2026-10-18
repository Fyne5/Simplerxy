package main

import (
	"bufio"
	"bytes"
	"context"
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

// Định dạng nội dung cấu hình cho config.conf
// Configuration content format for config.conf
type Config struct {
	LogShow            bool
	ListenAddress      string
	ReadTimeout        time.Duration
	WriteTimeout       time.Duration
	IdleTimeout        time.Duration
	ProxyClientTimeout time.Duration
	DNSFallback        string
	DNSIP              string
	DNSDOH             string
	DNSDOT             string
	DNSCache           bool
	DNSCacheSize       int64 // Lưu trữ dung lượng dưới dạng bytes
	DNSCacheExp        time.Duration
}

// Cấu trúc lưu trữ bản ghi DNS Cache
// DNS Cache record structure
type DNSCacheItem struct {
	IP         string
	ExpireTime time.Time
	Size       int64
}

var (
	// Bộ nhớ cache DNS toàn cục
	// Global DNS cache storage
	dnsCacheStore     = make(map[string]DNSCacheItem)
	dnsCacheMutex     sync.RWMutex
	currentCacheSize int64
)

// Lấy giá trị ở trên (tên Config) gán vào biến toàn cục
// Assign the value from above (Config name) to the global variable
var config Config

func main() {
	// Lấy các giá trị từ config.conf
	// Get values from config.conf
	loadConfig("config.conf")

	// Lắng nghe TCP trên ListenAddress để hỗ trợ đồng thời cả HTTP Proxy và SOCKS5 Proxy
	// Listen on TCP to support both HTTP Proxy and SOCKS5 Proxy simultaneously
	listener, err := net.Listen("tcp", config.ListenAddress)
	if err != nil {
		log.Fatalf("Can not start the server: %v", err)
	}
	defer listener.Close()

	log.Printf("Proxy (HTTP & SOCKS5 TCP/UDP) is running at: %s\n", config.ListenAddress)
	log.Printf("Log show status: %v\n", config.LogShow)
	log.Printf("DNS Cache status: %v (Size limit: %d bytes, Expire: %v)\n", config.DNSCache, config.DNSCacheSize, config.DNSCacheExp)

	// Thực hiện kiểm tra ngầm nội bộ theo thứ tự: Direct IP -> Fallback -> DoH -> DoT, sau đó show client ra log
	// Perform silent internal checks in order: Direct IP -> Fallback -> DoH -> DoT, then display client results
	runClientDNSHealthCheckWithInternal("google.com")

	// Vòng lặp chấp nhận kết nối từ client
	// Accept incoming connections loop
	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}

		go handleIncomingConnection(conn)
	}
}

// Bộ đọc hỗ trợ tính năng Peek (đọc trước byte đầu tiên mà không làm mất dữ liệu của stream)
// Reader supporting Peek feature (previewing the first byte without consuming stream data)
type peekReaderConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *peekReaderConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

// Phân luồng kết nối dựa trên byte đầu tiên (SOCKS5 bắt đầu bằng 0x05)
// Dispatch connection based on the first byte (SOCKS5 starts with 0x05)
func handleIncomingConnection(clientConn net.Conn) {
	reader := bufio.NewReader(clientConn)
	firstByte, err := reader.Peek(1)
	if err != nil {
		clientConn.Close()
		return
	}

	peeledConn := &peekReaderConn{
		Conn:   clientConn,
		reader: reader,
	}

	if firstByte[0] == 0x05 {
		// Nhánh xử lý SOCKS5 Proxy
		// Handle SOCKS5 Proxy branch
		go handleSocks5Direct(peeledConn)
	} else {
		// Nhánh xử lý HTTP / HTTPS Proxy
		// Handle HTTP / HTTPS Proxy branch
		go handleHTTPProxyDirect(peeledConn, reader)
	}
}

// Xử lý trực tiếp HTTP Proxy (cả CONNECT tunnel và HTTP thông thường)
// Handle HTTP Proxy directly (both CONNECT tunnel and standard HTTP)
func handleHTTPProxyDirect(clientConn net.Conn, reader *bufio.Reader) {
	defer clientConn.Close()

	reqLine, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	parts := strings.Fields(reqLine)
	if len(parts) < 2 {
		return
	}

	method := parts[0]
	rawTarget := parts[1]

	if method == "CONNECT" {
		handleConnectDirect(clientConn, reader, rawTarget)
	} else {
		handleHTTPDirect(clientConn, reader, method, rawTarget)
	}
}

// Xử lý HTTPS TUNNEL (Vượt chướng ngại vật SNI/DPI bằng phân mảnh TLS Client Hello)
// Handle HTTPS Tunnel (Bypass SNI/DPI restrictions via TLS Client Hello fragmentation)
func handleConnectDirect(clientConn net.Conn, reader *bufio.Reader, rawTarget string) {
	// Đọc và bỏ qua các header còn lại của request CONNECT
	// Read and discard remaining headers of the CONNECT request
	for {
		line, err := reader.ReadString('\n')
		gtLine := strings.TrimSpace(line)
		if err != nil || gtLine == "" {
			break
		}
	}

	hostname, port, err := net.SplitHostPort(rawTarget)
	if err != nil {
		hostname = rawTarget
		port = "443"
	}

	// Giải mã IP thông qua thứ tự ưu tiên DNS (DoH -> DoT -> DNSIP -> DNSFallback)
	// Resolve IP using priority order: DoH -> DoT -> DNSIP -> DNSFallback[cite: 2]
	targetIP, err := resolveDomainPriority(hostname)
	if err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	targetAddr := net.JoinHostPort(targetIP, port)

	// Kết nối tới server đích (chỉ IPv4)
	// Connect to the destination server (just IPv4)[cite: 2]
	destConn, err := net.DialTimeout("tcp4", targetAddr, 5*time.Second)
	if err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer destConn.Close()

	// Ép gửi gói tin TCP ngay lập tức (Tắt Nagle's Algorithm)
	// Disable Nagle's Algorithm to send TCP packets immediately[cite: 2]
	if tcpConn, ok := destConn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	// Phản hồi cho client biết đã kết nối thông suốt
	// Respond to the client to indicate a successful connection[cite: 2]
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	if config.LogShow {
		log.Printf("[HTTP CONNECT] Established connection to %s (%s)\n", rawTarget, targetAddr)
	}

	// 1. Chuyển dữ liệu từ server đích về lại client
	// 1. Transfer data from the destination server back to the client[cite: 2]
	go io.Copy(clientConn, destConn)

	// 2. Xử lý chiều từ client sang server đích để bẻ gãy gói tin SNI
	// 2. Handle the client-to-destination-server direction to break the SNI packet[cite: 2]
	buffer := make([]byte, 32*1024)
	n, err := clientConn.Read(buffer)
	if err != nil {
		return
	}

	// 0x16 đại diện cho TLS Handshake (Client Hello)
	// 0x16 represents the TLS Handshake (Client Hello)[cite: 2]
	if n > 5 && buffer[0] == 0x16 {
		// Vị trí cắt ngẫu nhiên an toàn trong khoảng 2 đến 5 byte đầu
		// Safe random split position within 2 to 5 bytes[cite: 2]
		splitPos := 2 + rand.Intn(4) // Trả về 2, 3, 4 hoặc 5[cite: 2]

		// Gửi mảnh đầu tiên
		// Send the first fragment[cite: 2]
		_, err = destConn.Write(buffer[:splitPos])
		if err != nil {
			return
		}

		// Ru ngủ với thời gian ngẫu nhiên từ 5 đến 25 ms
		// Sleep for a random duration between 5ms to 25ms[cite: 2]
		randomSleep := time.Duration(5+rand.Intn(21)) * time.Millisecond
		time.Sleep(randomSleep)

		// Gửi mảnh còn lại
		// Send the remaining fragment[cite: 2]
		_, err = destConn.Write(buffer[splitPos:n])
		if err != nil {
			return
		}
	} else {
		// Dữ liệu HTTP thường hoặc không phải TLS thì cho qua luôn
		// Pass through standard or non-TLS HTTP data immediately[cite: 2]
		_, err = destConn.Write(buffer[:n])
		if err != nil {
			return
		}
	}

	// 3. Khi xong cú bắt tay đầu tiên, chuyển tiếp các gói dữ liệu tiếp theo
	// 3. Upon completion of the initial handshake, forward subsequent data packets[cite: 2]
	io.Copy(destConn, clientConn)
}

// Xử lý HTTP Proxy thông thường trực tiếp
// Handle standard HTTP proxy requests directly
func handleHTTPDirect(clientConn net.Conn, reader *bufio.Reader, method, rawTarget string) {
	var targetURL string
	if strings.HasPrefix(rawTarget, "http://") {
		targetURL = rawTarget
	} else {
		targetURL = "http://" + rawTarget
	}

	req, err := http.NewRequest(method, targetURL, reader)
	if err != nil {
		return
	}

	for {
		line, err := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if err != nil || line == "" {
			break
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			if strings.EqualFold(key, "Host") {
				req.Host = val
			} else {
				req.Header.Set(key, val)
			}
		}
	}

	hostname := req.URL.Hostname()
	port := req.URL.Port()
	if port == "" {
		port = "80"
	}

	targetIP, err := resolveDomainPriority(hostname)
	if err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	targetAddr := net.JoinHostPort(targetIP, port)

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.DialTimeout("tcp4", targetAddr, 30*time.Second)
		},
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer resp.Body.Close()

	resp.Write(clientConn)
}

// Xử lý giao thức SOCKS5 trực tiếp (RFC 1928) tích hợp TCP và UDP Associate
// Handle SOCKS5 protocol directly (RFC 1928) integrated with TCP and UDP Associate
func handleSocks5Direct(clientConn net.Conn) {
	defer clientConn.Close()

	if config.LogShow {
		log.Printf("[SOCKS5] New connection from %s\n", clientConn.RemoteAddr())
	}

	// 1. Đọc byte phiên bản (VER) và số lượng phương thức xác thực (NMETHODS)
	// 1. Read version byte (VER) and number of authentication methods (NMETHODS)
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

	// 2. Phản hồi client: Chọn phương thức Không cần xác thực (0x00 - No Authentication Required)
	// 2. Respond to client: Choose No Authentication Required (0x00)[cite: 2]
	_, err := clientConn.Write([]byte{0x05, 0x00})
	if err != nil {
		return
	}

	// 3. Đọc yêu cầu kết nối từ client (Request)
	// 3. Read connection request from client[cite: 2]
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

	// Hỗ trợ cả TCP Stream (CMD 0x01) và UDP Associate (CMD 0x03)
	// Support both TCP Stream (CMD 0x01) and UDP Associate (CMD 0x03)
	if cmd != 0x01 && cmd != 0x03 {
		clientConn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Command not supported
		return
	}

	var host string
	switch atyp {
	case 0x01: // IPv4 address (4 bytes)
		ipBuf := make([]byte, 4)
		if _, err := io.ReadFull(clientConn, ipBuf); err != nil {
			return
		}
		host = net.IP(ipBuf).String()

	case 0x03: // Domain name (1 byte length + domain string)
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

	case 0x04: // IPv6 address (16 bytes)
		ipBuf := make([]byte, 16)
		if _, err := io.ReadFull(clientConn, ipBuf); err != nil {
			return
		}
		host = net.IP(ipBuf).String()

	default:
		clientConn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Address type not supported
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, portBuf); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf)
	portStr := fmt.Sprintf("%d", port)

	// Xử lý nhánh UDP ASSOCIATE (CMD = 0x03)
	// Handle UDP ASSOCIATE branch (CMD = 0x03)
	if cmd == 0x03 {
		handleSocks5UDP(clientConn)
		return
	}

	// --- NHÁNH XỬ LÝ TCP (CMD = 0x01) ---
	// --- TCP HANDLING BRANCH (CMD = 0x01) ---
	targetIP, err := resolveDomainPriority(host)
	if err != nil {
		if config.LogShow {
			log.Printf("[SOCKS5 ERROR] DNS resolution failed for %s: %v\n", host, err)
		}
		clientConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Host unreachable
		return
	}

	targetAddr := net.JoinHostPort(targetIP, portStr)

	destConn, err := net.DialTimeout("tcp4", targetAddr, 5*time.Second)
	if err != nil {
		if config.LogShow {
			log.Printf("[SOCKS5 ERROR] Connect to %s failed: %v\n", targetAddr, err)
		}
		clientConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Connection refused
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

	go io.Copy(clientConn, destConn)

	buffer := make([]byte, 32*1024)
	n, err := clientConn.Read(buffer)
	if err != nil {
		return
	}

	if n > 5 && buffer[0] == 0x16 {
		splitPos := 2 + rand.Intn(4)

		_, err = destConn.Write(buffer[:splitPos])
		if err != nil {
			return
		}

		randomSleep := time.Duration(5+rand.Intn(21)) * time.Millisecond
		time.Sleep(randomSleep)

		_, err = destConn.Write(buffer[splitPos:n])
		if err != nil {
			return
		}
	} else {
		_, err = destConn.Write(buffer[:n])
		if err != nil {
			return
		}
	}

	io.Copy(destConn, clientConn)
}

// Xử lý gói tin UDP Relay cho SOCKS5 (UDP Associate)
// Handle SOCKS5 UDP Relay (UDP Associate)
func handleSocks5UDP(clientConn net.Conn) {
	// Mở UDP listener ngẫu nhiên trên máy chủ để nhận gói tin chuyển tiếp từ client
	// Open a random UDP listener on the server to receive forwarded packets from the client
	udpListener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer udpListener.Close()

	localAddr := udpListener.LocalAddr().(*net.UDPAddr)
	serverIP := net.ParseIP("127.0.0.1")
	if host, _, err := net.SplitHostPort(config.ListenAddress); err == nil {
		if parsed := net.ParseIP(host); parsed != nil && !parsed.IsUnspecified() {
			serverIP = parsed
		}
	}

	// Phản hồi cho client biết cổng UDP Relay đã sẵn sàng
	// Respond to the client indicating that the UDP Relay port is ready
	reply := make([]byte, 10)
	reply[0] = 0x05 // VER
	reply[1] = 0x00 // REP (Success)
	reply[2] = 0x00 // RSV
	reply[3] = 0x01 // ATYP (IPv4)
	copy(reply[4:8], serverIP.To4())
	binary.BigEndian.PutUint16(reply[8:10], uint16(localAddr.Port))

	if _, err := clientConn.Write(reply); err != nil {
		return
	}

	if config.LogShow {
		log.Printf("[SOCKS5 UDP] Associate established, relay listening on port %d\n", localAddr.Port)
	}

	// Giữ kết nối TCP sống; khi client đóng kết nối TCP thì hủy UDP relay
	// Keep the TCP connection alive; when the client closes TCP, terminate the UDP relay
	go func() {
		io.Copy(io.Discard, clientConn)
		udpListener.Close()
	}()

	buf := make([]byte, 65535)
	var clientUDPAddr *net.UDPAddr

	for {
		n, remoteAddr, err := udpListener.ReadFromUDP(buf)
		if err != nil {
			break
		}
		if clientUDPAddr == nil {
			clientUDPAddr = remoteAddr
		}

		// Định dạng SOCKS5 UDP Datagram Header (RFC 1928):
		// +----+------+------+----------+----------+----------+
        // |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
        // +----+------+------+----------+----------+----------+
        // | 2  |  1   |  1   variable   |    2     | variable |
        // +----+------+------+----------+----------+----------+
		if n < 10 {
			continue
		}

		// Kiểm tra fragment (không hỗ trợ phân mảnh gói tin UDP nên bỏ qua nếu frag != 0)
		// Check fragment (fragmentation not supported, ignore if frag != 0)
		if buf[2] != 0x00 {
			continue
		}

		atyp := buf[3]
		var targetHost string
		var headerLen int

		switch atyp {
		case 0x01: // IPv4
			if n < 10 {
				continue
			}
			targetHost = net.IP(buf[4:8]).String()
			headerLen = 4 + 4 + 2
		case 0x03: // Domain
			domainLen := int(buf[4])
			if n < 5+domainLen+2 {
				continue
			}
			targetHost = string(buf[5 : 5+domainLen])
			headerLen = 4 + 1 + domainLen + 2
		case 0x04: // IPv6
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

		// Giải mã tên miền qua hệ thống DNS ưu tiên
		// Resolve domain via priority DNS system
		resolvedIP, err := resolveDomainPriority(targetHost)
		if err != nil {
			continue
		}

		destUDPAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(resolvedIP, fmt.Sprintf("%d", destPort)))
		if err != nil {
			continue
		}

		// Gửi gói tin đi đích qua UDP thực tế
		// Send the packet to the destination via actual UDP
		outConn, err := net.DialUDP("udp", nil, destUDPAddr)
		if err != nil {
			continue
		}

		_, err = outConn.Write(payload)
		if err != nil {
			outConn.Close()
			continue
		}

		// Đọc phản hồi từ đích và gói lại theo chuẩn SOCKS5 UDP để trả về client
		// Read response from destination and wrap it in SOCKS5 UDP standard to return to client
		go func(targetConn *net.UDPConn, originalHeader []byte, origHeaderLen int) {
			defer targetConn.Close()
			targetConn.SetReadDeadline(time.Now().Add(10 * time.Second))
			respBuf := make([]byte, 65535)
			rn, _, rerr := targetConn.ReadFrom(respBuf)
			if rerr != nil || rn <= 0 {
				return
			}

			// Đóng gói lại header SOCKS5 UDP ban đầu để gửi về client
			// Repackage original SOCKS5 UDP header to send back to client
			responseDatagram := append([]byte(nil), originalHeader[:origHeaderLen]...)
			responseDatagram = append(responseDatagram, respBuf[:rn]...)

			if clientUDPAddr != nil {
				udpListener.WriteToUDP(responseDatagram, clientUDPAddr)
			}
		}(outConn, buf[:headerLen], headerLen)
	}
}

// Hàm phân giải IP theo thứ tự ưu tiên: DoH -> DoT -> DNSIP -> DNSFallback (Có tích hợp DNS Cache)
// Resolve domain by priority with DNS Cache support[cite: 2]
func resolveDomainPriority(domain string) (string, error) {
	if net.ParseIP(domain) != nil {
		return domain, nil
	}

	// Kiểm tra DNS Cache nếu được bật
	// Check DNS Cache if enabled[cite: 2]
	if config.DNSCache {
		dnsCacheMutex.RLock()
		if item, found := dnsCacheStore[domain]; found {
			if time.Now().Before(item.ExpireTime) {
				dnsCacheMutex.RUnlock()
				if config.LogShow {
					log.Printf("[DNS CACHE HIT] Resolved %s -> %s from cache\n", domain, item.IP)
				}
				return item.IP, nil
			}
		}
		dnsCacheMutex.RUnlock()
	}

	// Thực hiện phân giải thực tế qua các kênh DNS
	// Perform actual resolution through DNS channels[cite: 2]
	ip, err := resolveDomainActual(domain)
	if err != nil {
		return "", err
	}

	// Lưu vào cache nếu được bật
	// Save to cache if enabled[cite: 2]
	if config.DNSCache && ip != "" {
		dnsCacheMutex.Lock()
		itemSize := int64(len(domain) + len(ip) + 32) // Ước tính dung lượng lưu trữ bản ghi / Estimate record size[cite: 2]

		if config.DNSCacheSize > 0 && (currentCacheSize+itemSize) <= config.DNSCacheSize {
			dnsCacheStore[domain] = DNSCacheItem{
				IP:         ip,
				ExpireTime: time.Now().Add(config.DNSCacheExp),
				Size:       itemSize,
			}
			currentCacheSize += itemSize
			if config.LogShow {
				log.Printf("[DNS CACHE STORE] Cached %s -> %s (Exp: %v)\n", domain, ip, config.DNSCacheExp)
			}
		}
		dnsCacheMutex.Unlock()
	}

	return ip, nil
}

// Thực hiện truy vấn DNS thực tế qua các bước ưu tiên phục vụ client (DoH -> DoT -> DNSIP -> DNSFallback)
// Actual DNS resolution through priority steps serving clients (DoH -> DoT -> DNSIP -> DNSFallback)
func resolveDomainActual(domain string) (string, error) {
	// 1. Thử giải mã qua DoH (DNS over HTTPS)
	if config.DNSDOH != "" {
		if ip, err := queryDoH(config.DNSDOH, domain); err == nil && ip != "" {
			if config.LogShow {
				log.Printf("[DNS SUCCESS] Resolved %s -> %s via DoH (%s)\n", domain, ip, config.DNSDOH)
			}
			return ip, nil
		}
	}

	// 2. Thử giải mã qua DoT (DNS over TLS)
	if config.DNSDOT != "" {
		if ip, err := queryDoT(config.DNSDOT, domain); err == nil && ip != "" {
			if config.LogShow {
				log.Printf("[DNS SUCCESS] Resolved %s -> %s via DoT (%s)\n", domain, ip, config.DNSDOT)
			}
			return ip, nil
		}
	}

	// 3. Thử giải mã qua DNS IP trực tiếp (UDP 53)
	if config.DNSIP != "" {
		if ip, err := queryUDP(config.DNSIP, domain); err == nil && ip != "" {
			if config.LogShow {
				log.Printf("[DNS SUCCESS] Resolved %s -> %s via Direct UDP (%s)\n", domain, ip, config.DNSIP)
			}
			return ip, nil
		}
	}

	// 4. Dự phòng giải mã qua DNS Fallback (UDP 53)
	if config.DNSFallback != "" {
		if ip, err := queryUDP(config.DNSFallback, domain); err == nil && ip != "" {
			if config.LogShow {
				log.Printf("[DNS SUCCESS] Resolved %s -> %s via Fallback UDP (%s)\n", domain, ip, config.DNSFallback)
			}
			return ip, nil
		}
	}

	return "", fmt.Errorf("unable to resolve domain %s using all configured DNS servers", domain)
}

// Kiểm tra ngầm nội bộ theo thứ tự: Direct IP -> Fallback -> DoH -> DoT, sau đó in kết quả client theo thứ tự: DoH -> DoT -> Direct IP -> Fallback
// Internal check order: Direct IP -> Fallback -> DoH -> DoT, then print client results order: DoH -> DoT -> Direct IP -> Fallback
func runClientDNSHealthCheckWithInternal(domain string) {
	// --- PHẦN 1: INTERNAL CHECK NGẦM (Thứ tự: Direct IP > Fallback > DoH > DoT) ---
	directIPOk := false
	fallbackOk := false
	dohOk := false
	dotOk := false

	// 1. Direct IP
	if config.DNSIP != "" {
		if ip, err := queryUDP(config.DNSIP, domain); err == nil && ip != "" {
			directIPOk = true
		}
	}

	// 2. Fallback
	if config.DNSFallback != "" {
		if ip, err := queryUDP(config.DNSFallback, domain); err == nil && ip != "" {
			fallbackOk = true
		}
	}

	// 3. DoH
	if config.DNSDOH != "" {
		if ip, err := queryDoH(config.DNSDOH, domain); err == nil && ip != "" {
			dohOk = true
		}
	}

	// 4. DoT
	if config.DNSDOT != "" {
		if ip, err := queryDoT(config.DNSDOT, domain); err == nil && ip != "" {
			dotOk = true
		}
	}

	// --- PHẦN 2: SHOW CLIENT RA LOG (Thứ tự: DoH > DoT > Direct IP > Fallback) ---
	fmt.Println("DNS Priority Order for Client:")

	// 1. DoH
	if config.DNSDOH != "" {
		if dohOk {
			fmt.Printf("- DoH (%s): OK\n", config.DNSDOH)
		} else {
			fmt.Printf("- DoH (%s): FAILED\n", config.DNSDOH)
		}
	} else {
		fmt.Println("- DoH: NOT CONFIGURED")
	}

	// 2. DoT
	if config.DNSDOT != "" {
		if dotOk {
			fmt.Printf("- DoT (%s): OK\n", config.DNSDOT)
		} else {
			fmt.Printf("- DoT (%s): FAILED\n", config.DNSDOT)
		}
	} else {
		fmt.Println("- DoT: NOT CONFIGURED")
	}

	// 3. Direct IP
	if config.DNSIP != "" {
		if directIPOk {
			fmt.Printf("- Direct IP (%s): OK\n", config.DNSIP)
		} else {
			fmt.Printf("- Direct IP (%s): FAILED\n", config.DNSIP)
		}
	} else {
		fmt.Println("- Direct IP: NOT CONFIGURED")
	}

	// 4. Fallback
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

// Gửi DNS Query qua HTTPS (DoH)
// Send DNS Query via HTTPS (DoH)[cite: 2]
func queryDoH(dohURL, domain string) (string, error) {
	dnsQuery := buildDNSQuery(domain)
	req, err := http.NewRequest("POST", dohURL, bytes.NewReader(dnsQuery))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/dns-message")

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("DoH status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return parseDNSResponse(body)
}

// Gửi DNS Query qua TLS (DoT)
// Send DNS Query via TLS (DoT)[cite: 2]
func queryDoT(dotHost, domain string) (string, error) {
	targetHost := dotHost
	if !strings.Contains(targetHost, ":") {
		targetHost = targetHost + ":853"
	}

	serverName := strings.Split(dotHost, ":")[0]
	tlsConfig := &tls.Config{ServerName: serverName}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", targetHost, tlsConfig)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	dnsQuery := buildDNSQuery(domain)
	lengthBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthBuf, uint16(len(dnsQuery)))

	if _, err := conn.Write(append(lengthBuf, dnsQuery...)); err != nil {
		return "", err
	}

	respLenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, respLenBuf); err != nil {
		return "", err
	}
	respLen := binary.BigEndian.Uint16(respLenBuf)

	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		return "", err
	}

	return parseDNSResponse(respBuf)
}

// Gửi DNS Query qua UDP thông thường
// Send DNS Query via standard UDP[cite: 2]
func queryUDP(dnsServer, domain string) (string, error) {
	serverAddr := dnsServer
	if !strings.Contains(serverAddr, ":") {
		serverAddr = serverAddr + ":53"
	}

	conn, err := net.DialTimeout("udp", serverAddr, 3*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	dnsQuery := buildDNSQuery(domain)
	if _, err := conn.Write(dnsQuery); err != nil {
		return "", err
	}

	respBuf := make([]byte, 512)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(respBuf)
	if err != nil {
		return "", err
	}

	return parseDNSResponse(respBuf[:n])
}

// Hàm dựng gói tin DNS Wire Format cơ bản (Type A - IPv4)
// Build basic DNS Wire Format packet (Type A - IPv4)[cite: 2]
func buildDNSQuery(domain string) []byte {
	var buf bytes.Buffer

	id := uint16(rand.Intn(65535))
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

	binary.Write(&buf, binary.BigEndian, uint16(1))
	binary.Write(&buf, binary.BigEndian, uint16(1))

	return buf.Bytes()
}

// Hàm bóc tách phản hồi gói tin DNS wire format lấy IPv4
// Parse DNS wire format response to extract IPv4[cite: 2]
func parseDNSResponse(data []byte) (string, error) {
	if len(data) < 12 {
		return "", fmt.Errorf("response too short")
	}

	ancount := binary.BigEndian.Uint16(data[6:8])
	if ancount == 0 {
		return "", fmt.Errorf("no answers found in DNS response")
	}

	offset := 12
	for data[offset] != 0 {
		if data[offset]&0xC0 == 0xC0 {
			offset += 2
			break
		}
		offset += int(data[offset]) + 1
	}
	if data[offset] == 0 {
		offset += 1 + 4
	}

	for i := 0; i < int(ancount); i++ {
		if offset >= len(data) {
			break
		}

		if data[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for data[offset] != 0 {
				offset += int(data[offset]) + 1
			}
			offset++
		}

		if offset+10 > len(data) {
			break
		}

		qtype := binary.BigEndian.Uint16(data[offset : offset+2])
		rdlength := binary.BigEndian.Uint16(data[offset+8 : offset+10])
		offset += 10

		if qtype == 1 && rdlength == 4 {
			if offset+4 <= len(data) {
				ip := net.IP(data[offset : offset+4])
				return ip.String(), nil
			}
		}

		offset += int(rdlength)
	}

	return "", fmt.Errorf("no IPv4 address found")
}

// Nếu file config.conf lỗi hoặc không có, thì xài tham số cố định này
// If config.conf is faulty or missing, use these hardcoded parameters[cite: 2]
func loadConfig(filepath string) {
	config = Config{
		LogShow:            false,
		ListenAddress:      "127.0.0.1:3979", // Khuyến nghị 127.0.0.1 để tránh kẹt IPv6 loopback / Recommended 127.0.0.1 to avoid IPv6 loopback issues
		ReadTimeout:        10 * time.Second,
		WriteTimeout:       10 * time.Second,
		IdleTimeout:        0,
		ProxyClientTimeout: 60 * time.Second,
		DNSFallback:        "208.67.222.222",
		DNSIP:              "8.8.8.8",
		DNSDOH:             "https://cloudflare-dns.com/dns-query",
		DNSDOT:             "1.1.1.1",
		DNSCache:           true,
		DNSCacheSize:       1024 * 1024,
		DNSCacheExp:        60 * time.Second,
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

		parts := strings.SplitN(line, ":", 2)
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
		case "proxyClient.timeout":
			config.ProxyClientTimeout = parseDuration(val)
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
		}
	}
}

// Chuyển đổi dung lượng bộ nhớ (VD: 1MB, 512KB) thành bytes
// Convert memory size string (e.g., 1MB, 512KB) to bytes[cite: 2]
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

func parseDuration(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 10 * time.Second
	}
	return d
}
