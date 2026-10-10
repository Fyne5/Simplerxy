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
}

// Lấy giá trị ở trên (tên Config) gán vào biến toàn cục
// Assign the value from above (Config name) to the global variable
var config Config

func main() {
	// Lấy các giá trị từ config.conf
	// Get values from config.conf
	loadConfig("config.conf")

	// Khởi tạo HTTP Server với các thông số từ config.conf
	// Initialize the HTTP server with parameters from config.conf
	server := &http.Server{
		Addr:         config.ListenAddress,
		ReadTimeout:  config.ReadTimeout,
		WriteTimeout: config.WriteTimeout,
		IdleTimeout:  config.IdleTimeout,
		Handler:      http.HandlerFunc(proxyHandler),
	}

	log.Printf("Proxy is running at: %s\n", config.ListenAddress)
	log.Printf("Log show status: %v\n", config.LogShow)
	log.Printf("DNS Priority Order: DoH (%s) -> DoT (%s) -> Direct IP (%s) -> Fallback (%s)\n",
		config.DNSDOH, config.DNSDOT, config.DNSIP, config.DNSFallback)

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Can not start the server: %v", err)
	}
}

// Điều hướng request: CONNECT hoặc HTTP thông thường
// Request routing: CONNECT or standard HTTP
func proxyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		handleConnect(w, r)
	} else {
		handleHTTP(w, r)
	}
}

// Xử lý HTTPS TUNNEL (Vượt chướng ngại vật SNI/DPI)
// Handle HTTPS Tunnel (Bypass SNI/DPI restrictions)
func handleConnect(w http.ResponseWriter, r *http.Request) {
	rawHost := r.URL.Host
	hostname, port, err := net.SplitHostPort(rawHost)
	if err != nil {
		hostname = rawHost
		port = "443"
	}

	// Giải mã IP thông qua thứ tự ưu tiên DoH -> DoT -> DNSIP -> DNSFallback
	// Resolve IP using priority order: DoH -> DoT -> DNSIP -> DNSFallback
	targetIP, err := resolveDomainPriority(hostname)
	if err != nil {
		http.Error(w, fmt.Sprintf("DNS resolution failed: %v", err), http.StatusServiceUnavailable)
		return
	}

	targetAddr := net.JoinHostPort(targetIP, port)

	// Kết nối tới server đích (chỉ IPv4)
	// Connect to the destination server (just IPv4)
	destConn, err := net.DialTimeout("tcp4", targetAddr, 5*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer destConn.Close()

	// Ép gửi gói tin TCP ngay lập tức (Tắt Nagle's Algorithm)
	if tcpConn, ok := destConn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	// Hijack kết nối
	// Hijack connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	// Phản hồi cho client biết đã kết nối thông suốt
	// Respond to the client to indicate a successful connection
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// 1. Chuyển dữ liệu từ server đích (nơi chứa website) về lại client
	// 1. Transfer data from the destination server (hosting the website) back to the client.
	go io.Copy(clientConn, destConn)

	// 2. Xử lý chiều từ client sang server đích để bẻ gãy gói tin SNI
	// 2. Handle the client-to-destination-server direction to break the SNI packet
	buffer := make([]byte, 32*1024)
	n, err := clientConn.Read(buffer)
	if err != nil {
		return
	}

	// 0x16 đại diện cho TLS Handshake (Client Hello)
	// 0x16 represents the TLS Handshake (Client Hello)
	if n > 5 && buffer[0] == 0x16 {
		// Vị trí cắt ngẫu nhiên an toàn trong khoảng 2 đến 5 byte đầu
		// Safe random split position within 2 to 5 bytes
		splitPos := 2 + rand.Intn(4) // Trả về 2, 3, 4 hoặc 5

		// Gửi mảnh đầu tiên
		// Send the first fragment
		_, err = destConn.Write(buffer[:splitPos])
		if err != nil {
			return
		}

		// Ru ngủ với thời gian ngẫu nhiên từ 5 đến 25 ms
		// Sleep for a random duration between 5ms to 25ms
		randomSleep := time.Duration(5+rand.Intn(21)) * time.Millisecond
		time.Sleep(randomSleep)

		// Gửi mảnh còn lại
		// Send the remaining fragment
		_, err = destConn.Write(buffer[splitPos:n])
		if err != nil {
			return
		}
	} else {
		// Dữ liệu HTTP thường hoặc không phải TLS thì cho qua luôn
		// Pass through standard or non-TLS HTTP data immediately.
		_, err = destConn.Write(buffer[:n])
		if err != nil {
			return
		}
	}

	// 3. Khi xong cú bắt tay đầu tiên, chuyển tiếp các gói dữ liệu tiếp theo
	// 3. Upon completion of the initial handshake, forward subsequent data packets
	io.Copy(destConn, clientConn)
}

// Xử lý HTTP Proxy thông thường
// Handle standard HTTP proxy
func handleHTTP(w http.ResponseWriter, r *http.Request) {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			hostname, port, err := net.SplitHostPort(addr)
			if err != nil {
				hostname = addr
				port = "80"
			}
			targetIP, err := resolveDomainPriority(hostname)
			if err != nil {
				return nil, err
			}
			d := net.Dialer{Timeout: 30 * time.Second}
			return d.DialContext(ctx, "tcp4", net.JoinHostPort(targetIP, port))
		},
	}

	outReq := new(http.Request)
	*outReq = *r
	outReq.RequestURI = ""

	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// Hàm phân giải IP theo thứ tự ưu tiên: DoH -> DoT -> DNSIP -> DNSFallback
// Resolve domain by priority: DoH -> DoT -> DNSIP -> DNSFallback
func resolveDomainPriority(domain string) (string, error) {
	if net.ParseIP(domain) != nil {
		return domain, nil
	}

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

// Gửi DNS Query qua HTTPS (DoH)
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
func queryDoT(dotHost, domain string) (string, error) {
	targetHost := dotHost
	if !strings.Contains(targetHost, ":") {
		targetHost = targetHost + ":853"
	}

	serverName := strings.Split(dotHost, ":")[0]
	tlsConfig := &tls.Config{
		ServerName: serverName,
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", targetHost, tlsConfig)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	dnsQuery := buildDNSQuery(domain)
	// DoT yêu cầu thêm 2 byte chỉ định độ dài gói tin ở đầu
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
func buildDNSQuery(domain string) []byte {
	var buf bytes.Buffer

	// Header
	id := uint16(rand.Intn(65535))
	binary.Write(&buf, binary.BigEndian, id)              // ID
	binary.Write(&buf, binary.BigEndian, uint16(0x0100)) // Flags: Standard Query, Recursion Desired
	binary.Write(&buf, binary.BigEndian, uint16(1))      // QDCOUNT: 1 question
	binary.Write(&buf, binary.BigEndian, uint16(0))      // ANCOUNT
	binary.Write(&buf, binary.BigEndian, uint16(0))      // NSCOUNT
	binary.Write(&buf, binary.BigEndian, uint16(0))      // ARCOUNT

	// Question Section
	parts := strings.Split(domain, ".")
	for _, part := range parts {
		buf.WriteByte(byte(len(part)))
		buf.WriteString(part)
	}
	buf.WriteByte(0) // Kết thúc domain

	binary.Write(&buf, binary.BigEndian, uint16(1)) // QTYPE: A (IPv4)
	binary.Write(&buf, binary.BigEndian, uint16(1)) // QCLASS: IN

	return buf.Bytes()
}

// Hàm bóc tách phản hồi gói tin DNS wire format lấy IPv4
func parseDNSResponse(data []byte) (string, error) {
	if len(data) < 12 {
		return "", fmt.Errorf("response too short")
	}

	ancount := binary.BigEndian.Uint16(data[6:8])
	if ancount == 0 {
		return "", fmt.Errorf("no answers found in DNS response")
	}

	// Bỏ qua phần Header và Question
	offset := 12
	for data[offset] != 0 {
		if data[offset]&0xC0 == 0xC0 {
			offset += 2
			break
		}
		offset += int(data[offset]) + 1
	}
	if data[offset] == 0 {
		offset += 1 + 4 // Skip NULL byte + QTYPE(2) + QCLASS(2)
	}

	// Đọc các bản ghi Answer
	for i := 0; i < int(ancount); i++ {
		if offset >= len(data) {
			break
		}

		// Skip Name
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

		// Nếu là Type A (IPv4)
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
// If config.conf is faulty or missing, use this hardcoded parameter.
func loadConfig(filepath string) {
	config = Config{
		LogShow:            false,
		ListenAddress:      "0.0.0.0:3979",
		ReadTimeout:        10 * time.Second,
		WriteTimeout:       10 * time.Second,
		IdleTimeout:        0,
		ProxyClientTimeout: 60 * time.Second,
		DNSFallback:        "208.67.222.222",
		DNSIP:              "8.8.8.8",
		DNSDOH:             "https://cloudflare-dns.com/dns-query",
		DNSDOT:             "cloudflare-dns.com",
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
		}
	}
}

func parseDuration(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 10 * time.Second
	}
	return d
}