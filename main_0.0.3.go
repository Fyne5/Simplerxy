package main

import (
	"bufio"
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
	ListenAddress string
	ReadTimeout   time.Duration
	WriteTimeout  time.Duration
	IdleTimeout   time.Duration
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
	host := r.URL.Host
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	// Kết nối tới server đích
	// Connect to the destination server
	destConn, err := net.DialTimeout("tcp", host, 5*time.Second)
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
		// 21 - 1 = 20; 20 + 5 = 25
		// From 10 to 20 ms: 11 - 1 = 10; 10 + 10 = 20
		// randomSleep := time.Duration(10+rand.Intn(11)) * time.Millisecond
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
	transport := http.DefaultTransport
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

// Nếu file config.conf lỗi hoặc không có, thì xài tham số cố định này
// If config.conf is faulty or missing, use this hardcoded parameter.
func loadConfig(filepath string) {
	config = Config{
		ListenAddress: "0.0.0.0:3979",
		ReadTimeout:   10 * time.Second,
		WriteTimeout:  10 * time.Second,
		IdleTimeout:   120 * time.Second,
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
		case "listenAddress":
			config.ListenAddress = val
		case "readTimeout":
			config.ReadTimeout = parseDuration(val)
		case "writeTimeout":
			config.WriteTimeout = parseDuration(val)
		case "idleTimeout":
			config.IdleTimeout = parseDuration(val)
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