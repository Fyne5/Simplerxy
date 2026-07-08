package main

import (
   "bufio" // Thu vien doc file theo tung dong
   "fmt"
   "io"
   "log"
   "net"
   "net/http" //Cau truc phuc vu 'http.Server{}'
   "os"
   "strings"
   "time"
)

// Dinh dang noi dung cau hinh cho config.conf
type Config struct {
	ListenAddress string
	ReadTimeout   time.Duration
	WriteTimeout  time.Duration
	IdleTimeout   time.Duration
}

// Lay gia tri o tren (ten Config) gan vao bien toan cuc
var config Config

func main() {
	// Lay cac gia tri tu config.conf
	loadConfig("config.conf")

	// Khoi tao HTTP Server voi cac thong so tu config.conf
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

// Dieu huong request: CONNECT hoac HTTP thong thuong
func proxyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		handleConnect(w, r)
	} else {
		handleHTTP(w, r)
	}
}

// Xu ly HTTPS TUNNEL (Bypass SNI/DPI nam o day)
func handleConnect(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Host
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	// Kết nối tới server đích (ví dụ: medium.com:443)
	destConn, err := net.DialTimeout("tcp", host, 5*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer destConn.Close()

	// Hijack kết nối để giành quyền điều khiển các byte thô từ HTTP Server
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

	// Phản hồi cho client biết tunnel đã thông
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// 1. Chuyển tiếp dữ liệu chiều ngược từ Server đích về lại Client (Giữ nguyên bản)
	go io.Copy(clientConn, destConn)

	// 2. Xử lý chiều đi từ Client sang Server đích để bẻ gãy gói tin chứa SNI
	buffer := make([]byte, 32*1024)
	n, err := clientConn.Read(buffer)
	if err != nil {
		return
	}

	// 0x16 đại diện cho TLS Handshake (Client Hello)
	if n > 5 && buffer[0] == 0x16 {
		// Kỹ thuật Fragmentation: Băm nhỏ 5 byte đầu (TLS Record Header) đi trước
		_, err = destConn.Write(buffer[:5])
		if err != nil {
			return
		}

		// Ru ngủ DPI nhà mạng trong 20 miligiây để nó lỡ nhịp và không ghép gói tin quét SNI
		time.Sleep(20 * time.Millisecond)

		// Gửi tiếp phần thân còn lại chứa SNI thật (medium.com)
		_, err = destConn.Write(buffer[5:n])
		if err != nil {
			return
		}
	} else {
		// Dữ liệu HTTP thường hoặc không phải TLS thì cho qua thẳng
		_, err = destConn.Write(buffer[:n])
		if err != nil {
			return
		}
	}

	// 3. Sau khi vượt qua bước bắt tay đầu tiên, các gói dữ liệu sau cứ để io.Copy lo nốt
	io.Copy(destConn, clientConn)
}

// Xử lý HTTP Proxy thông thường (không mã hóa)
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

// Hàm bổ trợ đọc file config.conf của đại ca
func loadConfig(filepath string) {
	// Cấu hình mặc định phòng trường hợp không đọc được file
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