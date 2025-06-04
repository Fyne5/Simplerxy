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
   Simplerxy struct {
      ListenAddress string
      ReadTimeout string
      WriteTimeout string
      IdleTimeout string
   }
   ProxyClient struct {
      Timeout string
   }
}

// Lay gia tri o tren (ten Config) gan vao bien toan cuc
var cfg Config

// loadConfig reads the configuration from the specified .conf file
func loadConfig(filepath string) error {
   f, err := os.Open(filepath)
   if err != nil {
      return fmt.Errorf("failed to open config file '%s': %w", filepath, err)
   }
   defer f.Close()

   scanner := bufio.NewScanner(f)
   configMap := make(map[string]string)

   for scanner.Scan() {
      line := strings.TrimSpace(scanner.Text())

      // Skip empty lines and comments
      if line == "" || strings.HasPrefix(line, "#") {
         continue
      }

      // Xai dau 2 cham de phan tach cau hinh ':'
      parts := strings.SplitN(line, ":", 2)
      if len(parts) != 2 {
         log.Printf("Skipping invalid config line: %s", line)
         continue // Bo qua va tiep tuc neu cap gia tri 'key: value' khong ton tai
      }

      key := strings.TrimSpace(parts[0])
      value := strings.TrimSpace(parts[1])
      configMap[key] = value
   }

   if err := scanner.Err(); err != nil {
      return fmt.Errorf("error reading config file: %w", err)
   }

   // Manually assign values from the map to the Config struct
   // This makes it explicit and handles missing keys gracefully (default to empty string)
   cfg.Simplerxy.ListenAddress = configMap["listenAddress"]
   cfg.Simplerxy.ReadTimeout = configMap["readTimeout"]
   cfg.Simplerxy.WriteTimeout = configMap["writeTimeout"]
   cfg.Simplerxy.IdleTimeout = configMap["idleTimeout"]
   cfg.ProxyClient.Timeout = configMap["proxyClient.timeout"]

   // Basic validation: Check if essential fields are set
   if cfg.Simplerxy.ListenAddress == "" {
      return fmt.Errorf("config error: 'listenAddress' is required in %s", filepath)
   }
   if cfg.ProxyClient.Timeout == "" {
      return fmt.Errorf("config error: 'proxyClient.timeout' is required in %s", filepath)
   }

   return nil
}

// durationFromConfig parses a duration string (e.g., "10s", "1m") into time.Duration
func durationFromConfig(d string) time.Duration {
   parsedDuration, err := time.ParseDuration(d)
   if err != nil {
      log.Fatalf("Invalid duration format in config: '%s'. Error: %v", d, err)
   }
   return parsedDuration
}

// handleHTTP handles standard HTTP requests (non-CONNECT)
func handleHTTP(w http.ResponseWriter, r *http.Request) {
   log.Printf("HTTP Request: %s %s from %s", r.Method, r.URL.String(), r.RemoteAddr)

   // Ensure the URL is absolute for a forward proxy
   if !r.URL.IsAbs() {
      http.Error(w, "Invalid URL in HTTP request (not absolute)", http.StatusBadRequest)
      return
   }

   // Create a new request to forward
   proxyReq, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
   if err != nil {
      log.Printf("Error creating proxy request: %v", err)
      http.Error(w, "Internal proxy error", http.StatusInternalServerError)
      return
   }

   // Copy headers from the original request to the proxy request
   // Exclude "Connection" and "Proxy-Connection" which are hop-by-hop headers
   // and "Proxy-Authenticate", "Proxy-Authorization" (handled by Simplerxy server if needed)
   for name, values := range r.Header {
      if !strings.EqualFold(name, "Connection") &&
         !strings.EqualFold(name, "Proxy-Connection") &&
         !strings.EqualFold(name, "Proxy-Authenticate") &&
         !strings.EqualFold(name, "Proxy-Authorization") {
         for _, value := range values {
            proxyReq.Header.Add(name, value)
         }
      }
   }

   // Add standard proxy headers
   // X-Forwarded-For: Original client IP address
   if clientIP, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
      if priorXFF := proxyReq.Header.Get("X-Forwarded-For"); priorXFF != "" {
         proxyReq.Header.Set("X-Forwarded-For", priorXFF+", "+clientIP)
      } else {
         proxyReq.Header.Set("X-Forwarded-For", clientIP)
      }
   }
   // Via: Indicates intermediaries
   proxyReq.Header.Add("Via", fmt.Sprintf("1.1 %s (GoProxy)", r.Host))

   // Create a new HTTP client to send the request, using config timeout
   client := &http.Client{
      Timeout: durationFromConfig(cfg.ProxyClient.Timeout), // Use config value here
      // Do not follow redirects, let the client handle them
      CheckRedirect: func(req *http.Request, via []*http.Request) error {
         return http.ErrUseLastResponse
      },
   }

   // Send the proxy request
   resp, err := client.Do(proxyReq)
   if err != nil {
      log.Printf("Error sending proxy request to %s: %v", r.URL.String(), err)
      // Check for specific network errors and provide a more informative message
      if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
         http.Error(w, "Proxy target connection timed out", http.StatusGatewayTimeout)
      } else if strings.Contains(err.Error(), "connection refused") {
         http.Error(w, "Proxy target refused connection", http.StatusBadGateway)
      } else {
         http.Error(w, "Error communicating with proxy target", http.StatusBadGateway)
      }
      return
   }
   defer resp.Body.Close()

   log.Printf("Received response for %s: %d %s", r.URL.String(), resp.StatusCode, resp.Status)

   // Copy headers from the target response to the original client's response
   for name, values := range resp.Header {
      // Exclude hop-by-hop headers from being directly copied
      if !strings.EqualFold(name, "Connection") &&
         !strings.EqualFold(name, "Proxy-Connection") &&
         !strings.EqualFold(name, "Transfer-Encoding") { // Transfer-Encoding is handled automatically by Go's HTTP server
         for _, value := range values {
            w.Header().Add(name, value)
         }
      }
   }

   // Set the status code for the client's response
   w.WriteHeader(resp.StatusCode)

   // Copy the response body from the target to the client
   _, err = io.Copy(w, resp.Body)
   if err != nil {
      log.Printf("Error copying response body for %s: %v", r.URL.String(), err)
   }
}

// handleConnect handles HTTPS CONNECT requests by tunneling raw TCP
func handleConnect(w http.ResponseWriter, r *http.Request) {
   log.Printf("CONNECT Request: %s from %s", r.URL.Host, r.RemoteAddr)

   // Ensure the Host is specified (e.g., google.com:443)
   if r.URL.Host == "" {
      http.Error(w, "CONNECT requires host:port", http.StatusBadRequest)
      return
   }

   // Establish a connection to the target host, using config timeout
   destConn, err := net.DialTimeout("tcp", r.URL.Host, durationFromConfig(cfg.ProxyClient.Timeout)) // Use config value here
   if err != nil {
      log.Printf("Error dialing target %s: %v", r.URL.Host, err)
      http.Error(w, fmt.Sprintf("Failed to connect to target: %v", err), http.StatusServiceUnavailable)
      return
   }
   defer destConn.Close() // Close the connection to the target when done

   // Hijack the client's connection (take over the underlying TCP connection)
   hijacker, ok := w.(http.Hijacker)
   if !ok {
      log.Println("HTTP Hijacker not supported!")
      http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
      return
   }
   clientConn, _, err := hijacker.Hijack()
   if err != nil {
      log.Printf("Error hijacking client connection: %v", err)
      http.Error(w, "Failed to hijack connection", http.StatusInternalServerError)
      return
   }
   defer clientConn.Close() // Close the client connection when done

   // Send a 200 OK to the client to indicate connection established
   // This tells the client (e.g., browser) that it can now start its TLS handshake
   _, err = clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
   if err != nil {
      log.Printf("Error writing 200 to client: %v", err)
      return
   }

   // Now, pipe data between client and destination
   done := make(chan struct{})

   go func() {
      _, err := io.Copy(destConn, clientConn)
      if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
         log.Printf("Error copying from client to target %s: %v", r.URL.Host, err)
      }
      done <- struct{}{}
   }()

   go func() {
      _, err := io.Copy(clientConn, destConn)
      if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
         log.Printf("Error copying from target %s to client: %v", r.URL.Host, err)
      }
      done <- struct{}{}
   }()

   // Wait for one of the copy operations to finish (meaning the connection is closed)
   <-done
   log.Printf("Tunnel closed for %s", r.URL.Host)
}

// Proxy is the main handler for all requests
func proxyHandler(w http.ResponseWriter, r *http.Request) {
   if r.Method == http.MethodConnect {
      handleConnect(w, r)
   } else {
      handleHTTP(w, r)
   }
}

func main() {
   log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

   // Load configuration from config.conf
   if err := loadConfig("config.conf"); err != nil {
      log.Fatalf("Failed to load configuration: %v", err)
   }

   log.Printf("Starting forward Simplerxy on %s", cfg.Simplerxy.ListenAddress)

   server := &http.Server{ //Cau truc 'http.Server{}' cua thu vien go 'net/http'
      Addr: cfg.Simplerxy.ListenAddress,
      Handler: http.HandlerFunc(proxyHandler),
      ReadTimeout: durationFromConfig(cfg.Simplerxy.ReadTimeout),
      WriteTimeout: durationFromConfig(cfg.Simplerxy.WriteTimeout),
      IdleTimeout: durationFromConfig(cfg.Simplerxy.IdleTimeout),
   }

   log.Printf("Simplerxy is listening on %s...", cfg.Simplerxy.ListenAddress)
   log.Fatal(server.ListenAndServe())
}
