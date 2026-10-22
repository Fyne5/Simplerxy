package main

import (
	"bufio"
	"bytes"
	"context"
	"container/list"
	crypto_rand "crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	version = "1.0.3"

	defaultDialTimeout                    = 5 * time.Second
	defaultDNSTimeout                     = 5 * time.Second
	defaultDoXTimeout                     = 3 * time.Second
	defaultTransportResponseHeaderTimeout = 30 * time.Second
	defaultTransportIdleConnTimeout       = 90 * time.Second
	happyEyeballsDelay   = 250 * time.Millisecond
	acceptErrorBackoff   = 100 * time.Millisecond
	udpTargetIdleTimeout = 30 * time.Second
	udpWriteTimeout      = 10 * time.Second
	maxUDPTargets        = 256
	maxConcurrentConns   = 8192
	maxHeaderBytes       = 64 * 1024
)

var hopByHopHeaders = []string{
	"Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Proxy-Connection", "Te",
	"Trailer", "Transfer-Encoding", "Upgrade",
}

type Config struct {
	LogShow          bool
	ListenAddress    string
	ReadTimeout      time.Duration
	WriteTimeout     time.Duration
	IdleTimeout      time.Duration
	ClientTimeout    time.Duration
	DNSFallback      string
	DNSIP            string
	DNSDOH           string
	DNSDOT           string
	DNSCache         bool
	DNSCacheSize     int64
	DNSCacheExp      time.Duration
	ClientAllowlist  string
	AllowPrivateIP   bool
	AllowPrivateDest string
}

type DNSCacheItem struct {
	IPs        []string
	ExpireTime time.Time
	Size       int64
	elem       *list.Element
}

type dnsCall struct {
	wg  sync.WaitGroup
	val []string
	err error
}

type miniSingleflight struct {
	mu sync.Mutex
	m  map[string]*dnsCall
}

func (g *miniSingleflight) Do(key string, fn func() ([]string, error)) ([]string, error) {
	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[string]*dnsCall)
	}
	if c, ok := g.m[key]; ok {
		g.mu.Unlock()
		c.wg.Wait()
		return c.val, c.err
	}
	c := new(dnsCall)
	c.wg.Add(1)
	g.m[key] = c
	g.mu.Unlock()

	// Bảo đảm an toàn khi fn() panic
	defer func() {
		c.wg.Done()
		g.mu.Lock()
		delete(g.m, key)
		g.mu.Unlock()
	}()

	c.val, c.err = fn()
	return c.val, c.err
}

var (
	dnsCacheStore    = make(map[string]DNSCacheItem)
	dnsCacheMutex    sync.RWMutex
	currentCacheSize int64
	dnsGroup         miniSingleflight

	bufferPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 32*1024)
			return &b
		},
	}

	maxConnsChan = make(chan struct{}, maxConcurrentConns)

	httpTransport *http.Transport
	dohClient     *http.Client

	allowAll             bool
	allowNets            []*net.IPNet
	allowPrivateDestNets []*net.IPNet

	errBlockedDestination = errors.New("destination not allowed")

	privateNets = func() []*net.IPNet {
		cidrs := []string{
			"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
			"169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
			"224.0.0.0/4", "240.0.0.0/4",
			"::/128", "::1/128", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
		}
		nets := make([]*net.IPNet, 0, len(cidrs))
		for _, c := range cidrs {
			if _, n, err := net.ParseCIDR(c); err == nil {
				nets = append(nets, n)
			}
		}
		return nets
	}()
)

var errUnsupportedAtyp = errors.New("unsupported atyp")

var config Config

func main() {
	configPath := flag.String("config", "config.conf", "path to config file")
	flag.Parse()

	loadConfig(resolveConfigPath(*configPath))
	compileAllowlist()
	compileAllowPrivateDest()
	initHTTPTransport()

	listener, err := net.Listen("tcp", config.ListenAddress)
	if err != nil {
		log.Fatalf("Can not start the server: %v", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		os.Exit(0)
	}()

	log.Printf("Simplerxy %s (HTTP & SOCKS5 Dual-Stack TCP/UDP) is running at: %s\n", version, config.ListenAddress)
	log.Printf("Log show status: %v\n", config.LogShow)
	log.Printf("Timeouts -> Read(handshake): %v, Write: %v, Idle(tunnel): %v, Client(handshake): %v\n", config.ReadTimeout, config.WriteTimeout, config.IdleTimeout, config.ClientTimeout)
	log.Printf("DNS Cache status: %v (Size limit: %d bytes, Expire: %v)\n", config.DNSCache, config.DNSCacheSize, config.DNSCacheExp)
	log.Printf("Client Allowlist: [%s], Allow Private Dest: [%s], Allow Private IP: %v\n", config.ClientAllowlist, config.AllowPrivateDest, config.AllowPrivateIP)
	if allowAll {
		log.Printf("[WARNING] clientAllowlist is empty or '*': anyone who can reach %s can use this proxy\n", config.ListenAddress)
	}

	runClientDNSHealthCheckWithInternal("google.com")

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("[ACCEPT ERROR] %v\n", err)
			time.Sleep(acceptErrorBackoff)
			continue
		}

		if !isClientAllowed(conn.RemoteAddr()) {
			if config.LogShow {
				log.Printf("[SECURITY] Rejected connection from unauthorized IP: %s\n", conn.RemoteAddr())
			}
			conn.Close()
			continue
		}

		select {
		case maxConnsChan <- struct{}{}:
		default:
			if config.LogShow {
				log.Printf("[LIMIT] Too many concurrent connections, dropping %s\n", conn.RemoteAddr())
			}
			conn.Close()
			continue
		}

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

// ---------------------------------
// Transport, Allowlist & Private IP
// ---------------------------------

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
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: defaultTransportResponseHeaderTimeout,
		IdleConnTimeout:       defaultTransportIdleConnTimeout,
	}

	dohClient = &http.Client{
		Timeout: defaultDoXTimeout,
		Transport: &http.Transport{
			Proxy:               nil,
			TLSHandshakeTimeout: defaultDoXTimeout,
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     defaultTransportIdleConnTimeout,
			ForceAttemptHTTP2:   true,
		},
	}
}

func parseIPNets(listStr string) []*net.IPNet {
	var nets []*net.IPNet
	list := strings.TrimSpace(listStr)
	if list == "" {
		return nil
	}
	list = strings.ReplaceAll(list, ",", ";")
	for _, rule := range strings.Split(list, ";") {
		rule = strings.TrimSpace(rule)
		if rule == "" {
			continue
		}
		if strings.Contains(rule, "/") {
			_, n, err := net.ParseCIDR(rule)
			if err != nil {
				log.Printf("[CONFIG] invalid CIDR: %q\n", rule)
				continue
			}
			nets = append(nets, n)
		} else if ip := net.ParseIP(rule); ip != nil {
			bits := 128
			if ip4 := ip.To4(); ip4 != nil {
				ip = ip4
				bits = 32
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		} else {
			log.Printf("[CONFIG] invalid IP: %q\n", rule)
		}
	}
	return nets
}

func compileAllowlist() {
	allowNets = nil
	list := strings.TrimSpace(config.ClientAllowlist)
	if list == "" || list == "*" {
		allowAll = true
		return
	}
	allowAll = false
	allowNets = parseIPNets(config.ClientAllowlist)
	if len(allowNets) == 0 {
		log.Printf("[WARNING] clientAllowlist has no valid entries: every client will be rejected\n")
	}
}

func compileAllowPrivateDest() {
	allowPrivateDestNets = nil
	if config.AllowPrivateIP {
		return
	}
	
	// Nếu trong cấu hình rỗng thì in thông báo ra
	if strings.TrimSpace(config.AllowPrivateDest) == "" {
		log.Printf("[CONFIG] allowPrivateDest is empty: no private IP destinations are allowed\n")
		return
	}

	allowPrivateDestNets = parseIPNets(config.AllowPrivateDest)
	if len(allowPrivateDestNets) == 0 {
		log.Printf("[WARNING] allowPrivateDest has no valid CIDRs/IPs configured\n")
	}
}

func isClientAllowed(remoteAddr net.Addr) bool {
	if allowAll {
		return true
	}
	var ip net.IP
	if ta, ok := remoteAddr.(*net.TCPAddr); ok {
		ip = ta.IP
	} else {
		host, _, err := net.SplitHostPort(remoteAddr.String())
		if err != nil {
			host = remoteAddr.String()
		}
		if i := strings.IndexByte(host, '%'); i >= 0 {
			host = host[:i]
		}
		ip = net.ParseIP(host)
	}
	if ip == nil {
		return false
	}
	for _, n := range allowNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true
	}
	for _, n := range privateNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func isIPAllowed(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if !isPrivateIP(ipStr) {
		return true
	}
	if config.AllowPrivateIP {
		return true
	}
	for _, n := range allowPrivateDestNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Quản lý Deadline Kết nối & Kênh Closed
// ---------------------------------------------------------------------------

type timeoutConn struct {
	net.Conn
	readTimeout  time.Duration
	writeTimeout time.Duration
	lastActivity atomic.Int64
	tunnel       atomic.Bool
	noIdle       atomic.Bool
	hsTimer      *time.Timer
	closed       chan struct{}
	closeOnce    sync.Once
}

func newTimeoutConn(c net.Conn) *timeoutConn {
	tc := &timeoutConn{
		Conn:         c,
		readTimeout:  config.ReadTimeout,
		writeTimeout: config.WriteTimeout,
		closed:       make(chan struct{}),
	}
	tc.touch()
	return tc
}

func (c *timeoutConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
	})
	return c.Conn.Close()
}

func (c *timeoutConn) touch() {
	c.lastActivity.Store(time.Now().UnixNano())
}

func (c *timeoutConn) Read(b []byte) (int, error) {
	if !c.tunnel.Load() && c.readTimeout > 0 {
		c.Conn.SetReadDeadline(time.Now().Add(c.readTimeout))
	}
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.touch()
	}
	return n, err
}

func (c *timeoutConn) Write(b []byte) (int, error) {
	if c.writeTimeout > 0 {
		c.Conn.SetWriteDeadline(time.Now().Add(c.writeTimeout))
	}
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.touch()
	}
	return n, err
}

func (c *timeoutConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}

func (c *timeoutConn) stopHandshakeTimer() {
	if c.hsTimer != nil {
		c.hsTimer.Stop()
	}
}

func (c *timeoutConn) enterTunnel() {
	c.tunnel.Store(true)
	c.stopHandshakeTimer()
	c.Conn.SetReadDeadline(time.Time{})
	c.touch()
	c.noIdle.Store(false)
}

type liftableLimit struct {
	r io.Reader
	n int64
}

func (l *liftableLimit) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	return n, err
}

func (l *liftableLimit) lift() {
	l.n = math.MaxInt64
}

type peekReaderConn struct {
	*timeoutConn
	reader *bufio.Reader
	limit  *liftableLimit
}

func (c *peekReaderConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *peekReaderConn) enterTunnel() {
	if c.limit != nil {
		c.limit.lift()
	}
	c.timeoutConn.enterTunnel()
}

type closeWriter interface{ CloseWrite() error }

func closeWrite(c net.Conn) {
	if cw, ok := c.(closeWriter); ok {
		cw.CloseWrite()
		return
	}
	c.Close()
}

type onlyWriter struct{ io.Writer }
type onlyReader struct{ io.Reader }

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

func (b *bufferedConn) CloseWrite() error {
	if cw, ok := b.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return b.Conn.Close()
}

func recoverAndKill(where string, kill func()) {
	if r := recover(); r != nil {
		log.Printf("[RECOVER] Panic in %s: %v\n", where, r)
		kill()
	}
}

func watchIdle(c *timeoutConn, done <-chan struct{}) {
	idle := config.IdleTimeout
	interval := idle / 2
	if interval < 250*time.Millisecond {
		interval = 250 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if c.noIdle.Load() {
				continue
			}
			if time.Since(time.Unix(0, c.lastActivity.Load())) >= idle {
				c.Close()
				return
			}
		case <-done:
			return
		case <-c.closed:
			return
		}
	}
}

func handleIncomingConnection(clientConn net.Conn) {
	tConn := newTimeoutConn(clientConn)
	tConn.noIdle.Store(true)
	defer tConn.Close()

	if config.ClientTimeout > 0 {
		tConn.hsTimer = time.AfterFunc(config.ClientTimeout, func() { tConn.Close() })
		defer tConn.stopHandshakeTimer()
	}

	if config.IdleTimeout > 0 {
		done := make(chan struct{})
		defer close(done)
		go watchIdle(tConn, done)
	}

	lim := &liftableLimit{r: tConn, n: maxHeaderBytes}
	br := bufio.NewReader(lim)
	firstByte, err := br.Peek(1)
	if err != nil {
		return
	}

	peeledConn := &peekReaderConn{
		timeoutConn: tConn,
		reader:      br,
		limit:       lim,
	}

	if firstByte[0] == 0x05 {
		handleSocks5Direct(peeledConn)
	} else {
		handleHTTPProxyDirect(peeledConn)
	}
}

// ---------------------------------------------------------------------------
// Happy Eyeballs & Kết nối Đích
// ---------------------------------------------------------------------------

func interleaveFamilies(ips []string) []string {
	var v6, v4 []string
	for _, s := range ips {
		if ip := net.ParseIP(s); ip != nil && ip.To4() == nil {
			v6 = append(v6, s)
		} else {
			v4 = append(v4, s)
		}
	}
	if len(v6) == 0 || len(v4) == 0 {
		return ips
	}
	out := make([]string, 0, len(ips))
	for i := 0; i < len(v6) || i < len(v4); i++ {
		if i < len(v6) {
			out = append(out, v6[i])
		}
		if i < len(v4) {
			out = append(out, v4[i])
		}
	}
	return out
}

func dialWithFallback(ips []string, port string) (net.Conn, string, error) {
	cands := make([]string, 0, len(ips))
	for _, ip := range ips {
		if !isIPAllowed(ip) {
			continue
		}
		cands = append(cands, ip)
	}
	if len(cands) == 0 {
		return nil, "", errBlockedDestination
	}
	cands = interleaveFamilies(cands)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type result struct {
		conn net.Conn
		addr string
		err  error
	}
	results := make(chan result, len(cands))
	dialer := net.Dialer{Timeout: defaultDialTimeout}

	start := func(ip string) {
		addr := net.JoinHostPort(ip, port)
		go func() {
			c, err := dialer.DialContext(ctx, "tcp", addr)
			results <- result{c, addr, err}
		}()
	}

	timer := time.NewTimer(happyEyeballsDelay)
	defer timer.Stop()
	resetTimer := func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(happyEyeballsDelay)
	}

	next, pending := 1, 1
	start(cands[0])

	var lastErr error
	for pending > 0 {
		select {
		case r := <-results:
			pending--
			if r.err == nil {
				cancel()
				go func(n int) {
					for i := 0; i < n; i++ {
						if lr := <-results; lr.conn != nil {
							lr.conn.Close()
						}
					}
				}(pending)
				return r.conn, r.addr, nil
			}
			lastErr = r.err
			if next < len(cands) {
				start(cands[next])
				next++
				pending++
				resetTimer()
			}
		case <-timer.C:
			if next < len(cands) {
				start(cands[next])
				next++
				pending++
				timer.Reset(happyEyeballsDelay)
			}
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no valid or allowed destination IP address")
	}
	return nil, "", lastErr
}

// ---------------------------------------------------------------------------
// Cơ chế Tunnel & Xử lý Buffer Pool Pointer
// ---------------------------------------------------------------------------

func writeFirstChunk(dest net.Conn, data []byte) error {
	if len(data) > 5 && data[0] == 0x16 {
		splitPos := 2 + rand.Intn(4)
		if _, err := dest.Write(data[:splitPos]); err != nil {
			return err
		}
		time.Sleep(time.Duration(5+rand.Intn(21)) * time.Millisecond)
		_, err := dest.Write(data[splitPos:])
		return err
	}
	_, err := dest.Write(data)
	return err
}

func copyClientToDest(client, dest net.Conn, buf []byte) error {
	n, rerr := client.Read(buf)
	if n > 0 {
		if err := writeFirstChunk(dest, buf[:n]); err != nil {
			return err
		}
	}
	if rerr != nil {
		if rerr == io.EOF {
			return nil
		}
		return rerr
	}
	_, err := io.CopyBuffer(onlyWriter{dest}, onlyReader{client}, buf)
	return err
}

func tunnel(client *peekReaderConn, dest net.Conn) {
	client.enterTunnel()

	pUp := bufferPool.Get().(*[]byte)
	pDown := bufferPool.Get().(*[]byte)
	bufUp := *pUp
	bufDown := *pDown

	killBoth := func() {
		client.Close()
		dest.Close()
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer recoverAndKill("tunnel dest->client", killBoth)
		if _, err := io.CopyBuffer(onlyWriter{client}, onlyReader{dest}, bufDown); err != nil {
			killBoth()
			return
		}
		closeWrite(client)
	}()

	go func() {
		defer wg.Done()
		defer recoverAndKill("tunnel client->dest", killBoth)
		if err := copyClientToDest(client, dest, bufUp); err != nil {
			killBoth()
			return
		}
		closeWrite(dest)
	}()

	wg.Wait()
	killBoth()
	bufferPool.Put(pUp)
	bufferPool.Put(pDown)
}

// ---------------------------------------------------------------------------
// Xử lý HTTP Proxy
// ---------------------------------------------------------------------------

func writeHTTPError(w io.Writer, code int) {
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", code, http.StatusText(code))
}

func removeHopByHop(h http.Header) {
	for _, f := range h["Connection"] {
		for _, name := range strings.Split(f, ",") {
			if name = strings.TrimSpace(name); name != "" {
				h.Del(name)
			}
		}
	}
	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
}

func removeHopByHopKeepUpgrade(h http.Header) {
	for _, f := range h["Connection"] {
		for _, name := range strings.Split(f, ",") {
			if name = strings.TrimSpace(name); name != "" && !strings.EqualFold(name, "Upgrade") && !strings.EqualFold(name, "Connection") {
				h.Del(name)
			}
		}
	}
	for _, name := range hopByHopHeaders {
		if !strings.EqualFold(name, "Upgrade") && !strings.EqualFold(name, "Connection") {
			h.Del(name)
		}
	}
	if h.Get("Connection") == "" {
		h.Set("Connection", "Upgrade")
	}
	if h.Get("Upgrade") == "" {
		h.Set("Upgrade", "websocket")
	}
}

func handleHTTPProxyDirect(c *peekReaderConn) {
	req, err := http.ReadRequest(c.reader)
	if err != nil {
		return
	}

	if req.Method == http.MethodConnect {
		handleConnectDirect(c, req.Host)
	} else {
		handleHTTPDirect(c, req)
	}
}

func handleConnectDirect(c *peekReaderConn, rawTarget string) {
	hostname, port, err := net.SplitHostPort(rawTarget)
	if err != nil {
		hostname = strings.Trim(rawTarget, "[]")
		port = "443"
	}

	targetIPs, err := resolveDomainPriority(hostname)
	if err != nil || len(targetIPs) == 0 {
		writeHTTPError(c, http.StatusBadGateway)
		return
	}

	destConn, connectedAddr, err := dialWithFallback(targetIPs, port)
	if err != nil {
		if errors.Is(err, errBlockedDestination) {
			writeHTTPError(c, http.StatusForbidden)
		} else {
			writeHTTPError(c, http.StatusBadGateway)
		}
		return
	}
	defer destConn.Close()

	if _, err := c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	if config.LogShow {
		log.Printf("[HTTP CONNECT] Established connection to %s (%s)\n", rawTarget, connectedAddr)
	}

	tunnel(c, destConn)
}

func handleHTTPDirect(c *peekReaderConn, req *http.Request) {
	if req.URL == nil || req.URL.Host == "" {
		writeHTTPError(c, http.StatusBadRequest)
		return
	}

	isWS := strings.EqualFold(req.URL.Scheme, "ws") || strings.EqualFold(req.Header.Get("Upgrade"), "websocket")
	if isWS {
		handleWebSocketDirect(c, req)
		return
	}

	if !strings.EqualFold(req.URL.Scheme, "http") {
		writeHTTPError(c, http.StatusBadRequest)
		return
	}

	c.enterTunnel()

	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()

	go func() {
		select {
		case <-c.closed:
			cancel()
		case <-ctx.Done():
		}
	}()

	req = req.WithContext(ctx)
	req.RequestURI = ""
	removeHopByHop(req.Header)
	req.Close = true

	resp, err := httpTransport.RoundTrip(req)
	c.touch()
	if err != nil {
		if errors.Is(err, errBlockedDestination) {
			writeHTTPError(c, http.StatusForbidden)
		} else {
			writeHTTPError(c, http.StatusBadGateway)
		}
		return
	}
	defer resp.Body.Close()

	removeHopByHop(resp.Header)
	resp.Close = true
	resp.Write(c)
}

func handleWebSocketDirect(c *peekReaderConn, req *http.Request) {
	c.enterTunnel()

	rawHost := req.URL.Host
	if rawHost == "" {
		rawHost = req.Host
	}
	hostname, port, err := net.SplitHostPort(rawHost)
	if err != nil {
		hostname = strings.Trim(rawHost, "[]")
		port = "80"
	}

	targetIPs, err := resolveDomainPriority(hostname)
	if err != nil || len(targetIPs) == 0 {
		writeHTTPError(c, http.StatusBadGateway)
		return
	}

	destConn, connectedAddr, err := dialWithFallback(targetIPs, port)
	if err != nil {
		if errors.Is(err, errBlockedDestination) {
			writeHTTPError(c, http.StatusForbidden)
		} else {
			writeHTTPError(c, http.StatusBadGateway)
		}
		return
	}
	defer destConn.Close()

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-c.closed:
			destConn.Close()
		case <-done:
		}
	}()

	req.URL.Scheme = "http"
	req.RequestURI = req.URL.RequestURI()
	if req.RequestURI == "" {
		req.RequestURI = "/"
	}

	removeHopByHopKeepUpgrade(req.Header)

	if err := req.Write(destConn); err != nil {
		writeHTTPError(c, http.StatusBadGateway)
		return
	}

	destConn.SetReadDeadline(time.Now().Add(defaultTransportResponseHeaderTimeout))
	respReader := bufio.NewReader(destConn)
	resp, err := http.ReadResponse(respReader, req)
	if err != nil {
		writeHTTPError(c, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	destConn.SetReadDeadline(time.Time{})

	if err := resp.Write(c); err != nil {
		return
	}

	if config.LogShow {
		log.Printf("[HTTP WEBSOCKET] Handshake response status %d from %s (%s)\n", resp.StatusCode, rawHost, connectedAddr)
	}

	if resp.StatusCode == http.StatusSwitchingProtocols {
		tunnel(c, &bufferedConn{Conn: destConn, r: respReader})
	}
}

// ---------------------------------------------------------------------------
// Xử lý Giao thức SOCKS5
// ---------------------------------------------------------------------------

func socks5Reply(w io.Writer, rep byte) {
	w.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

func readSocks5Address(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err // Lỗi I/O / ngắt kết nối
		}
		return net.IP(b).String(), nil
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(r, l); err != nil {
			return "", err
		}
		d := make([]byte, int(l[0]))
		if _, err := io.ReadFull(r, d); err != nil {
			return "", err
		}
		return string(d), nil
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	default:
		return "", errUnsupportedAtyp // Trả về lỗi chuẩn cho atyp lạ
	}
}

func handleSocks5Direct(c *peekReaderConn) {
	if config.LogShow {
		log.Printf("[SOCKS5] New connection from %s\n", c.RemoteAddr())
	}

	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil {
		return
	}
	if head[0] != 0x05 {
		return
	}

	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}

	if !bytes.Contains(methods, []byte{0x00}) {
		c.Write([]byte{0x05, 0xFF})
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	if req[0] != 0x05 {
		return
	}

	cmd, atyp := req[1], req[3]
	if cmd != 0x01 && cmd != 0x03 {
		socks5Reply(c, 0x07)
		return
	}

	host, err := readSocks5Address(c, atyp)
	if err != nil {
		if !errors.Is(err, errUnsupportedAtyp) {
			return 
		}
		socks5Reply(c, 0x08)
		return
	}

	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return
	}
	portStr := strconv.Itoa(int(binary.BigEndian.Uint16(pb)))

	if cmd == 0x03 {
		handleSocks5UDP(c)
		return
	}

	targetIPs, err := resolveDomainPriority(host)
	if err != nil || len(targetIPs) == 0 {
		if config.LogShow {
			log.Printf("[SOCKS5 ERROR] DNS resolution failed for %s: %v\n", host, err)
		}
		socks5Reply(c, 0x04)
		return
	}

	destConn, targetAddr, err := dialWithFallback(targetIPs, portStr)
	if err != nil {
		if config.LogShow {
			log.Printf("[SOCKS5 ERROR] Connect to %s failed: %v\n", host, err)
		}
		if errors.Is(err, errBlockedDestination) {
			socks5Reply(c, 0x02)
		} else {
			socks5Reply(c, 0x04)
		}
		return
	}
	defer destConn.Close()

	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	if config.LogShow {
		log.Printf("[SOCKS5 CONNECT] Established TCP connection to %s (%s)\n", host, targetAddr)
	}

	tunnel(c, destConn)
}

func udpResponseHeader(addr *net.UDPAddr) []byte {
	h := []byte{0x00, 0x00, 0x00}
	if ip4 := addr.IP.To4(); ip4 != nil {
		h = append(h, 0x01)
		h = append(h, ip4...)
	} else {
		h = append(h, 0x04)
		h = append(h, addr.IP.To16()...)
	}
	return append(h, byte(addr.Port>>8), byte(addr.Port))
}

func handleSocks5UDP(c *peekReaderConn) {
	c.enterTunnel()
	c.noIdle.Store(true)

	clientHost, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		clientHost = c.RemoteAddr().String()
	}
	clientIP := net.ParseIP(clientHost)
	localTCP, ok := c.LocalAddr().(*net.TCPAddr)
	if clientIP == nil || !ok {
		socks5Reply(c, 0x01)
		return
	}

	network := "udp4"
	if localTCP.IP.To4() == nil {
		network = "udp6"
	}

	udpListener, err := net.ListenUDP(network, &net.UDPAddr{IP: localTCP.IP, Zone: localTCP.Zone})
	if err != nil {
		socks5Reply(c, 0x01)
		return
	}
	defer udpListener.Close()

	localAddr := udpListener.LocalAddr().(*net.UDPAddr)
	reply := []byte{0x05, 0x00, 0x00}
	if ip4 := localTCP.IP.To4(); ip4 != nil {
		reply = append(reply, 0x01)
		reply = append(reply, ip4...)
	} else {
		reply = append(reply, 0x04)
		reply = append(reply, localTCP.IP.To16()...)
	}
	reply = append(reply, byte(localAddr.Port>>8), byte(localAddr.Port))
	if _, err := c.Write(reply); err != nil {
		return
	}

	if config.LogShow {
		log.Printf("[SOCKS5 UDP] Associate established, relay listening on %s\n", localAddr)
	}

	var (
		udpConns           = make(map[string]*net.UDPConn)
		udpConnsMutex      sync.Mutex
		clientUDPAddr      atomic.Pointer[net.UDPAddr]
		allowedByHostMutex sync.Mutex
		allowedByHost      = make(map[string]struct {
			cands      []string
			expireTime time.Time
		})
	)
	defer func() {
		udpConnsMutex.Lock()
		for _, oc := range udpConns {
			oc.Close()
		}
		udpConnsMutex.Unlock()
	}()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[RECOVER] Panic in SOCKS5 UDP control watcher: %v\n", r)
			}
		}()
		io.Copy(io.Discard, c)
		udpListener.Close()
	}()

	startReader := func(tc *net.UDPConn, key string) {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[RECOVER] Panic in UDP target reader worker: %v\n", r)
				}
				tc.Close()
				udpConnsMutex.Lock()
				if udpConns[key] == tc {
					delete(udpConns, key)
				}
				udpConnsMutex.Unlock()
			}()
			p := bufferPool.Get().(*[]byte)
			rb := *p
			defer bufferPool.Put(p)
			for {
				tc.SetReadDeadline(time.Now().Add(udpTargetIdleTimeout))
				rn, rAddr, rerr := tc.ReadFromUDP(rb)
				if rerr != nil {
					return
				}
				if rn <= 0 || rAddr == nil {
					continue
				}
				dst := clientUDPAddr.Load()
				if dst == nil {
					continue
				}
				udpListener.WriteToUDP(append(udpResponseHeader(rAddr), rb[:rn]...), dst)
			}
		}()
	}

	pBuf := bufferPool.Get().(*[]byte)
	buf := *pBuf
	defer bufferPool.Put(pBuf)

	for {
		n, remote, err := udpListener.ReadFromUDP(buf)
		if err != nil {
			break
		}
		if !remote.IP.Equal(clientIP) {
			continue
		}
		clientUDPAddr.CompareAndSwap(nil, remote)

		if n < 10 || buf[2] != 0x00 {
			continue
		}

		var targetHost string
		var headerLen int
		switch buf[3] {
		case 0x01:
			targetHost = net.IP(buf[4:8]).String()
			headerLen = 4 + 4 + 2
		case 0x03:
			dl := int(buf[4])
			if dl == 0 || n < 5+dl+2 {
				continue
			}
			targetHost = string(buf[5 : 5+dl])
			headerLen = 4 + 1 + dl + 2
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
		if destPort == 0 {
			continue
		}
		payload := buf[headerLen:n]
		portStr := strconv.Itoa(int(destPort))

		allowedByHostMutex.Lock()
		entry, cached := allowedByHost[targetHost]
		now := time.Now()
		hasValidCache := cached && now.Before(entry.expireTime)
		allowedByHostMutex.Unlock()

		var cands []string
		if hasValidCache {
			cands = entry.cands
		} else {
			ips, rerr := resolveDomainPriority(targetHost)
			var validCands []string
			var exp time.Time
			if rerr != nil {
				exp = time.Now().Add(5 * time.Second)
			} else {
				for _, ip := range ips {
					if isIPAllowed(ip) {
						validCands = append(validCands, ip)
					}
				}
				exp = time.Now().Add(config.DNSCacheExp)
				if config.DNSCacheExp <= 0 {
					exp = time.Now().Add(60 * time.Second)
				}
			}

			allowedByHostMutex.Lock()
			// Cache lại các IP đã phân giải của UDP để tránh mất gói tin đầu tiên (packet loss) khi test.
			// Đưu má, logic của mình mà không nhớ, tự nhiên hỏi sao nó làm vậy ta, nhờ A.I dò hỏi lại thì nhớ ra. Tuổi già sức khỏe cmnr.
			// Mới đầu tính để 1024 record rồi bụp xóa luôn, mà sợ nó sốc. Nên thôi xóa 'dồn lần' theo kiểu 'cuốn chiếu'
/* 			if len(allowedByHost) >= 1024 {
				allowedByHost = make(map[string]struct {
					cands      []string
					expireTime time.Time
				})
			} */
			if len(allowedByHost) >= 1024 {
				// Nếu quá hạn thì xóa thoai
				for k, v := range allowedByHost {
					if now.After(v.expireTime) {
						delete(allowedByHost, k)
					}
				}
				// Trường hợp còn hạn mà bị đầy, tỉa tót, cuốn chiếu 256 tay
				if len(allowedByHost) >= 1024 {
					count := 0
					for k := range allowedByHost {
						delete(allowedByHost, k)
						count++
						if count >= 256 {
							break
						}
					}
				}
			}
			allowedByHost[targetHost] = struct {
				cands      []string
				expireTime time.Time
			}{cands: validCands, expireTime: exp}
			allowedByHostMutex.Unlock()

			cands = validCands
		}

		if len(cands) == 0 {
			continue
		}

		var outConn *net.UDPConn
		var destKey string

		udpConnsMutex.Lock()
		for _, ip := range cands {
			key := net.JoinHostPort(ip, portStr)
			if existing := udpConns[key]; existing != nil {
				outConn, destKey = existing, key
				break
			}
		}
		if outConn == nil && len(udpConns) < maxUDPTargets {
			for _, ip := range cands {
				key := net.JoinHostPort(ip, portStr)
				addr, aerr := net.ResolveUDPAddr("udp", key)
				if aerr != nil {
					continue
				}
				oc, derr := net.DialUDP("udp", nil, addr)
				if derr != nil {
					continue
				}
				outConn, destKey = oc, key
				udpConns[key] = oc
				startReader(oc, key)
				break
			}
		}
		udpConnsMutex.Unlock()
		if outConn == nil {
			continue
		}

		outConn.SetWriteDeadline(time.Now().Add(udpWriteTimeout))
		if _, werr := outConn.Write(payload); werr != nil {
			outConn.Close()
			udpConnsMutex.Lock()
			if udpConns[destKey] == outConn {
				delete(udpConns, destKey)
			}
			udpConnsMutex.Unlock()
		}
	}
}

// ---------------------------------------------------------------------------
// Phân giải DNS Tốc độ cao kèm Singleflight
// ---------------------------------------------------------------------------

func normalizeDomain(d string) (string, error) {
	d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
	if d == "" || len(d) > 253 {
		return "", fmt.Errorf("invalid domain length")
	}
	for i := 0; i < len(d); i++ {
		if d[i] <= 0x20 || d[i] >= 0x7f {
			return "", fmt.Errorf("invalid character in domain")
		}
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" || len(label) > 63 {
			return "", fmt.Errorf("invalid label in domain")
		}
	}
	return d, nil
}

func resolveDomainPriority(domain string) ([]string, error) {
	if ip := net.ParseIP(domain); ip != nil {
		return []string{ip.String()}, nil
	}
	name, err := normalizeDomain(domain)
	if err != nil {
		return nil, err
	}

	useCache := config.DNSCache && config.DNSCacheExp > 0 && config.DNSCacheSize > 0
	if useCache {
		dnsCacheMutex.RLock()
		item, found := dnsCacheStore[name]
		dnsCacheMutex.RUnlock()
		if found && time.Now().Before(item.ExpireTime) {
			if config.LogShow {
				log.Printf("[DNS CACHE HIT] Resolved %s -> [%s] from cache\n", name, strings.Join(item.IPs, " "))
			}
			return item.IPs, nil
		}
	}

	res, err := dnsGroup.Do(name, func() ([]string, error) {
		ips, rerr := resolveDomainActual(name)
		if rerr != nil {
			return nil, rerr
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("no IP found for %s", name)
		}
		if useCache {
			storeDNSCache(name, ips)
		}
		return ips, nil
	})

	if err != nil {
		return nil, err
	}
	return res, nil
}

var dnsCacheOrder = list.New()

func storeDNSCache(name string, ips []string) {
	dnsCacheMutex.Lock()
	defer dnsCacheMutex.Unlock()

	if old, ok := dnsCacheStore[name]; ok {
		currentCacheSize -= old.Size
		dnsCacheOrder.Remove(old.elem)
		delete(dnsCacheStore, name)
	}

	itemSize := int64(len(name) + 32)
	for _, ip := range ips {
		itemSize += int64(len(ip))
	}
	if itemSize > config.DNSCacheSize {
		return
	}

	for currentCacheSize+itemSize > config.DNSCacheSize {
		front := dnsCacheOrder.Front()
		if front == nil {
			break
		}
		k := front.Value.(string)
		currentCacheSize -= dnsCacheStore[k].Size
		delete(dnsCacheStore, k)
		dnsCacheOrder.Remove(front)
	}

	dnsCacheStore[name] = DNSCacheItem{
		IPs:        ips,
		ExpireTime: time.Now().Add(config.DNSCacheExp),
		Size:       itemSize,
		elem:       dnsCacheOrder.PushBack(name),
	}
	currentCacheSize += itemSize

	if config.LogShow {
		log.Printf("[DNS CACHE STORE] Cached %s -> [%s] (Exp: %v)\n", name, strings.Join(ips, " "), config.DNSCacheExp)
	}
}

func resolveDomainActual(domain string) ([]string, error) {
	type step struct {
		label, server string
		fn            func(string, string) ([]string, error)
		plain         bool
	}
	steps := []step{
		{"DoH", config.DNSDOH, queryDoH, false},
		{"DoT", config.DNSDOT, queryDoT, false},
		{"Direct UDP", config.DNSIP, queryUDP, true},
		{"Fallback UDP", config.DNSFallback, queryUDP, true},
	}
	for _, s := range steps {
		if s.server == "" {
			continue
		}
		ips, err := s.fn(s.server, domain)
		if err == nil && len(ips) > 0 {
			if config.LogShow {
				log.Printf("[DNS SUCCESS] Resolved %s -> [%s] via %s (%s)\n", domain, strings.Join(ips, " "), s.label, s.server)
				if s.plain {
					log.Printf("[DNS WARNING] %s was resolved over unencrypted UDP DNS; your ISP may tamper with it\n", domain)
				}
			}
			return ips, nil
		}
	}
	return nil, fmt.Errorf("unable to resolve domain %s using all configured DNS servers", domain)
}

func runClientDNSHealthCheckWithInternal(domain string) {
	fmt.Println("DNS Priority Order for Client:")
	check := func(label, server string, fn func(string, string) ([]string, error)) bool {
		if server == "" {
			fmt.Printf("- %s: NOT CONFIGURED\n", label)
			return false
		}
		if ips, err := fn(server, domain); err == nil && len(ips) > 0 {
			fmt.Printf("- %s (%s): OK\n", label, server)
			return true
		}
		fmt.Printf("- %s (%s): FAILED\n", label, server)
		return false
	}
	dohOK := check("DoH", config.DNSDOH, queryDoH)
	dotOK := check("DoT", config.DNSDOT, queryDoT)
	check("Direct IP", config.DNSIP, queryUDP)
	check("Fallback", config.DNSFallback, queryUDP)
	if !dohOK && !dotOK {
		fmt.Println("[WARNING] Neither DoH nor DoT works: DNS will fall back to UDP port 53")
	}
}

func queryDual(domain, label string, exec func([]byte, uint16) ([]string, error)) ([]string, error) {
	qV4, idV4 := buildDNSQueryWithType(domain, 1)
	qV6, idV6 := buildDNSQueryWithType(domain, 28)

	var v4Res, v6Res []string
	var errV4, errV6 error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		v6Res, errV6 = exec(qV6, idV6)
	}()
	go func() {
		defer wg.Done()
		v4Res, errV4 = exec(qV4, idV4)
	}()
	wg.Wait()

	var final []string
	if errV6 == nil {
		final = append(final, v6Res...)
	}
	if errV4 == nil {
		final = append(final, v4Res...)
	}
	if len(final) > 0 {
		return final, nil
	}
	return nil, fmt.Errorf("%s resolution failed for both IPv4 and IPv6", label)
}

func queryDoH(dohURL, domain string) ([]string, error) {
	return queryDual(domain, "DoH", func(q []byte, id uint16) ([]string, error) {
		return executeDoHRequest(dohURL, q, id)
	})
}

func queryDoT(dotHost, domain string) ([]string, error) {
	return queryDual(domain, "DoT", func(q []byte, id uint16) ([]string, error) {
		return executeDoTRequest(dotHost, q, id)
	})
}

func queryUDP(dnsServer, domain string) ([]string, error) {
	return queryDual(domain, "UDP DNS", func(q []byte, id uint16) ([]string, error) {
		return executeUDPRequest(dnsServer, q, id)
	})
}

func splitHostPortDefault(s, defPort string) (string, string) {
	if h, p, err := net.SplitHostPort(s); err == nil {
		return h, p
	}
	return strings.Trim(s, "[]"), defPort
}

func executeDoHRequest(dohURL string, query []byte, expectedID uint16) ([]string, error) {
	req, err := http.NewRequest("POST", dohURL, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := dohClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH status code: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}
	return parseDNSResponse(body, expectedID)
}

func executeDoTRequest(dotHost string, query []byte, expectedID uint16) ([]string, error) {
	host, port := splitHostPortDefault(dotHost, "853")
	tlsConfig := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: defaultDoXTimeout}, "tcp", net.JoinHostPort(host, port), tlsConfig)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(defaultDoXTimeout))

	msg := make([]byte, 2, 2+len(query))
	binary.BigEndian.PutUint16(msg, uint16(len(query)))
	msg = append(msg, query...)
	if _, err := conn.Write(msg); err != nil {
		return nil, err
	}

	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, err
	}
	respLen := binary.BigEndian.Uint16(lenBuf)
	if respLen == 0 {
		return nil, fmt.Errorf("empty DoT response")
	}
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		return nil, err
	}
	return parseDNSResponse(respBuf, expectedID)
}

func executeUDPRequest(dnsServer string, query []byte, expectedID uint16) ([]string, error) {
	host, port := splitHostPortDefault(dnsServer, "53")

	conn, err := net.DialTimeout("udp", net.JoinHostPort(host, port), defaultDNSTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	respBuf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(defaultDNSTimeout))
	n, err := conn.Read(respBuf)
	if err != nil {
		return nil, err
	}
	return parseDNSResponse(respBuf[:n], expectedID)
}

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

	binary.Write(&buf, binary.BigEndian, qtype)
	binary.Write(&buf, binary.BigEndian, uint16(1))

	return buf.Bytes(), id
}

func parseDNSResponse(data []byte, expectedID uint16) ([]string, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("response too short")
	}

	respID := binary.BigEndian.Uint16(data[0:2])
	if respID != expectedID {
		return nil, fmt.Errorf("DNS transaction ID mismatch")
	}
	flags := binary.BigEndian.Uint16(data[2:4])
	if flags&0x8000 == 0 {
		return nil, fmt.Errorf("not a DNS response")
	}
	if rcode := flags & 0x000F; rcode != 0 {
		return nil, fmt.Errorf("DNS error rcode=%d", rcode)
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

	resultIPs := append(ipv6List, ipv4List...)
	if len(resultIPs) > 0 {
		return resultIPs, nil
	}

	return nil, fmt.Errorf("no usable IP address found")
}

// ---------------------------------------------------------------------------
// Tải Cấu hình
// ---------------------------------------------------------------------------

func resolveConfigPath(name string) string {
	if _, err := os.Stat(name); err == nil {
		return name
	}
	if exe, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(exe), name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return name
}

func loadConfig(filepath string) {
	config = Config{
		LogShow:          false,
		ListenAddress:    ":3979",
		ReadTimeout:      10 * time.Second,
		WriteTimeout:     10 * time.Second,
		IdleTimeout:      60 * time.Second,
		ClientTimeout:    60 * time.Second,
		DNSFallback:      "208.67.222.222",
		DNSIP:            "8.8.8.8",
		DNSDOH:           "https://1.1.1.1/dns-query",
		DNSDOT:           "1.1.1.1",
		DNSCache:         true,
		DNSCacheSize:     1024 * 1024,
		DNSCacheExp:      60 * time.Second,
		ClientAllowlist:  "127.0.0.1; ::1",
		AllowPrivateIP:   false,
		AllowPrivateDest: "",
	}

	file, err := os.Open(filepath)
	if err != nil {
		fmt.Printf("The config file %s is missing, use default hard code.\n", filepath)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "\ufeff"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			log.Printf("[CONFIG] line %d ignored (expected key = value)\n", lineNo)
			continue
		}

		key := strings.ToLower(strings.TrimSpace(parts[0]))
		val := stripInlineComment(strings.TrimSpace(parts[1]))

		switch key {
		case "logshow":
			config.LogShow = parseBool(val)
		case "listenaddress":
			config.ListenAddress = val
		case "readtimeout":
			config.ReadTimeout = parseDuration(key, val, config.ReadTimeout)
		case "writetimeout":
			config.WriteTimeout = parseDuration(key, val, config.WriteTimeout)
		case "idletimeout":
			config.IdleTimeout = parseDuration(key, val, config.IdleTimeout)
		case "clienttimeout":
			config.ClientTimeout = parseDuration(key, val, config.ClientTimeout)
		case "dnsfallback":
			config.DNSFallback = val
		case "dnsip":
			config.DNSIP = val
		case "dnsdoh":
			config.DNSDOH = val
		case "dnsdot":
			config.DNSDOT = val
		case "dnscache":
			config.DNSCache = parseBool(val)
		case "dnscachesize":
			config.DNSCacheSize = parseCacheSize(val)
		case "dnscacheexp":
			config.DNSCacheExp = parseDuration(key, val, config.DNSCacheExp)
		case "clientallowlist":
			config.ClientAllowlist = val
		case "allowprivateip":
			config.AllowPrivateIP = parseBool(val)
		case "allowprivatedest":
			config.AllowPrivateDest = val
		default:
			log.Printf("[CONFIG] line %d: unknown key %q ignored\n", lineNo, key)
		}
	}
}

func stripInlineComment(s string) string {
	for i := 1; i < len(s); i++ {
		if s[i] == '#' && (s[i-1] == ' ' || s[i-1] == '\t') {
			return strings.TrimSpace(s[:i])
		}
	}
	return s
}

func parseBool(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "yes", "true", "1", "on":
		return true
	}
	return false
}

func parseCacheSize(s string) int64 {
	const def = 1024 * 1024
	s = strings.ToUpper(strings.TrimSpace(s))
	var multiplier int64 = 1
	switch {
	case strings.HasSuffix(s, "KB"):
		multiplier, s = 1024, strings.TrimSuffix(s, "KB")
	case strings.HasSuffix(s, "MB"):
		multiplier, s = 1024*1024, strings.TrimSuffix(s, "MB")
	case strings.HasSuffix(s, "GB"):
		multiplier, s = 1024*1024*1024, strings.TrimSuffix(s, "GB")
	case strings.HasSuffix(s, "B"):
		s = strings.TrimSuffix(s, "B")
	}
	size, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || size <= 0 {
		log.Printf("[CONFIG] invalid dnsCacheSize, using default 1MB\n")
		return def
	}
	return size * multiplier
}

func parseDuration(key, val string, current time.Duration) time.Duration {
	if d, err := time.ParseDuration(val); err == nil && d >= 0 {
		return d
	}
	if n, err := strconv.Atoi(val); err == nil && n >= 0 {
		return time.Duration(n) * time.Second
	}
	log.Printf("[CONFIG] invalid duration for %s: %q (keeping %v)\n", key, val, current)
	return current
}