package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/truesignal/sdk-go"
	sdkdecoy "github.com/truesignal/sdk-go/decoy"
)

// reporter is the slice of the SDK the handlers use, so they can be tested
// with a fake. *sdk.Sensor satisfies it.
type reporter interface {
	ReportEventSeverity(severity, trigger, source, target string, details sdk.EventDetails) bool
}

// decoy serves one skin.
type decoy struct {
	ts           reporter
	skin         Skin
	passwordMode string
	passwordKey  []byte
	probes       *probeLimiter
	// logins caps web_login_attempt events per source, so a password spray
	// cannot fill the SDK queue (1000) and push out other alerts.
	logins     *sdkdecoy.Limiter
	loginDelay time.Duration
}

// loginsPerMinute matches the other credential decoys.
const loginsPerMinute = 20

// brandProfiles keeps the page footer consistent with the advertised brand;
// a "Netgear" header over a Cisco model number is an instant tell.
var brandProfiles = map[string][2]string{
	"netgear": {"R7000", "V1.0.11.134_10.2.120"},
	"tp-link": {"Archer C7", "3.15.3 Build 180114"},
	"tplink":  {"Archer C7", "3.15.3 Build 180114"},
	"cisco":   {"RV340", "1.0.03.20"},
	"asus":    {"RT-AC68U", "3.0.0.4.386_51665"},
	"linksys": {"EA7500", "2.0.8.194281"},
}

func brandProfile(brand string) (model, firmware string) {
	if p, ok := brandProfiles[strings.ToLower(strings.TrimSpace(brand))]; ok {
		return p[0], p[1]
	}
	return "GW-2200", "2.4.1"
}

func main() {
	ts, err := sdk.NewSensor()
	if err != nil {
		log.Fatalf("[!] FATAL: %v", err)
	}

	ts.SetTestPayload(
		"web_login_attempt",
		"Wizard Firedrill",
		"Web Interface",
		sdk.EventDetails{
			{Key: "test_message", Value: "Wizard triggered a synthetic event firedrill."},
			{Key: "user_agent", Value: "TrueSignal-Firedrill/1.0"},
			{Key: "attempted_username", Value: "admin"},
			{Key: "attempted_password_hmac", Value: "firedrill"},
			{Key: "skin", Value: "router"},
			{Key: "auth", Value: "form"},
			{Key: "action_taken", Value: "logged"},
		},
	)

	// Load environment variables AFTER the SDK loads the .env file
	port := getEnv("TS_BIND_PORT", "8080")
	brand := getEnv("TS_ROUTER_BRAND", "Netgear")
	skin, err := loadSkin(getEnv("TS_SKIN", "router"), os.Getenv("TS_SKIN_PRODUCT"), brand, os.Getenv("TS_SKIN_JSON"))
	if err != nil {
		log.Fatalf("[!] FATAL: %v", err)
	}
	d := &decoy{
		ts:           ts,
		skin:         skin,
		passwordMode: strings.ToLower(getEnv("TS_CAPTURE_PASSWORDS", "hash")),
		passwordKey:  passwordHashKey(os.Getenv("TS_CAPTURE_HASH_KEY"), os.Getenv("TS_HUB_KEY")),
		probes:       newProbeLimiter(60 * time.Second),
		logins:       sdkdecoy.NewLimiter(loginsPerMinute, time.Minute),
		loginDelay:   1500 * time.Millisecond,
	}

	if ts.TestMode {
		if ts.RunTestMode() {
			os.Exit(0)
		}
		os.Exit(1)
	}

	server := &http.Server{
		Addr:              fmt.Sprintf("0.0.0.0:%s", port),
		Handler:           limitBody(d.routes()),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	// Run server in background
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[!] FATAL: Web server failed: %v", err)
		}
	}()
	log.Printf("[*] TrueSignal Web Decoy | Skin: %s (%s) | Port: %s | Password capture: %s", skin.Name, skin.Product, port, d.passwordMode)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := ts.Start(); err != nil {
		log.Fatalf("[!] FATAL: %v", err)
	}
	defer ts.Stop()

	<-ctx.Done()

	log.Println("[*] Shutting down web decoy...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("[-] Shutdown error: %v", err)
	}
}

func clientIP(r *http.Request) string {
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return ip
	}
	return r.RemoteAddr
}

func userAgent(r *http.Request) string {
	if ua := r.UserAgent(); ua != "" {
		return ua
	}
	return "Unknown"
}

func (d *decoy) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", d.handleRoot)
	if !d.skin.Basic {
		mux.HandleFunc(d.skin.LoginPath, d.handleLogin)
	}
	return mux
}

func (d *decoy) setHeaders(w http.ResponseWriter) {
	if d.skin.ServerHeader != "" {
		w.Header().Set("Server", d.skin.ServerHeader)
	}
}

// renderLogin writes the skin's login page, with the error block after a
// failed attempt.
func (d *decoy) renderLogin(w http.ResponseWriter, status int, failed bool) {
	d.setHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	loginTemplate.Execute(w, pageData{Skin: d.skin, Failed: failed})
}

// challenge answers a Basic-auth skin request with 401 and the realm.
func (d *decoy) challenge(w http.ResponseWriter) {
	d.setHeaders(w)
	w.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=%q", d.skin.Realm))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	basicTemplate.Execute(w, d.skin)
}

// handleRoot serves the login page and records reconnaissance: page views and
// probes for other paths (/.env, /admin, /cgi-bin/...) at medium severity,
// rate-limited per source so a directory brute-force yields a few events.
// Basic-auth skins challenge every path and record any credentials sent.
func (d *decoy) handleRoot(w http.ResponseWriter, r *http.Request) {
	srcIP := clientIP(r)
	if d.skin.Basic {
		if user, pass, ok := r.BasicAuth(); ok {
			d.reportLogin(r, user, pass, "basic", nil)
			time.Sleep(d.loginDelay)
			d.challenge(w)
			return
		}
	}
	if d.probes.allow(srcIP, time.Now()) {
		trigger := "web_page_view"
		if r.URL.Path != "/" {
			trigger = "web_path_probe"
		}
		d.ts.ReportEventSeverity("medium", trigger, srcIP, d.target(), sdk.EventDetails{
			{Key: "method", Value: r.Method},
			{Key: "path", Value: truncate(r.URL.RequestURI(), 512)},
			{Key: "user_agent", Value: truncate(userAgent(r), 512)},
			{Key: "skin", Value: d.skin.Name},
		})
	}
	if d.skin.Basic {
		d.challenge(w)
		return
	}
	if r.URL.Path != "/" {
		d.setHeaders(w)
		http.NotFound(w, r)
		return
	}
	d.renderLogin(w, http.StatusOK, false)
}

func (d *decoy) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		d.setHeaders(w)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		d.setHeaders(w)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// Extra form fields (a VPN realm, a domain selector) are recorded too:
	// they say what the attacker believes they are logging in to.
	var extra sdk.EventDetails
	for _, f := range d.skin.Fields {
		if f.Name != d.skin.UserField && f.Name != d.skin.PassField {
			if v := r.PostFormValue(f.Name); v != "" {
				extra = append(extra, sdk.EventDetail{Key: "form_" + f.Name, Value: truncate(v, 256)})
			}
		}
	}
	d.reportLogin(r, r.PostFormValue(d.skin.UserField), r.PostFormValue(d.skin.PassField), "form", extra)

	// Tarpit delay: an artificial backend processing delay slows automated
	// scripts, then the same page comes back with the error shown.
	time.Sleep(d.loginDelay)
	d.renderLogin(w, http.StatusUnauthorized, true)
}

// reportLogin records a web_login_attempt. attempted_username is the key the
// Hub matches honeytokens on.
//
// Events beyond loginsPerMinute per source are dropped and counted; the next
// event emitted for that source carries suppressed_since_last. The attacker
// sees no difference: every attempt still gets the delay and the error page.
func (d *decoy) reportLogin(r *http.Request, user, password, auth string, extra sdk.EventDetails) {
	srcIP := clientIP(r)
	ok, suppressed := d.logins.Allow(srcIP)
	if !ok {
		return
	}
	username := truncate(user, 256)
	log.Printf("[!] Login attempt from %s (User: %q, skin %s)", srcIP, username, d.skin.Name)
	details := sdk.EventDetails{
		{Key: "user_agent", Value: truncate(userAgent(r), 512)},
		{Key: "attempted_username", Value: username},
	}
	details = append(details, passwordDetails(password, d.passwordMode, d.passwordKey)...)
	details = append(details,
		sdk.EventDetail{Key: "skin", Value: d.skin.Name},
		sdk.EventDetail{Key: "auth", Value: auth},
		sdk.EventDetail{Key: "path", Value: truncate(r.URL.Path, 256)})
	details = append(details, extra...)
	if suppressed > 0 {
		details = append(details, sdk.EventDetail{Key: "suppressed_since_last", Value: suppressed})
	}
	details = append(details, sdk.EventDetail{Key: "action_taken", Value: "logged"})
	// Empty severity: the sensor's TS_SEVERITY (critical by default).
	d.ts.ReportEventSeverity("", "web_login_attempt", srcIP, d.target(), details)
}

func (d *decoy) target() string {
	return "Web Interface (" + d.skin.Product + ")"
}

// passwordDetails decides how much of a submitted password leaves the decoy.
// The default ("hash") records a keyed HMAC-SHA256 and the length instead of
// storing it. If staff ever type a real password here it must not end up in
// cleartext in the Hub DB, SIEM or exports, and a plain SHA-256 would be
// reversible for common passwords by anyone holding those records. "plain"
// opts in to cleartext capture; "none" records only that a password was
// submitted.
func passwordDetails(password, mode string, key []byte) sdk.EventDetails {
	switch mode {
	case "plain":
		return sdk.EventDetails{{Key: "attempted_password", Value: truncate(password, 256)}}
	case "none":
		return sdk.EventDetails{{Key: "password_submitted", Value: password != ""}}
	default:
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(password))
		return sdk.EventDetails{
			{Key: "attempted_password_hmac", Value: hex.EncodeToString(mac.Sum(nil))},
			{Key: "attempted_password_length", Value: len(password)},
			{Key: "hmac_key_id", Value: keyID(key)},
		}
	}
}

// passwordHashKey picks the HMAC key. TS_CAPTURE_HASH_KEY, set to the same
// value on every node, makes the same password correlate fleet-wide. Without
// it the node key is used: stable per node, and the Hub stores only its hash,
// so Hub/SIEM records alone can't be brute-forced.
func passwordHashKey(captureKey, nodeKey string) []byte {
	if captureKey != "" {
		return []byte(captureKey)
	}
	return []byte("truesignal-capture:" + nodeKey)
}

// keyID lets analysts tell which key produced an HMAC without revealing it.
func keyID(key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("truesignal-key-id"))
	return hex.EncodeToString(mac.Sum(nil))[:8]
}

func truncate(s string, n int) string {
	s = strings.ToValidUTF8(s, "?")
	if len(s) > n {
		return s[:n]
	}
	return s
}

func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		next.ServeHTTP(w, r)
	})
}

// probeLimiter emits at most one reconnaissance event per source per window.
type probeLimiter struct {
	mu     sync.Mutex
	window time.Duration
	last   map[string]time.Time
}

func newProbeLimiter(window time.Duration) *probeLimiter {
	return &probeLimiter{window: window, last: map[string]time.Time{}}
}

func (p *probeLimiter) allow(key string, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if t, ok := p.last[key]; ok && now.Sub(t) < p.window {
		return false
	}
	p.last[key] = now
	if len(p.last) > 10000 {
		for k, t := range p.last {
			if now.Sub(t) >= p.window {
				delete(p.last, k)
			}
		}
	}
	return true
}

func getEnv(key, fallback string) string {
	if val, exists := os.LookupEnv(key); exists {
		return val
	}
	return fallback
}
