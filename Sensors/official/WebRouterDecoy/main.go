package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html"
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
)

var (
	port         string
	routerBrand  string
	passwordMode string
	passwordKey  []byte
	ts           *sdk.Sensor
	probes       = newProbeLimiter(60 * time.Second)
)

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

// The HTML template: %[1]s brand, %[2]s error block display, %[3]s model, %[4]s firmware
const loginHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>%[1]s Router Login</title>

<style>
* {
    box-sizing: border-box;
}

body {
    margin: 0;
    font-family: Arial, Helvetica, sans-serif;
    background: #dfe3e8;
    color: #333;
}

.header {
    height: 64px;
    background: linear-gradient(to bottom, #3b6ea5, #2c5d90);
    border-bottom: 1px solid #21486f;
    display: flex;
    align-items: center;
    padding: 0 24px;
    color: white;
}

.brand {
    font-size: 24px;
    font-weight: bold;
    letter-spacing: 0.5px;
}

.container {
    width: 100%%;
    max-width: 520px;
    margin: 80px auto;
}

.panel {
    background: white;
    border: 1px solid #b7bec8;
}

.panel-header {
    background: #f2f4f7;
    border-bottom: 1px solid #d3d8de;
    padding: 12px 16px;
    font-weight: bold;
    color: #444;
}

.panel-body {
    padding: 24px;
}

.info {
    margin-bottom: 20px;
    font-size: 13px;
    color: #666;
    line-height: 1.5;
}

.error {
    display: %[2]s;
    background: #fff2f2;
    border: 1px solid #d77;
    color: #a00000;
    padding: 10px;
    margin-bottom: 18px;
    font-size: 13px;
}

.form-row {
    margin-bottom: 16px;
}

label {
    display: block;
    margin-bottom: 6px;
    font-size: 13px;
    font-weight: bold;
}

input {
    width: 100%%;
    height: 34px;
    padding: 0 10px;
    border: 1px solid #aeb6bf;
    font-size: 13px;
}

input:focus {
    outline: none;
    border-color: #3b6ea5;
}

.actions {
    margin-top: 20px;
}

button {
    min-width: 100px;
    height: 34px;
    border: 1px solid #1f4d79;
    background: linear-gradient(to bottom, #4a7ab0, #2f5f95);
    color: white;
    font-weight: bold;
    cursor: pointer;
}

button:hover {
    background: linear-gradient(to bottom, #5385bc, #35689f);
}

.footer {
    margin-top: 14px;
    padding: 12px;
    background: #f7f7f7;
    border: 1px solid #cfd4da;
    font-size: 12px;
    color: #666;
    line-height: 1.6;
}

.footer-row {
    display: flex;
    justify-content: space-between;
}

@media (max-width: 600px) {
    .container {
        margin: 20px;
    }
}
</style>
</head>

<body>

<div class="header">
    <div class="brand">%[1]s</div>
</div>

<div class="container">

    <div class="panel">

        <div class="panel-header">
            Router Login
        </div>

        <div class="panel-body">

            <div class="info">
                Enter administrator credentials to access the device management interface.
            </div>

            <div class="error">
                Login failed. Incorrect username or password.
            </div>

            <form method="post" action="/login">

                <div class="form-row">
                    <label for="username">Username</label>
                    <input
                        id="username"
                        name="username"
                        type="text"
                        autocomplete="username"
                        required
                    >
                </div>

                <div class="form-row">
                    <label for="password">Password</label>
                    <input
                        id="password"
                        name="password"
                        type="password"
                        autocomplete="current-password"
                        required
                    >
                </div>

                <div class="actions">
                    <button type="submit">Login</button>
                </div>

            </form>

        </div>
    </div>

    <div class="footer">
        <div class="footer-row">
            <span>Model</span>
            <span>%[3]s</span>
        </div>

        <div class="footer-row">
            <span>Firmware Version</span>
            <span>%[4]s</span>
        </div>

        <div class="footer-row">
            <span>Hardware Version</span>
            <span>1.0</span>
        </div>
    </div>

</div>

</body>
</html>`

func main() {
	var err error
	ts, err = sdk.NewSensor()
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
			{Key: "attempted_password", Value: "password123"},
			{Key: "action_taken", Value: "logged"},
		},
	)

	// Load environment variables AFTER the SDK loads the .env file
	port = getEnv("TS_BIND_PORT", "8080")
	routerBrand = getEnv("TS_ROUTER_BRAND", "Netgear")
	passwordMode = strings.ToLower(getEnv("TS_CAPTURE_PASSWORDS", "hash"))
	passwordKey = passwordHashKey(os.Getenv("TS_CAPTURE_HASH_KEY"), os.Getenv("TS_HUB_KEY"))

	if ts.TestMode {
		if ts.RunTestMode() {
			os.Exit(0)
		}
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleRoot)
	mux.HandleFunc("/login", handleLogin)

	server := &http.Server{
		Addr:              fmt.Sprintf("0.0.0.0:%s", port),
		Handler:           limitBody(mux),
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
	log.Printf("[*] TrueSignal Web Router Decoy | Brand: %s | Port: %s | Password capture: %s", routerBrand, port, passwordMode)

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

// renderLogin writes the login page; errorDisplay is "none" or "block".
func renderLogin(w http.ResponseWriter, status int, errorDisplay string) {
	model, firmware := brandProfile(routerBrand)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	// codeql[go/xss] Honeypot decoy rendering; all interpolated values are HTML-escaped.
	// nosemgrep: go.lang.security.audit.xss.no-fprintf-to-responsewriter.no-fprintf-to-responsewriter
	fmt.Fprintf(w, loginHTML, html.EscapeString(routerBrand), errorDisplay, html.EscapeString(model), html.EscapeString(firmware))
}

// handleRoot serves the login page and records reconnaissance: page views and
// probes for other paths (/.env, /admin, /cgi-bin/...) at medium severity,
// rate-limited per source so a directory brute-force yields a few events.
func handleRoot(w http.ResponseWriter, r *http.Request) {
	srcIP := clientIP(r)
	if probes.allow(srcIP, time.Now()) {
		trigger := "web_page_view"
		if r.URL.Path != "/" {
			trigger = "web_path_probe"
		}
		ts.ReportEventSeverity("medium", trigger, srcIP, "Web Interface", sdk.EventDetails{
			{Key: "method", Value: r.Method},
			{Key: "path", Value: truncate(r.URL.RequestURI(), 512)},
			{Key: "user_agent", Value: truncate(userAgent(r), 512)},
		})
	}

	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	renderLogin(w, http.StatusOK, "none")
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	username := truncate(r.FormValue("username"), 256)
	password := r.FormValue("password")
	srcIP := clientIP(r)

	log.Printf("[!] Login attempt from %s (User: %q)", srcIP, username)

	details := sdk.EventDetails{
		{Key: "user_agent", Value: truncate(userAgent(r), 512)},
		{Key: "attempted_username", Value: username},
	}
	details = append(details, passwordDetails(password, passwordMode, passwordKey)...)
	details = append(details, sdk.EventDetail{Key: "action_taken", Value: "logged"})

	ts.ReportEvent("web_login_attempt", srcIP, "Web Interface", details)

	// Tarpit delay: Add an artificial backend processing delay to slow down automated scripts
	time.Sleep(1500 * time.Millisecond)

	// Re-render the exact same login page, but cleanly display the red error block
	renderLogin(w, http.StatusUnauthorized, "block")
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
