package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/truesignal/sdk-go"
)

var (
	decoyPorts = parsePorts(getEnv("TS_DECOY_PORTS", "2222,3306"))
	tarpitMode = strings.ToLower(getEnv("TS_TARPIT_MODE", "hold"))
	// banner is the fallback for ports without an entry in TS_TARPIT_BANNERS.
	banner      = parseBanner(getEnv("TS_TARPIT_BANNER", ""))
	portBanners = parsePortBanners(getEnv("TS_TARPIT_BANNERS", "22=SSH-2.0-OpenSSH_8.2p1\\r\\n;2222=SSH-2.0-OpenSSH_8.2p1\\r\\n"))
	concurrency = 1000
	maxBytes    = 50 * 1024
	maxLines    = 10
	maxDuration = 3600 * time.Second
)

func main() {
	ts, err := sdk.NewSensor()
	if err != nil {
		log.Fatalf("[!] FATAL: %v", err)
	}

	ts.SetTestPayload(
		"tcp_connection",
		"Wizard Firedrill",
		"Mock Tarpit Port",
		sdk.EventDetails{
			{Key: "test_message", Value: "Wizard triggered a synthetic event firedrill."},
			{Key: "payload", Value: []string{"SSH-2.0-Firedrill-Test\r\n"}},
			{Key: "duration_sec", Value: 5.2},
			{Key: "action_taken", Value: "hold"},
		},
	)

	if ts.TestMode {
		if ts.RunTestMode() {
			os.Exit(0)
		}
		os.Exit(1)
	}

	var listeners []net.Listener
	var lc net.ListenConfig
	for _, port := range decoyPorts {
		addr := fmt.Sprintf("0.0.0.0:%d", port)
		l, err := lc.Listen(context.Background(), "tcp", addr)
		if err != nil {
			log.Fatalf("[!] FATAL: Failed to bind to port %d: %v", port, err)
		}
		listeners = append(listeners, l)
	}

	log.Printf("[*] TrueSignal Tarpit | Mode: %s", strings.ToUpper(tarpitMode))

	semaphore := make(chan struct{}, concurrency)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	for i, listener := range listeners {
		go startListener(ctx, ts, decoyPorts[i], listener, semaphore)
	}

	if err := ts.Start(); err != nil {
		log.Fatalf("[!] FATAL: %v", err)
	}
	defer ts.Stop()

	<-ctx.Done()
	log.Println("[*] Tarpit shutting down.")
}

func startListener(ctx context.Context, ts *sdk.Sensor, port int, listener net.Listener, semaphore chan struct{}) {
	defer listener.Close()

	log.Printf("[+] Tarpit listening on port %d", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			// Break if context was cancelled
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("[-] Accept error on port %d: %v", port, err)
				continue
			}
		}

		semaphore <- struct{}{}
		go func(c net.Conn) {
			defer func() { <-semaphore }()
			handleConnection(ts, c, port)
		}(conn)
	}
}

func handleConnection(ts *sdk.Sensor, conn net.Conn, port int) {
	defer conn.Close()
	start := time.Now()

	remoteAddr := conn.RemoteAddr().String()
	srcIP, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		srcIP = remoteAddr
	}

	var payload []string
	consumedBytes := 0

	// Alert on the connection itself, immediately. In hold mode a session can
	// stay open for up to maxDuration; waiting for it to end would delay the
	// alert by up to an hour.
	ts.ReportEvent(
		"tcp_connection",
		srcIP,
		fmt.Sprintf("Port %d", port),
		sdk.EventDetails{
			{Key: "phase", Value: "connect"},
			{Key: "action_taken", Value: tarpitMode},
		},
	)

	portBanner := bannerFor(port)
	if portBanner != "" && tarpitMode != "close" {
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		conn.Write([]byte(portBanner))
	}

	if tarpitMode != "close" {
		buf := make([]byte, 1024)
		for consumedBytes < maxBytes && time.Since(start) < maxDuration {
			conn.SetReadDeadline(time.Now().Add(300 * time.Second))
			n, err := conn.Read(buf)

			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
					conn.Write([]byte{0})
					continue
				}
				break
			}

			if n > 0 {
				consumedBytes += n

				if len(payload) < maxLines {
					text := strings.TrimSpace(strings.ToValidUTF8(string(buf[:n]), "?"))
					if text != "" {
						payload = append(payload, text)
					}
				}

				if tarpitMode == "echo" {
					conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
					conn.Write(buf[:n])
				}

				time.Sleep(500 * time.Millisecond)
			}
		}
	}

	// Follow up only when the session revealed something (what the client
	// sent); a bare connect/close adds nothing to the first event.
	if len(payload) == 0 {
		return
	}
	ts.ReportEvent(
		"tcp_session_payload",
		srcIP,
		fmt.Sprintf("Port %d", port),
		sdk.EventDetails{
			{Key: "phase", Value: "close"},
			{Key: "duration_sec", Value: time.Since(start).Seconds()},
			{Key: "bytes_received", Value: consumedBytes},
			{Key: "payload", Value: payload},
			{Key: "action_taken", Value: tarpitMode},
		},
	)
}

// bannerFor returns the banner to present on a port. Server-first protocols
// must look right: an SSH banner on a MySQL port is an instant tell.
func bannerFor(port int) string {
	if b, ok := portBanners[port]; ok {
		return b
	}
	return banner
}

// parsePortBanners parses "port=banner;port=banner". An empty banner means
// "send nothing" for that port.
func parsePortBanners(raw string) map[int]string {
	out := make(map[int]string)
	for _, entry := range strings.Split(raw, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		k, v, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if p, err := strconv.Atoi(strings.TrimSpace(k)); err == nil && p > 0 && p <= 65535 {
			out[p] = parseBanner(v)
		}
	}
	return out
}

func parsePorts(raw string) []int {
	var ports []int
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if val, err := strconv.Atoi(p); err == nil && val > 0 && val <= 65535 {
			ports = append(ports, val)
		}
	}
	if len(ports) == 0 {
		return []int{2222, 3306}
	}
	return ports
}

func parseBanner(raw string) string {
	raw = strings.ReplaceAll(raw, "\\r", "\r")
	raw = strings.ReplaceAll(raw, "\\n", "\n")
	return raw
}

func getEnv(key, fallback string) string {
	if val, exists := os.LookupEnv(key); exists {
		return val
	}
	return fallback
}
