package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/truesignal/sdk-go"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func main() {
	ts, err := sdk.NewSensor()
	if err != nil {
		log.Fatalf("[!] FATAL: Failed to initialize sensor: %v", err)
	}

	ts.SetTestPayload(
		"icmp_scan_received",
		"Wizard Firedrill",
		"ICMP Listener",
		sdk.EventDetails{
			{Key: "test_message", Value: "Wizard triggered a synthetic event firedrill."},
			{Key: "icmp_type", Value: "Timestamp Request"},
			{Key: "packet_size", Value: 64},
			{Key: "icmp_id", Value: 1337},
			{Key: "icmp_seq", Value: 1},
		},
	)

	if ts.TestMode {
		if ts.RunTestMode() {
			log.Println("✅ Test mode complete. Exiting gracefully.")
			os.Exit(0)
		}
		log.Println("❌ Test mode failed to contact Hub.")
		os.Exit(1)
	}

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		log.Fatalf("[!] FATAL: Failed to listen for ICMP: %v\n(Ensure container has CAP_NET_RAW capability)", err)
	}
	defer conn.Close()

	log.Printf("[*] TrueSignal Ping Canary | Listening for ICMP Echo Requests...")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go listenICMP(conn, ts)

	if err := ts.Start(); err != nil {
		log.Fatalf("[!] FATAL: Failed to sync with Hub: %v", err)
	}
	defer ts.Stop() // Clean up goroutines!

	// Block until shutdown signal
	<-ctx.Done()
	log.Println("[*] Shutdown signal received. Exiting.")
}

// icmpThrottle aggregates repeated packets from the same source and type so a
// sweep or monitor produces one event per cooldown window (with a count)
// instead of one event per packet.
type icmpThrottle struct {
	cooldown time.Duration
	last     map[string]time.Time
	dropped  map[string]int
}

func newThrottle(cooldown time.Duration) *icmpThrottle {
	return &icmpThrottle{cooldown: cooldown, last: map[string]time.Time{}, dropped: map[string]int{}}
}

// allow reports whether an event should be emitted now, and how many packets
// were suppressed since the previous emitted event for this key.
func (t *icmpThrottle) allow(key string, now time.Time) (bool, int) {
	if t.cooldown <= 0 {
		return true, 0
	}
	if last, ok := t.last[key]; ok && now.Sub(last) < t.cooldown {
		t.dropped[key]++
		return false, 0
	}
	suppressed := t.dropped[key]
	t.last[key] = now
	delete(t.dropped, key)
	if len(t.last) > 10000 {
		for k, ts := range t.last {
			if now.Sub(ts) >= t.cooldown {
				delete(t.last, k)
				delete(t.dropped, k)
			}
		}
	}
	return true, suppressed
}

func listenICMP(conn *icmp.PacketConn, ts *sdk.Sensor) {
	throttle := newThrottle(time.Duration(getEnvInt("TS_ICMP_COOLDOWN", 60)) * time.Second)
	buf := make([]byte, 1500)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			log.Printf("[-] Read error: %v", err)
			continue
		}

		msg, err := icmp.ParseMessage(1, buf[:n])
		if err != nil {
			continue
		}

		// Clean the IP string
		sourceIP := addr.String()
		if host, _, err := net.SplitHostPort(sourceIP); err == nil {
			sourceIP = host
		}

		var icmpTypeStr string
		var icmpID, icmpSeq int

		switch msg.Type {
		case ipv4.ICMPTypeEcho:
			icmpTypeStr = "Echo Request (Ping)"
			if echo, ok := msg.Body.(*icmp.Echo); ok {
				icmpID = echo.ID
				icmpSeq = echo.Seq
			}
		case ipv4.ICMPTypeTimestamp:
			icmpTypeStr = "Timestamp Request"
			// Type 13 usually carries 12 bytes of data (ID, Seq, Timestamps).
			// x/net/icmp parses it into a RawBody
			if raw, ok := msg.Body.(*icmp.RawBody); ok && len(raw.Data) >= 4 {
				icmpID = int(raw.Data[0])<<8 | int(raw.Data[1])
				icmpSeq = int(raw.Data[2])<<8 | int(raw.Data[3])
			}
		default:
			continue // We only care about Ping and Timestamp scans
		}

		ok, suppressed := throttle.allow(sourceIP+"|"+icmpTypeStr, time.Now())
		if !ok {
			continue
		}

		log.Printf("[+] ICMP %s from %s (seq=%d size=%d)", icmpTypeStr, sourceIP, icmpSeq, n)

		ts.ReportEvent(
			"icmp_scan_received",
			sourceIP,
			"ICMP Listener",
			sdk.EventDetails{
				{Key: "icmp_type", Value: icmpTypeStr},
				{Key: "packet_size", Value: n},
				{Key: "icmp_id", Value: icmpID},
				{Key: "icmp_seq", Value: icmpSeq},
				{Key: "suppressed_since_last", Value: suppressed},
			},
		)
	}
}

func getEnvInt(key string, fallback int) int {
	if val, ok := os.LookupEnv(key); ok {
		if n, err := strconv.Atoi(val); err == nil && n >= 0 {
			return n
		}
	}
	return fallback
}
