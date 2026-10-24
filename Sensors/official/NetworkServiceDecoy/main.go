// NetworkServiceDecoy emulates UDP infrastructure services that attackers
// probe during discovery: SNMP (community-string guessing, device
// fingerprinting) and DNS. DNS is log-only: queries are recorded and answered
// REFUSED, never resolved or forwarded, so the decoy can't become an open
// resolver or leak internal names. Ported in concept from the Trapster
// Community honeypot (0xBallpoint, AGPLv3+), minus its DNS forwarding.
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	sdk "github.com/truesignal/sdk-go"
	"github.com/truesignal/sdk-go/decoy"
)

type persona struct {
	hostname string
	sysDescr string
}

type handler struct {
	ts        decoy.Reporter
	proto     string
	port      int
	cap       decoy.Capture
	persona   persona
	limit     *decoy.Limiter
	community string // the community the decoy accepts (and answers)
	started   time.Time
}

const (
	eventsPerMinute = 20
	maxDatagram     = 4096
)

func main() {
	ts, err := sdk.NewSensor()
	if err != nil {
		log.Fatalf("[!] FATAL: %v", err)
	}
	ts.SetTestPayload("snmp_query", "Wizard Firedrill", "SNMP:161 (sw-core-01)", sdk.EventDetails{
		{Key: "test_message", Value: "Wizard triggered a synthetic event firedrill."},
		{Key: "protocol", Value: "snmp"},
		{Key: "snmp_version", Value: "v2c"},
		{Key: "pdu", Value: "get"},
	})
	if ts.TestMode {
		if ts.RunTestMode() {
			os.Exit(0)
		}
		os.Exit(1)
	}

	per := persona{
		hostname: decoy.Getenv("TS_PERSONA_HOSTNAME", "sw-core-01"),
		sysDescr: decoy.Getenv("TS_SNMP_SYSDESCR", "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E8, RELEASE SOFTWARE (fc3)"),
	}
	services, err := decoy.ParseServices(decoy.Getenv("TS_SERVICES", "snmp:161,dns:53"), "snmp", "dns")
	if err != nil {
		log.Fatalf("[!] FATAL: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	limit := decoy.NewLimiter(eventsPerMinute, time.Minute)
	capture := decoy.NewCapture()
	community := decoy.Getenv("TS_SNMP_COMMUNITY", "public")
	var lc net.ListenConfig
	for _, s := range services {
		pc, err := lc.ListenPacket(ctx, "udp", fmt.Sprintf("0.0.0.0:%d", s.Port))
		if err != nil {
			log.Fatalf("[!] FATAL: bind %s/%d: %v", s.Proto, s.Port, err)
		}
		h := &handler{ts: ts, proto: s.Proto, port: s.Port, cap: capture, persona: per, limit: limit, community: community, started: time.Now()}
		log.Printf("[+] NetworkServiceDecoy serving %s on udp/%d as %s", s.Proto, s.Port, per.hostname)
		go h.servePackets(ctx, pc)
	}

	if err := ts.Start(); err != nil {
		log.Fatalf("[!] FATAL: %v", err)
	}
	defer ts.Stop()
	<-ctx.Done()
	log.Println("[*] NetworkServiceDecoy shutting down.")
}

func (h *handler) servePackets(ctx context.Context, pc net.PacketConn) {
	defer pc.Close()
	go func() {
		<-ctx.Done()
		pc.Close()
	}()
	buf := make([]byte, maxDatagram)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		reply := h.handle(buf[:n], decoy.RemoteIP(addr))
		if reply != nil {
			pc.WriteTo(reply, addr)
		}
	}
}

// handle processes one datagram from src and returns the reply, if any.
func (h *handler) handle(pkt []byte, src string) []byte {
	switch h.proto {
	case "snmp":
		return h.handleSNMP(pkt, src)
	case "dns":
		return h.handleDNS(pkt, src)
	}
	return nil
}

// report emits an event unless src is over the rate limit. Replies are
// limited the same way, so a spoofed source can't use the decoy to reflect
// traffic at a third party. allowed reports whether to answer.
func (h *handler) report(severity, trigger, src string, d sdk.EventDetails) (allowed bool) {
	ok, suppressed := h.limit.Allow(src)
	if !ok {
		return false
	}
	d = append(sdk.EventDetails{{Key: "protocol", Value: h.proto}, {Key: "dst_port", Value: h.port}}, d...)
	if suppressed > 0 {
		d = append(d, sdk.EventDetail{Key: "suppressed_since_last", Value: suppressed})
	}
	h.ts.ReportEventSeverity(severity, trigger, src, h.target(), d)
	return true
}

func (h *handler) target() string {
	return fmt.Sprintf("%s:%d (%s)", strings.ToUpper(h.proto), h.port, h.persona.hostname)
}
