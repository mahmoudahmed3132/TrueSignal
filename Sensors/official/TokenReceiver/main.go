// TokenReceiver is the callback end of TrueSignal's beacons: DNS names, web
// bugs and kubeconfig files the Hub generates and an operator plants where
// only an intruder would use them. When one is resolved or fetched, the
// lookup or request lands here and becomes a beacon_triggered event.
//
// It is the one TrueSignal component meant to face the internet (beacons
// fire from wherever the artifact is opened), so it runs on its own node in a
// DMZ and only talks outbound to the Hub, which stays internal. It serves an
// authoritative-only DNS zone and a fixed-response HTTP endpoint; it never
// resolves, forwards or proxies anything.
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	sdk "github.com/truesignal/sdk-go"
	"github.com/truesignal/sdk-go/decoy"
)

// Trigger is the event the receiver raises. The Hub resolves the token to
// the beacon it created and enriches the event.
const Trigger = "beacon_triggered"

type receiver struct {
	ts       decoy.Reporter
	zone     zone
	verify   verifier
	proxies  []*net.IPNet
	cooldown time.Duration
	replies  *decoy.Limiter // DNS replies per source

	mu   sync.Mutex
	seen map[string]*cooldownState // token|channel
	now  func() time.Time
}

type cooldownState struct {
	last    time.Time
	repeats int
}

const maxCooldownEntries = 10000

// report raises beacon_triggered for tok unless the same token fired on the
// same channel within the cooldown: one lookup is several queries (A, AAAA,
// HTTPS, resolver retries), one page load can be several requests. The
// suppressed count rides on the next event as repeats_since_last.
func (r *receiver) report(tok, channel, src string, d sdk.EventDetails) {
	key := tok + "|" + channel
	r.mu.Lock()
	now := r.now()
	st := r.seen[key]
	if st != nil && now.Sub(st.last) < r.cooldown {
		st.repeats++
		r.mu.Unlock()
		return
	}
	repeats := 0
	if st != nil {
		repeats = st.repeats
	}
	if len(r.seen) >= maxCooldownEntries {
		for k, v := range r.seen {
			if now.Sub(v.last) >= r.cooldown {
				delete(r.seen, k)
			}
		}
	}
	r.seen[key] = &cooldownState{last: now}
	r.mu.Unlock()

	d = append(sdk.EventDetails{{Key: "token", Value: tok}, {Key: "channel", Value: channel}}, d...)
	if repeats > 0 {
		d = append(d, sdk.EventDetail{Key: "repeats_since_last", Value: repeats})
	}
	r.ts.ReportEventSeverity("critical", Trigger, src, fmt.Sprintf("%s (%s)", strings.ToUpper(channel), r.zone.domain), d)
}

func parseCIDRs(raw string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			if ip := net.ParseIP(part); ip != nil && ip.To4() != nil {
				part += "/32"
			} else {
				part += "/128"
			}
		}
		_, n, err := net.ParseCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("TS_TRUSTED_PROXIES: bad entry %q", part)
		}
		out = append(out, n)
	}
	return out, nil
}

// loadZone reads TS_BEACON_DOMAIN, TS_BEACON_NS and TS_ANSWER_IPV4.
func loadZone(domain, nsList, ipv4 string) (zone, error) {
	z := zone{domain: strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))}
	if z.domain == "" || !strings.Contains(z.domain, ".") {
		return z, fmt.Errorf("TS_BEACON_DOMAIN must be a delegated zone such as t.example.com")
	}
	for _, n := range strings.Split(nsList, ",") {
		if n = strings.ToLower(strings.Trim(strings.TrimSpace(n), ".")); n != "" {
			z.ns = append(z.ns, n)
		}
	}
	if len(z.ns) == 0 {
		z.ns = []string{"ns1." + z.domain}
	}
	if ipv4 = strings.TrimSpace(ipv4); ipv4 != "" {
		ip := net.ParseIP(ipv4)
		if ip == nil || ip.To4() == nil {
			return z, fmt.Errorf("TS_ANSWER_IPV4 %q is not an IPv4 address", ipv4)
		}
		z.ipv4 = ip.To4()
	}
	return z, nil
}

func main() {
	ts, err := sdk.NewSensor()
	if err != nil {
		log.Fatalf("[!] FATAL: %v", err)
	}
	ts.SetTestPayload(Trigger, "Wizard Firedrill", "DNS (beacon zone)", sdk.EventDetails{
		{Key: "test_message", Value: "Wizard triggered a synthetic event firedrill."},
		{Key: "token", Value: "firedrill"},
		{Key: "channel", Value: "dns"},
	})
	if ts.TestMode {
		if ts.RunTestMode() {
			os.Exit(0)
		}
		os.Exit(1)
	}

	z, err := loadZone(os.Getenv("TS_BEACON_DOMAIN"), os.Getenv("TS_BEACON_NS"), os.Getenv("TS_ANSWER_IPV4"))
	if err != nil {
		log.Fatalf("[!] FATAL: %v", err)
	}
	key := os.Getenv("TS_BEACON_KEY")
	if key == "" {
		log.Fatalf("[!] FATAL: TS_BEACON_KEY is empty; the Hub sets it. Deploy this sensor through the Hub.")
	}
	proxies, err := parseCIDRs(os.Getenv("TS_TRUSTED_PROXIES"))
	if err != nil {
		log.Fatalf("[!] FATAL: %v", err)
	}
	cooldown, err := time.ParseDuration(decoy.Getenv("TS_ALERT_COOLDOWN", "60s"))
	if err != nil || cooldown < 0 {
		log.Fatalf("[!] FATAL: TS_ALERT_COOLDOWN: want a duration such as 60s")
	}
	services, err := decoy.ParseServices(decoy.Getenv("TS_SERVICES", "dns:53,http:80"), "dns", "http")
	if err != nil {
		log.Fatalf("[!] FATAL: %v", err)
	}

	r := &receiver{
		ts:       ts,
		zone:     z,
		verify:   verifier{key: []byte(key)},
		proxies:  proxies,
		cooldown: cooldown,
		replies:  decoy.NewLimiter(50, time.Second),
		seen:     map[string]*cooldownState{},
		now:      time.Now,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var lc net.ListenConfig
	for _, s := range services {
		bind := fmt.Sprintf("0.0.0.0:%d", s.Port)
		switch s.Proto {
		case "dns":
			pc, err := lc.ListenPacket(ctx, "udp", bind)
			if err != nil {
				log.Fatalf("[!] FATAL: bind dns udp/%d: %v", s.Port, err)
			}
			ln, err := lc.Listen(ctx, "tcp", bind)
			if err != nil {
				log.Fatalf("[!] FATAL: bind dns tcp/%d: %v", s.Port, err)
			}
			go r.serveDNSUDP(ctx, pc)
			go decoy.Accept(ctx, ln, r.serveDNSTCP)
			log.Printf("[+] TokenReceiver serving zone %s on udp+tcp/%d (NS %s)", z.domain, s.Port, strings.Join(z.ns, ", "))
		case "http":
			ln, err := lc.Listen(ctx, "tcp", bind)
			if err != nil {
				log.Fatalf("[!] FATAL: bind http/%d: %v", s.Port, err)
			}
			srv := r.httpServer()
			go srv.Serve(ln)
			go func() {
				<-ctx.Done()
				srv.Close()
			}()
			log.Printf("[+] TokenReceiver serving HTTP beacons on tcp/%d", s.Port)
		}
	}
	if z.ipv4 == nil {
		log.Println("[*] TS_ANSWER_IPV4 is not set: A queries get NODATA, so web bugs (HTTP) cannot reach this receiver.")
	}

	if err := ts.Start(); err != nil {
		log.Fatalf("[!] FATAL: %v", err)
	}
	defer ts.Stop()
	<-ctx.Done()
	log.Println("[*] TokenReceiver shutting down.")
}
