// IdentityDecoy emulates Windows identity services (LDAP, LDAPS, RDP) so an
// attacker moving laterally trips a decoy the moment they probe or try to
// authenticate. It captures the credentials and usernames they present. Ported
// in concept from the Trapster Community honeypot (0xBallpoint, AGPLv3+); the
// Go implementation and the TrueSignal SDK/capture policy are TrueSignal's.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"

	sdk "github.com/truesignal/sdk-go"
)

// persona is the shared identity every service on this node claims, so LDAP,
// LDAPS and RDP all look like one machine in one domain.
type persona struct {
	hostname string // e.g. "DC01"
	domain   string // e.g. "corp.local"
}

// reporter is the slice of the SDK the protocol handlers use, so they can be
// tested with a fake. *sdk.Sensor satisfies it.
type reporter interface {
	ReportEventSeverity(severity, trigger, source, target string, details sdk.EventDetails) bool
}

// service is one decoy listener: a protocol name and a TCP port.
type service struct {
	proto string
	port  int
}

var validProtos = map[string]bool{"ldap": true, "ldaps": true, "rdp": true}

func main() {
	ts, err := sdk.NewSensor()
	if err != nil {
		log.Fatalf("[!] FATAL: %v", err)
	}

	ts.SetTestPayload(
		"ldap_login",
		"Wizard Firedrill",
		"LDAP:389 (DC01)",
		sdk.EventDetails{
			{Key: "test_message", Value: "Wizard triggered a synthetic event firedrill."},
			{Key: "protocol", Value: "ldap"},
			{Key: "bind_dn", Value: "CN=admin,DC=corp,DC=local"},
			{Key: "auth", Value: "simple"},
			{Key: "password_hmac", Value: "firedrill"},
		},
	)
	if ts.TestMode {
		if ts.RunTestMode() {
			os.Exit(0)
		}
		os.Exit(1)
	}

	per := persona{
		hostname: getEnv("TS_PERSONA_HOSTNAME", "DC01"),
		domain:   getEnv("TS_PERSONA_DOMAIN", "corp.local"),
	}
	cap := newCredCapture(
		strings.ToLower(getEnv("TS_CAPTURE_PASSWORDS", "hash")),
		os.Getenv("TS_CAPTURE_HASH_KEY"),
		os.Getenv("TS_HUB_KEY"),
	)

	services, err := parseServices(getEnv("TS_SERVICES", "ldap:389,ldaps:636,rdp:3389"))
	if err != nil {
		log.Fatalf("[!] FATAL: %v", err)
	}

	var tlsConfig *tls.Config
	for _, s := range services {
		if s.proto == "ldaps" {
			cfg, err := selfSignedTLS(per)
			if err != nil {
				log.Fatalf("[!] FATAL: ldaps certificate: %v", err)
			}
			tlsConfig = cfg
			break
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var lc net.ListenConfig
	for _, s := range services {
		ln, err := lc.Listen(ctx, "tcp", fmt.Sprintf("0.0.0.0:%d", s.port))
		if err != nil {
			log.Fatalf("[!] FATAL: bind %s/%d: %v", s.proto, s.port, err)
		}
		if s.proto == "ldaps" {
			ln = tls.NewListener(ln, tlsConfig)
		}
		log.Printf("[+] IdentityDecoy serving %s on port %d as %s.%s", s.proto, s.port, per.hostname, per.domain)
		go accept(ctx, ln, serveFunc(ts, s, cap, per))
	}

	if err := ts.Start(); err != nil {
		log.Fatalf("[!] FATAL: %v", err)
	}
	defer ts.Stop()

	<-ctx.Done()
	log.Println("[*] IdentityDecoy shutting down.")
}

func serveFunc(ts *sdk.Sensor, s service, cap credcapture, per persona) func(net.Conn) {
	switch s.proto {
	case "ldap", "ldaps":
		h := &ldapHandler{ts: ts, proto: s.proto, port: s.port, cap: cap, persona: per}
		return h.serve
	case "rdp":
		h := &rdpHandler{ts: ts, port: s.port, persona: per}
		return h.serve
	}
	return func(c net.Conn) { c.Close() }
}

func accept(ctx context.Context, ln net.Listener, handle func(net.Conn)) {
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		go handle(conn)
	}
}

// parseServices parses "proto:port,proto:port" into a validated list, rejecting
// unknown protocols, bad ports and a port used twice in this sensor.
func parseServices(raw string) ([]service, error) {
	var out []service
	seen := map[int]bool{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		proto, portStr, ok := strings.Cut(part, ":")
		if !ok {
			return nil, fmt.Errorf("bad service %q, want proto:port", part)
		}
		proto = strings.ToLower(strings.TrimSpace(proto))
		if !validProtos[proto] {
			return nil, fmt.Errorf("unsupported protocol %q (want ldap, ldaps or rdp)", proto)
		}
		port, err := strconv.Atoi(strings.TrimSpace(portStr))
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("bad port in %q", part)
		}
		if seen[port] {
			return nil, fmt.Errorf("port %d used twice", port)
		}
		seen[port] = true
		out = append(out, service{proto: proto, port: port})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("TS_SERVICES is empty")
	}
	return out, nil
}

func remoteIP(conn net.Conn) string {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return host
}

// sanitizeUTF8 replaces invalid UTF-8 so captured attacker input is safe to log
// and to carry in a JSON event.
func sanitizeUTF8(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	return strings.ToValidUTF8(s, "?")
}

func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}
