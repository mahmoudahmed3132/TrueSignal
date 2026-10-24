// Package decoy holds the building blocks shared by the interactive service
// decoys (database, remote-access and network-service sensors): the multi-port
// TS_SERVICES listener list, the credential capture policy, the accept loop
// and input sanitising. The protocol emulation stays in each sensor.
package decoy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	sdk "github.com/truesignal/sdk-go"
)

// Reporter is the slice of the SDK protocol handlers use, so they can be
// tested with a fake. *sdk.Sensor satisfies it.
type Reporter interface {
	ReportEventSeverity(severity, trigger, source, target string, details sdk.EventDetails) bool
}

// Service is one decoy listener: a protocol name and a port.
type Service struct {
	Proto string
	Port  int
}

// ParseServices parses "proto:port,proto:port" into a validated list. It
// rejects protocols not in allowed, bad ports and a port used twice. The Hub
// separately rejects two sensors on one node binding the same port
// (listen_ports_env).
func ParseServices(raw string, allowed ...string) ([]Service, error) {
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	var out []Service
	seen := map[int]bool{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		proto, portStr, found := strings.Cut(part, ":")
		if !found {
			return nil, fmt.Errorf("bad service %q, want proto:port", part)
		}
		proto = strings.ToLower(strings.TrimSpace(proto))
		if !ok[proto] {
			return nil, fmt.Errorf("unsupported protocol %q (want %s)", proto, strings.Join(allowed, ", "))
		}
		port, err := strconv.Atoi(strings.TrimSpace(portStr))
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("bad port in %q", part)
		}
		if seen[port] {
			return nil, fmt.Errorf("port %d used twice", port)
		}
		seen[port] = true
		out = append(out, Service{Proto: proto, Port: port})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("TS_SERVICES is empty")
	}
	return out, nil
}

// Accept serves connections from ln until ctx ends.
func Accept(ctx context.Context, ln net.Listener, handle func(net.Conn)) {
	defer ln.Close()
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		go handle(conn)
	}
}

// RemoteIP is the peer address without the port.
func RemoteIP(addr net.Addr) string {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// Sanitize makes attacker input safe to log and to carry in a JSON event:
// invalid UTF-8 is replaced and the value is capped at n bytes.
func Sanitize(s string, n int) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "?")
	}
	if n > 0 && len(s) > n {
		s = s[:n]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}

// Getenv returns the variable or fallback when unset.
func Getenv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

// Capture decides how much of a captured secret leaves the decoy, using the
// same policy as the other TrueSignal decoys: "hash" (default) records a keyed
// HMAC-SHA256 and the length, never the secret; "plain" opts in to cleartext;
// "none" records only that something was submitted. A real password landing in
// the Hub or SIEM is credential material under PCI DSS, so the default never
// stores the recoverable value.
//
// The key is TS_CAPTURE_HASH_KEY, which the Hub sets to this node's derived
// capture key so it can recognise planted honeytokens; without it the key is
// derived from the node key.
type Capture struct {
	mode string
	key  []byte
}

// NewCapture reads TS_CAPTURE_PASSWORDS, TS_CAPTURE_HASH_KEY and TS_HUB_KEY.
func NewCapture() Capture {
	return NewCaptureWith(os.Getenv("TS_CAPTURE_PASSWORDS"), os.Getenv("TS_CAPTURE_HASH_KEY"), os.Getenv("TS_HUB_KEY"))
}

// NewCaptureWith builds a Capture from explicit values.
func NewCaptureWith(mode, captureKey, nodeKey string) Capture {
	mode = strings.ToLower(strings.TrimSpace(mode))
	switch mode {
	case "plain", "none":
	default:
		mode = "hash"
	}
	key := []byte(captureKey)
	if len(key) == 0 {
		key = []byte("truesignal-capture:" + nodeKey)
	}
	return Capture{mode: mode, key: key}
}

// Password returns event details for a submitted password.
func (c Capture) Password(password string) sdk.EventDetails {
	return c.Secret("password", password)
}

// Secret labels a captured value (password, community string) under prefix,
// e.g. prefix "password" gives password_hmac / password_length / hmac_key_id.
func (c Capture) Secret(prefix, value string) sdk.EventDetails {
	switch c.mode {
	case "plain":
		return sdk.EventDetails{{Key: prefix, Value: Sanitize(value, 256)}}
	case "none":
		return sdk.EventDetails{{Key: prefix + "_submitted", Value: value != ""}}
	default:
		mac := hmac.New(sha256.New, c.key)
		mac.Write([]byte(value))
		return sdk.EventDetails{
			{Key: prefix + "_hmac", Value: hex.EncodeToString(mac.Sum(nil))},
			{Key: prefix + "_length", Value: len(value)},
			{Key: "hmac_key_id", Value: c.KeyID()},
		}
	}
}

// KeyID lets an analyst (and the Hub) tell which key produced an HMAC without
// revealing it.
func (c Capture) KeyID() string {
	mac := hmac.New(sha256.New, c.key)
	mac.Write([]byte("truesignal-key-id"))
	return hex.EncodeToString(mac.Sum(nil))[:8]
}

// Limiter caps how many events one source can raise per window, so a password
// spray of thousands of attempts cannot flood the Hub and the SIEM. Allow
// reports whether to emit, and how many events were suppressed since the last
// one emitted for that source (attach it as suppressed_since_last).
type Limiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	seen   map[string]*limitState
	now    func() time.Time
}

type limitState struct {
	start      time.Time
	count      int
	suppressed int
}

// NewLimiter allows limit events per source per window.
func NewLimiter(limit int, window time.Duration) *Limiter {
	return &Limiter{limit: limit, window: window, seen: map[string]*limitState{}, now: time.Now}
}

// Allow records one event from src.
func (l *Limiter) Allow(src string) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	st, ok := l.seen[src]
	if !ok || now.Sub(st.start) >= l.window {
		if len(l.seen) > 10000 { // bound memory under a distributed spray
			for k, v := range l.seen {
				if now.Sub(v.start) >= l.window {
					delete(l.seen, k)
				}
			}
		}
		prev := 0
		if ok {
			prev = st.suppressed
		}
		l.seen[src] = &limitState{start: now, count: 1}
		return true, prev
	}
	if st.count < l.limit {
		st.count++
		s := st.suppressed
		st.suppressed = 0
		return true, s
	}
	st.suppressed++
	return false, 0
}
