package main

import (
	"fmt"
	"net"
	"sync"
	"time"

	sdk "github.com/truesignal/sdk-go"
	"github.com/truesignal/sdk-go/decoy"
)

// The receiver faces the internet, so concurrent TCP clients are capped
// twice: per source, so one host holding idle sockets can't take every slot
// and blind the beacons, and in total, so a distributed burst can't exhaust
// goroutines or descriptors. A connection over either cap is closed at once
// rather than queued, so slow clients can't hold the accept loop either.
// Trusted proxies (a TLS front end) are exempt from the per-source cap,
// because every client behind them shares their address.
const (
	maxDNSTCPConns = 128
	maxHTTPConns   = 256
	perSourceDNS   = 4
	perSourceHTTP  = 8

	// SaturatedTrigger reports refused connections, at most once per
	// saturationEvery per listener, so an attack on the receiver is visible
	// without flooding the Hub.
	SaturatedTrigger = "receiver_saturated"
	saturationEvery  = 5 * time.Minute
)

type limitListener struct {
	net.Listener
	name      string // "dns" or "http", for the saturation event
	slots     chan struct{}
	perSource int
	exempt    func(ip string) bool
	refused   func(listener, reason, ip string)

	mu     sync.Mutex
	active map[string]int
}

func newLimitListener(ln net.Listener, name string, max, perSource int, exempt func(string) bool, refused func(listener, reason, ip string)) net.Listener {
	if exempt == nil {
		exempt = func(string) bool { return false }
	}
	if refused == nil {
		refused = func(string, string, string) {}
	}
	return &limitListener{Listener: ln, name: name, slots: make(chan struct{}, max), perSource: perSource,
		exempt: exempt, refused: refused, active: map[string]int{}}
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ip := decoy.RemoteIP(c.RemoteAddr())
		limited := l.perSource > 0 && !l.exempt(ip)
		if limited {
			l.mu.Lock()
			if l.active[ip] >= l.perSource {
				l.mu.Unlock()
				c.Close()
				l.refused(l.name, "per_source", ip)
				continue
			}
			l.active[ip]++
			l.mu.Unlock()
		}
		select {
		case l.slots <- struct{}{}:
			return &limitConn{Conn: c, release: func() {
				<-l.slots
				if limited {
					l.mu.Lock()
					if l.active[ip]--; l.active[ip] <= 0 {
						delete(l.active, ip)
					}
					l.mu.Unlock()
				}
			}}, nil
		default:
			if limited {
				l.mu.Lock()
				if l.active[ip]--; l.active[ip] <= 0 {
					delete(l.active, ip)
				}
				l.mu.Unlock()
			}
			c.Close()
			l.refused(l.name, "total", ip)
		}
	}
}

// limitConn frees its slot on the first Close.
type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// saturation counts refused connections and reports them as
// receiver_saturated, at most once per saturationEvery per listener.
type saturation struct {
	ts     decoy.Reporter
	domain string
	now    func() time.Time

	mu    sync.Mutex
	state map[string]*saturationState
}

type saturationState struct {
	last    time.Time
	refused map[string]int // reason -> count since the last event
	sources map[string]int // source -> refused count since the last event
}

func newSaturation(ts decoy.Reporter, domain string) *saturation {
	return &saturation{ts: ts, domain: domain, now: time.Now, state: map[string]*saturationState{}}
}

func (s *saturation) refused(listener, reason, ip string) {
	s.mu.Lock()
	st := s.state[listener]
	if st == nil {
		st = &saturationState{refused: map[string]int{}, sources: map[string]int{}}
		s.state[listener] = st
	}
	st.refused[reason]++
	if len(st.sources) < 1000 || st.sources[ip] > 0 {
		st.sources[ip]++
	}
	now := s.now()
	if !st.last.IsZero() && now.Sub(st.last) < saturationEvery {
		s.mu.Unlock()
		return
	}
	top, topN := "", 0
	for src, n := range st.sources {
		if n > topN || (n == topN && src < top) {
			top, topN = src, n
		}
	}
	d := sdk.EventDetails{
		{Key: "listener", Value: listener},
		{Key: "refused_per_source", Value: st.refused["per_source"]},
		{Key: "refused_total_cap", Value: st.refused["total"]},
		{Key: "distinct_sources", Value: len(st.sources)},
		{Key: "top_source_refusals", Value: topN},
	}
	st.last, st.refused, st.sources = now, map[string]int{}, map[string]int{}
	s.mu.Unlock()
	// The source is the busiest refused address: one host holding slots is
	// the common case and the one an analyst can act on.
	s.ts.ReportEventSeverity("medium", SaturatedTrigger, top, fmt.Sprintf("%s (%s)", listenerLabel(listener), s.domain), d)
}

func listenerLabel(l string) string {
	if l == "dns" {
		return "DNS/TCP"
	}
	return "HTTP"
}
