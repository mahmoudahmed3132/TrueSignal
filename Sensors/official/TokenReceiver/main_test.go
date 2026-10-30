package main

import (
	"encoding/binary"
	"net"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/truesignal/sdk-go"
	"github.com/truesignal/sdk-go/decoy"
)

// The same vector is in Hub/internal/services/beacon: the Hub generates what
// the receiver verifies.
const (
	vectorKey   = "truesignal-test-key"
	vectorToken = "aaaqeayeaudaocaj4jyx76cl" // random bytes 0x00..0x09
)

type event struct {
	severity, trigger, source string
	details                   map[string]any
}

type fakeReporter struct {
	mu     sync.Mutex
	events []event
}

func (f *fakeReporter) ReportEventSeverity(severity, trigger, source, _ string, d sdk.EventDetails) bool {
	m := map[string]any{}
	for _, kv := range d {
		m[kv.Key] = kv.Value
	}
	f.mu.Lock()
	f.events = append(f.events, event{severity, trigger, source, m})
	f.mu.Unlock()
	return true
}

// snapshot copies the events (the saturation test reports from the accept
// goroutine).
func (f *fakeReporter) snapshot() []event {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]event(nil), f.events...)
}

func newTestReceiver(t *testing.T, ipv4 string) (*receiver, *fakeReporter) {
	t.Helper()
	z, err := loadZone("t.example.com", "", ipv4)
	if err != nil {
		t.Fatal(err)
	}
	proxies, _ := parseCIDRs("10.9.0.0/16")
	f := &fakeReporter{}
	return &receiver{
		ts: f, zone: z, verify: verifier{key: []byte(vectorKey)}, proxies: proxies,
		cooldown: time.Minute, replies: decoy.NewLimiter(50, time.Second),
		seen: map[string]*cooldownState{}, now: time.Now,
	}, f
}

func TestTokenVector(t *testing.T) {
	v := verifier{key: []byte(vectorKey)}
	if !v.valid(vectorToken) || !v.valid(strings.ToUpper(vectorToken)) {
		t.Fatal("test vector rejected")
	}
	bad := []byte(vectorToken)
	bad[23] = 'a'
	for _, s := range []string{string(bad), "", "www", vectorToken[:23], vectorToken + "a"} {
		if v.valid(s) {
			t.Errorf("accepted %q", s)
		}
	}
	if (verifier{key: []byte("other")}).valid(vectorToken) || (verifier{}).valid(vectorToken) {
		t.Error("accepted under the wrong key")
	}
}

// query builds a DNS query; opt adds an OPT record carrying an ECS option.
func query(name string, qtype uint16, ecs []byte) []byte {
	p := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	p = append(p, encodeName(name)...)
	p = binary.BigEndian.AppendUint16(p, qtype)
	p = binary.BigEndian.AppendUint16(p, classIN)
	if ecs != nil {
		p[11] = 1
		p = append(p, 0) // root owner
		p = binary.BigEndian.AppendUint16(p, typeOPT)
		p = binary.BigEndian.AppendUint16(p, 1232)
		p = append(p, 0, 0, 0, 0) // ttl
		opt := binary.BigEndian.AppendUint16(nil, 8)
		opt = binary.BigEndian.AppendUint16(opt, uint16(len(ecs)))
		opt = append(opt, ecs...)
		p = binary.BigEndian.AppendUint16(p, uint16(len(opt)))
		p = append(p, opt...)
	}
	return p
}

func header(resp []byte) (rcode byte, aa bool, an, ns int) {
	return resp[3] & 0x0F, resp[2]&0x04 != 0, int(binary.BigEndian.Uint16(resp[6:])), int(binary.BigEndian.Uint16(resp[8:]))
}

func TestDNSBeacon(t *testing.T) {
	r, f := newTestReceiver(t, "203.0.113.7")
	// Mixed case as with 0x20 randomisation; the question must come back verbatim.
	name := "ApI." + strings.ToUpper(vectorToken[:4]) + vectorToken[4:] + ".T.Example.COM"
	q := query(name, typeA, []byte{0, 1, 24, 0, 198, 51, 100})
	resp := r.handleDNS(q, "8.8.8.8", "udp")
	rcode, aa, an, _ := header(resp)
	if rcode != rcodeOK || !aa || an != 1 {
		t.Fatalf("rcode=%d aa=%v an=%d", rcode, aa, an)
	}
	qq, _ := parseQuestion(q)
	if string(resp[12:qq.end]) != string(q[12:qq.end]) {
		t.Fatal("question not echoed verbatim")
	}
	if !strings.HasSuffix(string(resp), string([]byte{0, 4, 203, 0, 113, 7})) {
		t.Fatalf("A record missing: %x", resp)
	}
	if len(f.events) != 1 {
		t.Fatalf("events = %d", len(f.events))
	}
	e := f.events[0]
	if e.trigger != Trigger || e.severity != "critical" || e.source != "8.8.8.8" ||
		e.details["token"] != vectorToken || e.details["channel"] != "dns" ||
		e.details["client_subnet"] != "198.51.100.0/24" || e.details["query_type"] != "A" {
		t.Fatalf("event = %+v", e)
	}

	// AAAA for the same lookup: answered (NODATA + SOA), no second event.
	resp = r.handleDNS(query(vectorToken+".t.example.com", 28, nil), "8.8.4.4", "udp")
	if rcode, _, an, ns := header(resp); rcode != rcodeOK || an != 0 || ns != 1 {
		t.Fatalf("AAAA: rcode=%d an=%d ns=%d", rcode, an, ns)
	}
	if len(f.events) != 1 {
		t.Fatalf("cooldown not applied: %d events", len(f.events))
	}
	// After the cooldown the repeats ride on the next event.
	r.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	r.handleDNS(query(vectorToken+".t.example.com", typeA, nil), "8.8.8.8", "udp")
	if len(f.events) != 2 || f.events[1].details["repeats_since_last"] != 1 {
		t.Fatalf("events = %+v", f.events)
	}
}

func TestDNSNoTokenAndOutOfZone(t *testing.T) {
	r, f := newTestReceiver(t, "")
	for _, n := range []string{"www.t.example.com", "aaaaaaaaaaaaaaaaaaaaaaaa.t.example.com", "t.example.com"} {
		resp := r.handleDNS(query(n, typeA, nil), "1.1.1.1", "udp")
		if rcode, aa, an, ns := header(resp); rcode != rcodeOK || !aa || an != 0 || ns != 1 {
			t.Errorf("%s: rcode=%d aa=%v an=%d ns=%d", n, rcode, aa, an, ns)
		}
	}
	// Not ours: refused, never resolved.
	resp := r.handleDNS(query(vectorToken+".example.org", typeA, nil), "1.1.1.1", "udp")
	if rcode, aa, an, _ := header(resp); rcode != rcodeRefuse || aa || an != 0 {
		t.Errorf("out of zone: rcode=%d aa=%v an=%d", rcode, aa, an)
	}
	if len(f.events) != 0 {
		t.Fatalf("events = %+v", f.events)
	}
	// A response is never answered.
	q := query("t.example.com", typeA, nil)
	q[2] |= 0x80
	if r.handleDNS(q, "1.1.1.1", "udp") != nil {
		t.Error("answered a response")
	}
}

func TestDNSApex(t *testing.T) {
	r, _ := newTestReceiver(t, "203.0.113.7")
	if _, _, an, _ := header(r.handleDNS(query("t.example.com", typeNS, nil), "1.1.1.1", "udp")); an != 1 {
		t.Errorf("NS answers = %d", an)
	}
	if _, _, an, _ := header(r.handleDNS(query("t.example.com", typeSOA, nil), "1.1.1.1", "udp")); an != 1 {
		t.Errorf("SOA answers = %d", an)
	}
	if _, _, an, _ := header(r.handleDNS(query("ns1.t.example.com", typeA, nil), "1.1.1.1", "udp")); an != 1 {
		t.Errorf("NS host A answers = %d", an)
	}
}

func TestHTTPBeacon(t *testing.T) {
	r, f := newTestReceiver(t, "203.0.113.7")
	req := httptest.NewRequest("GET", "http://t.example.com/img/"+vectorToken+".gif", nil)
	req.RemoteAddr = "192.0.2.10:5555"
	req.Header.Set("User-Agent", "Microsoft Office/16.0")
	req.Header.Set("X-Forwarded-For", "6.6.6.6") // untrusted peer: ignored
	w := httptest.NewRecorder()
	r.serveHTTP(w, req)
	if w.Code != 200 || w.Header().Get("Content-Type") != "image/gif" || w.Body.Len() != len(pixel) {
		t.Fatalf("response %d %q %d", w.Code, w.Header().Get("Content-Type"), w.Body.Len())
	}
	if len(f.events) != 1 || f.events[0].source != "192.0.2.10" || f.events[0].details["channel"] != "http" ||
		f.events[0].details["user_agent"] != "Microsoft Office/16.0" {
		t.Fatalf("events = %+v", f.events)
	}

	// Through a trusted proxy the client is the address the proxy appended;
	// a token in the Host also counts.
	req = httptest.NewRequest("GET", "http://"+vectorToken+".t.example.com/", nil)
	req.RemoteAddr = "10.9.1.1:443"
	req.Header.Set("X-Forwarded-For", "6.6.6.6, 198.51.100.20")
	r.serveHTTP(httptest.NewRecorder(), req)
	r.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	r.serveHTTP(httptest.NewRecorder(), req)
	if len(f.events) != 2 || f.events[1].source != "198.51.100.20" || f.events[1].details["proxy"] != "10.9.1.1" {
		t.Fatalf("events = %+v", f.events)
	}

	// No token: same pixel, no event.
	n := len(f.events)
	w = httptest.NewRecorder()
	r.serveHTTP(w, httptest.NewRequest("GET", "http://t.example.com/favicon.ico", nil))
	if w.Code != 200 || len(f.events) != n {
		t.Fatal("tokenless request raised an event")
	}
}

func TestLoadZone(t *testing.T) {
	if _, err := loadZone("", "", ""); err == nil {
		t.Error("empty domain accepted")
	}
	if _, err := loadZone("t.example.com", "", "::1"); err == nil {
		t.Error("IPv6 TS_ANSWER_IPV4 accepted")
	}
	z, err := loadZone("T.Example.com.", "a.ns.example.net, b.ns.example.net", "203.0.113.7")
	if err != nil || z.domain != "t.example.com" || len(z.ns) != 2 || z.ipv4 == nil {
		t.Fatalf("zone = %+v, %v", z, err)
	}
}

func TestClientSubnetMalformed(t *testing.T) {
	q := query("t.example.com", typeA, []byte{0, 1, 99, 0, 1, 2, 3, 4, 5})
	qq, _ := parseQuestion(q)
	if cs := clientSubnet(q, qq.end); cs != "" {
		t.Errorf("malformed ECS parsed as %q", cs)
	}
	if cs := clientSubnet(q[:len(q)-3], qq.end); cs != "" {
		t.Errorf("truncated packet parsed as %q", cs)
	}
}

func TestLimitListenerDropsBeyondCap(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := newLimitListener(raw, "http", 1, 0, nil, nil)
	defer ln.Close()
	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	dial := func() net.Conn {
		c, err := net.Dial("tcp", raw.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	first := dial()
	defer first.Close()
	held := <-accepted

	// Over the cap: the server closes it straight away.
	second := dial()
	defer second.Close()
	second.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := second.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection over the cap was served")
	}

	// Closing the held connection frees the slot (twice is harmless).
	held.Close()
	held.Close()
	third := dial()
	defer third.Close()
	select {
	case c := <-accepted:
		c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("slot not released")
	}
}

// One source can hold at most perSource slots; others still get in, a
// trusted proxy is exempt, and refusals are reported once per window.
func TestPerSourceCapAndSaturationEvent(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeReporter{}
	sat := newSaturation(f, "t.example.com")
	ln := newLimitListener(raw, "http", 10, 2, nil, sat.refused)
	defer ln.Close()
	accepted := make(chan net.Conn, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	dial := func() net.Conn {
		c, err := net.Dial("tcp", raw.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	a, b := dial(), dial()
	defer a.Close()
	defer b.Close()
	<-accepted
	<-accepted
	third := dial() // 127.0.0.1 is at its cap of 2
	defer third.Close()
	third.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := third.Read(make([]byte, 1)); err == nil {
		t.Fatal("third connection from one source was served")
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(f.snapshot()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if ev := f.snapshot(); len(ev) != 1 || ev[0].trigger != SaturatedTrigger || ev[0].source != "127.0.0.1" ||
		ev[0].details["refused_per_source"] != 1 || ev[0].details["listener"] != "http" {
		t.Fatalf("events = %+v", ev)
	}
	// A second refusal inside the window is counted, not reported.
	fourth := dial()
	defer fourth.Close()
	fourth.SetReadDeadline(time.Now().Add(2 * time.Second))
	fourth.Read(make([]byte, 1))
	time.Sleep(50 * time.Millisecond)
	if n := len(f.snapshot()); n != 1 {
		t.Fatalf("saturation not rate-limited: %d events", n)
	}

	// A trusted proxy is not capped per source.
	exempt := newLimitListener(raw, "http", 10, 1, func(string) bool { return true }, nil).(*limitListener)
	if exempt.perSource != 1 || !exempt.exempt("127.0.0.1") {
		t.Fatal("exempt wiring")
	}
}
