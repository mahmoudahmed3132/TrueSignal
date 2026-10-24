package main

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	sdk "github.com/truesignal/sdk-go"
	"github.com/truesignal/sdk-go/decoy"
)

type event struct {
	severity, trigger string
	details           map[string]any
}

type fakeReporter struct{ events []event }

func (f *fakeReporter) ReportEventSeverity(severity, trigger, _, _ string, d sdk.EventDetails) bool {
	m := map[string]any{}
	for _, kv := range d {
		m[kv.Key] = kv.Value
	}
	f.events = append(f.events, event{severity, trigger, m})
	return true
}

func newHandler(proto string, perMinute int) (*handler, *fakeReporter) {
	fr := &fakeReporter{}
	return &handler{ts: fr, proto: proto, port: 1, cap: decoy.NewCaptureWith("hash", "k", ""),
		persona:   persona{hostname: "sw-core-01", sysDescr: "Cisco IOS Software"},
		limit:     decoy.NewLimiter(perMinute, time.Minute),
		community: "public", started: time.Now()}, fr
}

// --- DNS ---

func dnsQuery(name string, qtype uint16) []byte {
	p := []byte{0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(name, ".") {
		p = append(p, byte(len(l)))
		p = append(p, l...)
	}
	p = append(p, 0, byte(qtype>>8), byte(qtype), 0, 1)
	return p
}

func TestDNSRefusedAndLogged(t *testing.T) {
	h, fr := newHandler("dns", 100)
	q := dnsQuery("payroll.corp.local", 1)
	resp := h.handle(q, "10.0.0.9")
	if len(resp) != len(q) || resp[0] != 0xab || resp[1] != 0xcd || resp[2]&0x80 == 0 || resp[3]&0x0f != 5 ||
		binary.BigEndian.Uint16(resp[6:]) != 0 || !bytes.Equal(resp[12:], q[12:]) {
		t.Fatalf("response = %x", resp)
	}
	if resp[2]&0x01 != q[2]&0x01 { // RD copied
		t.Fatal("RD flag not echoed")
	}
	e := fr.events[0]
	if e.trigger != "dns_query" || e.severity != "medium" || e.details["query_name"] != "payroll.corp.local" || e.details["query_type"] != "A" {
		t.Fatalf("event = %+v", e)
	}
	h.handle(dnsQuery("corp.local", 252), "10.0.0.9")
	if fr.events[1].severity != "high" || fr.events[1].details["query_type"] != "AXFR" {
		t.Fatalf("AXFR event = %+v", fr.events[1])
	}
}

func TestDNSIgnoresResponsesAndGarbage(t *testing.T) {
	h, fr := newHandler("dns", 100)
	resp := dnsQuery("x.local", 1)
	resp[2] |= 0x80
	for _, p := range [][]byte{resp, {1, 2, 3}, append(dnsQuery("x", 1)[:12], 0xC0, 0x0c)} {
		if h.handle(p, "10.0.0.9") != nil {
			t.Fatalf("replied to %x", p)
		}
	}
	if len(fr.events) != 0 {
		t.Fatalf("events = %+v", fr.events)
	}
}

func TestRateLimitSuppressesEventsAndReplies(t *testing.T) {
	h, fr := newHandler("dns", 2)
	for i := 0; i < 5; i++ {
		r := h.handle(dnsQuery("a.local", 1), "10.0.0.9")
		if (i < 2) != (r != nil) {
			t.Fatalf("query %d: reply=%v", i, r != nil)
		}
	}
	if len(fr.events) != 2 {
		t.Fatalf("events = %d, want 2", len(fr.events))
	}
}

// --- SNMP ---

func tl(tag byte, v []byte) []byte { return enc(tag, v) }

func snmpGet(version byte, community string, pdu byte, oid string) []byte {
	vb := tl(tagSeq, append(tl(tagOID, encodeOID(oid)), tagNull, 0))
	body := concat(tl(tagInt, []byte{0x12, 0x34}), tl(tagInt, []byte{0}), tl(tagInt, []byte{0}), tl(tagSeq, vb))
	return tl(tagSeq, concat(tl(tagInt, []byte{version}), tl(tagOctets, []byte(community)), tl(pdu, body)))
}

func TestSNMPValidCommunityAnswersSystemGroup(t *testing.T) {
	h, fr := newHandler("snmp", 100)
	resp := h.handle(snmpGet(1, "public", pduGet, oidSysDescr), "10.0.0.9")
	r, ok := parseSNMP(resp)
	if !ok || r.version != 1 || r.community != "public" || r.pdu != pduResponse || !bytes.Equal(r.requestID, []byte{0x12, 0x34}) {
		t.Fatalf("response = %x", resp)
	}
	if !bytes.Contains(resp, []byte("Cisco IOS Software")) {
		t.Fatal("sysDescr missing")
	}
	e := fr.events[0]
	if e.details["community_valid"] != true || e.details["pdu"] != "get" || e.details["oids"] != oidSysDescr || e.details["community_hmac"] == nil {
		t.Fatalf("event = %+v", e)
	}
	for _, v := range e.details {
		if s, ok := v.(string); ok && s == "public" {
			t.Fatal("community string in clear")
		}
	}
}

func TestSNMPGetNextWalksInNumericOrder(t *testing.T) {
	h, _ := newHandler("snmp", 100)
	resp := h.handle(snmpGet(1, "public", pduGetNext, "1.3.6.1.2.1.1.2.0"), "10.0.0.9")
	if !bytes.Contains(resp, encodeOID(oidSysUpTime)) {
		t.Fatalf("getnext after sysObjectID should return sysUpTime: %x", resp)
	}
	if !oidLess("1.3.6.1.2.1.1.2", "1.3.6.1.2.1.1.10") || oidLess("1.3.6.1.2.1.1.10", "1.3.6.1.2.1.1.2") {
		t.Fatal("oidLess is not numeric")
	}
	if got := oidString(encodeOID("1.3.6.1.4.1.9.300000")); got != "1.3.6.1.4.1.9.300000" {
		t.Fatalf("OID round trip = %q", got)
	}
}

func TestSNMPWrongCommunityAndSetAreSilent(t *testing.T) {
	h, fr := newHandler("snmp", 100)
	if h.handle(snmpGet(1, "guess", pduGet, oidSysDescr), "10.0.0.9") != nil {
		t.Fatal("answered a wrong community")
	}
	if h.handle(snmpGet(1, "public", pduSet, oidSysName), "10.0.0.9") != nil {
		t.Fatal("answered a SET")
	}
	if fr.events[0].details["community_valid"] != false || fr.events[1].severity != "high" || fr.events[1].details["pdu"] != "set" {
		t.Fatalf("events = %+v", fr.events)
	}
}

func TestSNMPv1UnknownOIDIsNoSuchName(t *testing.T) {
	h, _ := newHandler("snmp", 100)
	resp := h.handle(snmpGet(0, "public", pduGet, "1.3.6.1.4.1.9.9.1"), "10.0.0.9")
	_, msg, _, _ := tlv(resp, 0)
	_, _, pos, _ := tlv(msg, 0)
	_, _, pos, _ = tlv(msg, pos)
	_, pdu, _, _ := tlv(msg, pos)
	_, _, p2, _ := tlv(pdu, 0)
	_, status, _, _ := tlv(pdu, p2)
	if decInt(status) != v1NoSuchName {
		t.Fatalf("error-status = %d, want noSuchName", decInt(status))
	}
}

func TestSNMPv3RecordsUser(t *testing.T) {
	h, fr := newHandler("snmp", 100)
	usm := tl(tagSeq, concat(tl(tagOctets, []byte{0x80, 0, 0x1f, 0x88}), tl(tagInt, []byte{0}), tl(tagInt, []byte{0}),
		tl(tagOctets, []byte("svc_monitor")), tl(tagOctets, nil), tl(tagOctets, nil)))
	global := tl(tagSeq, concat(tl(tagInt, []byte{1}), tl(tagInt, []byte{5, 0xdc}), tl(tagOctets, []byte{4}), tl(tagInt, []byte{3})))
	pkt := tl(tagSeq, concat(tl(tagInt, []byte{3}), global, tl(tagOctets, usm), tl(tagSeq, nil)))
	if h.handle(pkt, "10.0.0.9") != nil {
		t.Fatal("answered v3")
	}
	if fr.events[0].details["snmp_version"] != "v3" || fr.events[0].details["username"] != "svc_monitor" {
		t.Fatalf("event = %+v", fr.events[0])
	}
}

func TestSNMPRejectsGarbage(t *testing.T) {
	h, fr := newHandler("snmp", 100)
	for _, p := range [][]byte{nil, {0x30}, {0x30, 0x05, 2, 1, 9, 4, 0}, {0x30, 0x84, 1, 1, 1, 1}} {
		if h.handle(p, "10.0.0.9") != nil {
			t.Fatalf("replied to %x", p)
		}
	}
	if len(fr.events) != 0 {
		t.Fatalf("events = %+v", fr.events)
	}
}
