package main

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	sdk "github.com/truesignal/sdk-go"
)

// fakeReporter records emitted events for assertions.
type fakeReporter struct{ events []event }

type event struct {
	severity, trigger, source, target string
	details                           map[string]any
}

func (f *fakeReporter) ReportEventSeverity(severity, trigger, source, target string, d sdk.EventDetails) bool {
	m := map[string]any{}
	for _, kv := range d {
		m[kv.Key] = kv.Value
	}
	f.events = append(f.events, event{severity, trigger, source, target, m})
	return true
}

func (f *fakeReporter) find(trigger string) *event {
	for i := range f.events {
		if f.events[i].trigger == trigger {
			return &f.events[i]
		}
	}
	return nil
}

func TestParseServices(t *testing.T) {
	ok, err := parseServices("ldap:389, ldaps:636 ,rdp:3389")
	if err != nil || len(ok) != 3 || ok[0].proto != "ldap" || ok[2].port != 3389 {
		t.Fatalf("parse = %v, %v", ok, err)
	}
	for _, bad := range []string{"ldap:389,rdp:389", "smtp:25", "ldap:0", "ldap", ""} {
		if _, err := parseServices(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestCredCaptureModes(t *testing.T) {
	key := newCredCapture("hash", "", "ts_key_node")
	d := details(key.password("S3cret!"))
	if _, plain := d["password"]; plain {
		t.Fatal("hash mode must not store the cleartext password")
	}
	if d["password_hmac"] == nil || d["password_length"] != 7 || d["hmac_key_id"] == nil {
		t.Fatalf("hash details = %v", d)
	}
	// Same key + value is stable (correlation); a different node key differs.
	if key.password("x")[0].Value != newCredCapture("hash", "", "ts_key_node").password("x")[0].Value {
		t.Error("same key must give the same HMAC")
	}
	if key.password("x")[0].Value == newCredCapture("hash", "", "ts_key_other").password("x")[0].Value {
		t.Error("different node keys must give different HMACs")
	}
	if p := details(newCredCapture("plain", "", "n").password("S3cret!")); p["password"] != "S3cret!" {
		t.Errorf("plain = %v", p)
	}
	if n := details(newCredCapture("none", "", "n").password("S3cret!")); n["password_submitted"] != true {
		t.Errorf("none = %v", n)
	}
}

func details(d sdk.EventDetails) map[string]any {
	m := map[string]any{}
	for _, kv := range d {
		m[kv.Key] = kv.Value
	}
	return m
}

func TestLdapSimpleBindCapturesAndReplies(t *testing.T) {
	fr := &fakeReporter{}
	h := &ldapHandler{ts: fr, proto: "ldap", port: 389, cap: newCredCapture("hash", "", "k"), persona: persona{hostname: "DC01", domain: "corp.local"}}

	client, server := net.Pipe()
	done := make(chan struct{})
	go func() { h.serve(server); close(done) }()

	name := "cn=admin,dc=corp,dc=local"
	password := "P@ssw0rd!"
	bindBody := concat(berInt(tagInteger, 3), berTLV(tagOctetStr, []byte(name)), berTLV(authSimple, []byte(password)))
	msg := berTLV(tagSequence, concat(berInt(tagInteger, 1), berTLV(appBindRequest, bindBody)))

	client.SetDeadline(time.Now().Add(2 * time.Second))
	client.Write(msg)

	resp := make([]byte, 256)
	n, err := client.Read(resp)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	client.Close()
	<-done

	// Reply: SEQUENCE { msgID, bindResponse[0x61] { ENUM resultCode, ... } }
	r := &berReader{buf: resp[:n]}
	_, outer, _ := r.readTLV()
	rr := &berReader{buf: outer}
	rr.readTLV() // msgID
	tag, body, _ := rr.readTLV()
	if tag != appBindResponse {
		t.Fatalf("reply op tag = %#x", tag)
	}
	code := &berReader{buf: body}
	_, cb, _ := code.readTLV()
	if len(cb) == 0 || int(cb[0]) != resultInvalidCredentials {
		t.Fatalf("resultCode = %v, want 49", cb)
	}

	ev := fr.find("ldap_login")
	if ev == nil {
		t.Fatal("no ldap_login event")
	}
	if ev.severity != "critical" || ev.details["bind_dn"] != name {
		t.Fatalf("login event = %+v", ev)
	}
	if ev.details["password_hmac"] == nil {
		t.Fatal("password not captured")
	}
	// The cleartext password must never appear anywhere in the event.
	for _, v := range ev.details {
		if s, ok := v.(string); ok && strings.Contains(s, password) {
			t.Fatalf("cleartext password leaked in %v", v)
		}
	}
}

func TestLdapAnonymousBindSucceeds(t *testing.T) {
	fr := &fakeReporter{}
	h := &ldapHandler{ts: fr, proto: "ldap", port: 389, cap: newCredCapture("hash", "", "k"), persona: persona{hostname: "DC01"}}
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() { h.serve(server); close(done) }()

	body := concat(berInt(tagInteger, 3), berTLV(tagOctetStr, nil), berTLV(authSimple, nil))
	msg := berTLV(tagSequence, concat(berInt(tagInteger, 1), berTLV(appBindRequest, body)))
	client.SetDeadline(time.Now().Add(2 * time.Second))
	client.Write(msg)
	resp := make([]byte, 64)
	n, _ := client.Read(resp)
	client.Close()
	<-done

	r := &berReader{buf: resp[:n]}
	_, outer, _ := r.readTLV()
	rr := &berReader{buf: outer}
	rr.readTLV()
	_, respBody, _ := rr.readTLV()
	code := &berReader{buf: respBody}
	_, cb, _ := code.readTLV()
	if int(cb[0]) != resultSuccess {
		t.Fatalf("anonymous bind resultCode = %v, want 0", cb)
	}
	if fr.find("ldap_login") != nil {
		t.Fatal("anonymous bind must not raise a login event")
	}
}

func TestRdpCapturesMstshashAndConfirms(t *testing.T) {
	fr := &fakeReporter{}
	h := &rdpHandler{ts: fr, port: 3389, persona: persona{hostname: "WIN-RDP"}}
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() { h.serve(server); close(done) }()

	cookie := []byte("Cookie: mstshash=corp\\\\administrator\r\n")
	x224body := append([]byte{0xE0, 0x00, 0x00, 0x00, 0x00, 0x00}, cookie...)
	x224 := append([]byte{byte(len(x224body))}, x224body...)
	tpkt := make([]byte, 4)
	tpkt[0] = 0x03
	binary.BigEndian.PutUint16(tpkt[2:4], uint16(4+len(x224)))
	cr := append(tpkt, x224...)

	client.SetDeadline(time.Now().Add(2 * time.Second))
	client.Write(cr)
	resp := make([]byte, 64)
	n, err := client.Read(resp)
	if err != nil {
		t.Fatalf("read CC: %v", err)
	}
	client.Close()
	<-done

	// Connection Confirm: TPKT then X.224 code 0xD0, server SRC-REF 0x1234.
	if n < 11 || resp[0] != 0x03 || resp[5] != 0xD0 {
		t.Fatalf("not a CC: % x", resp[:n])
	}
	if resp[8] != 0x12 || resp[9] != 0x34 {
		t.Fatalf("server SRC-REF = % x, want 12 34", resp[8:10])
	}

	ev := fr.find("rdp_login")
	if ev == nil || ev.severity != "critical" {
		t.Fatalf("rdp_login event = %+v", ev)
	}
	if ev.details["username"] != "corp\\\\administrator" {
		t.Fatalf("username = %v", ev.details["username"])
	}
}
