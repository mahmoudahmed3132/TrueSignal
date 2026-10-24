package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/truesignal/sdk-go"
	"github.com/truesignal/sdk-go/decoy"
)

type event struct {
	severity, trigger string
	details           map[string]any
}

type fakeReporter struct {
	mu     sync.Mutex
	events []event
}

func (f *fakeReporter) ReportEventSeverity(severity, trigger, _, _ string, d sdk.EventDetails) bool {
	m := map[string]any{}
	for _, kv := range d {
		m[kv.Key] = kv.Value
	}
	f.mu.Lock()
	f.events = append(f.events, event{severity, trigger, m})
	f.mu.Unlock()
	return true
}

func (f *fakeReporter) find(trigger string) *event {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.events {
		if f.events[i].trigger == trigger {
			return &f.events[i]
		}
	}
	return nil
}

// start serves one connection of proto over a pipe and returns the client end.
func start(t *testing.T, proto, captureMode string) (net.Conn, *fakeReporter, func()) {
	t.Helper()
	fr := &fakeReporter{}
	h := &handler{ts: fr, proto: proto, port: 1, cap: decoy.NewCaptureWith(captureMode, "node-key", ""), persona: persona{hostname: "DB01"}, limit: decoy.NewLimiter(loginsPerMinute, time.Minute)}
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() { h.serve(server); close(done) }()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	return client, fr, func() { client.Close(); <-done }
}

func noCleartext(t *testing.T, e *event, secret string) {
	t.Helper()
	for k, v := range e.details {
		if s, ok := v.(string); ok && strings.Contains(s, secret) {
			t.Fatalf("cleartext password in %s", k)
		}
	}
	if e.details["password_hmac"] == nil || e.details["hmac_key_id"] == nil {
		t.Fatalf("password not captured as HMAC: %v", e.details)
	}
}

// --- MySQL ---

func lenencStr(s string) []byte { return append([]byte{byte(len(s))}, s...) }

func mysqlHandshakeResponse(user, db string, authResp []byte, attrs map[string]string) []byte {
	caps := uint32(capProtocol41 | capSecureConnection | capConnectWithDB | capPluginAuth | capPluginAuthLenenc | capConnectAttrs)
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, caps)
	binary.Write(&b, binary.LittleEndian, uint32(1<<24))
	b.WriteByte(33)
	b.Write(make([]byte, 23))
	b.WriteString(user + "\x00")
	b.Write(lenencStr(string(authResp)))
	b.WriteString(db + "\x00")
	b.WriteString("mysql_native_password\x00")
	var a bytes.Buffer
	for k, v := range attrs {
		a.Write(lenencStr(k))
		a.Write(lenencStr(v))
	}
	b.Write(lenencStr(a.String()))
	return b.Bytes()
}

func TestMySQLLoginRefusedAndRecorded(t *testing.T) {
	c, fr, stop := start(t, "mysql", "hash")
	defer stop()

	_, greet, err := readMySQLPacket(c)
	if err != nil || greet[0] != 10 || !bytes.Contains(greet, []byte(mysqlServerVersion)) || !bytes.Contains(greet, []byte("mysql_native_password")) {
		t.Fatalf("greeting = %q (%v)", greet, err)
	}
	caps := uint32(binary.LittleEndian.Uint16(greet[len(mysqlServerVersion)+2+4+8+1:]))
	if caps&capSSL != 0 {
		t.Fatal("decoy must not offer TLS")
	}
	writeMySQLPacket(c, 1, mysqlHandshakeResponse("svc_backup7f3a", "payments", make([]byte, 20), map[string]string{"program_name": "mysql", "_os": "Linux"}))
	seq, errPkt, err := readMySQLPacket(c)
	if err != nil || seq != 2 || errPkt[0] != 0xff || binary.LittleEndian.Uint16(errPkt[1:]) != 1045 ||
		!strings.Contains(string(errPkt), "Access denied for user 'svc_backup7f3a'") || !strings.Contains(string(errPkt), "(using password: YES)") {
		t.Fatalf("ERR = seq %d %q (%v)", seq, errPkt, err)
	}
	ev := fr.find("mysql_login")
	if ev == nil || ev.severity != "critical" || ev.details["username"] != "svc_backup7f3a" || ev.details["database"] != "payments" ||
		ev.details["client_app"] != "mysql" || ev.details["client_os"] != "Linux" || ev.details["password_submitted"] != true {
		t.Fatalf("event = %+v", ev)
	}
}

func TestMySQLRejectsGarbage(t *testing.T) {
	if _, ok := parseMySQLLogin([]byte{1, 2, 3}); ok {
		t.Fatal("short packet accepted")
	}
	p := mysqlHandshakeResponse("u", "d", nil, nil)
	// Cut inside the user name (no NUL terminator): nothing usable.
	if _, ok := parseMySQLLogin(p[:33]); ok {
		t.Fatal("truncated packet accepted")
	}
}

// --- PostgreSQL ---

func pgStartup(code uint32, params ...string) []byte {
	var body bytes.Buffer
	for _, p := range params {
		body.WriteString(p + "\x00")
	}
	if len(params) > 0 {
		body.WriteByte(0)
	}
	out := make([]byte, 8)
	binary.BigEndian.PutUint32(out, uint32(8+body.Len()))
	binary.BigEndian.PutUint32(out[4:], code)
	return append(out, body.Bytes()...)
}

func TestPostgresCapturesCleartextAsHMAC(t *testing.T) {
	c, fr, stop := start(t, "postgres", "hash")
	defer stop()

	c.Write(pgStartup(pgSSLRequest))
	if b, _ := readFull(c, 1); b[0] != 'N' {
		t.Fatalf("SSLRequest answer = %q", b)
	}
	c.Write(pgStartup(pgProtocol3, "user", "postgres", "database", "billing", "application_name", "psql"))
	auth, _ := readFull(c, 9)
	if auth[0] != 'R' || binary.BigEndian.Uint32(auth[5:]) != 3 {
		t.Fatalf("auth request = %v", auth)
	}
	c.Write(pgMessage('p', []byte("Summer2026!\x00")))
	hdr, _ := readFull(c, 5)
	body, _ := readFull(c, int(binary.BigEndian.Uint32(hdr[1:]))-4)
	if hdr[0] != 'E' || !bytes.Contains(body, []byte("28P01")) || !bytes.Contains(body, []byte(`password authentication failed for user "postgres"`)) {
		t.Fatalf("error = %q %q", hdr, body)
	}
	ev := fr.find("postgres_login")
	if ev == nil || ev.details["username"] != "postgres" || ev.details["database"] != "billing" || ev.details["client_app"] != "psql" || ev.details["auth"] != "cleartext" {
		t.Fatalf("event = %+v", ev)
	}
	noCleartext(t, ev, "Summer2026!")
}

// --- MSSQL ---

func tdsPacket(typ byte, eom bool, payload []byte) []byte {
	status := byte(0)
	if eom {
		status = 1
	}
	h := []byte{typ, status, 0, 0, 0, 0, 1, 0}
	binary.BigEndian.PutUint16(h[2:], uint16(len(payload)+8))
	return append(h, payload...)
}

func obfuscate(pw string) []byte {
	b := utf16le(pw)
	for i, c := range b {
		c = c<<4 | c>>4
		b[i] = c ^ 0xA5
	}
	return b
}

func login7(user, pw, host, app, server, db string) []byte {
	const fixed = 94
	p := make([]byte, fixed)
	var data bytes.Buffer
	put := func(pos int, raw []byte) {
		binary.LittleEndian.PutUint16(p[pos:], uint16(fixed+data.Len()))
		binary.LittleEndian.PutUint16(p[pos+2:], uint16(len(raw)/2))
		data.Write(raw)
	}
	put(36, utf16le(host))
	put(40, utf16le(user))
	put(44, obfuscate(pw))
	put(48, utf16le(app))
	put(52, utf16le(server))
	put(68, utf16le(db))
	out := append(p, data.Bytes()...)
	binary.LittleEndian.PutUint32(out, uint32(len(out)))
	return out
}

func readTDSReply(t *testing.T, c net.Conn) []byte {
	t.Helper()
	typ, payload, err := readTDSMessage(c)
	if err != nil || typ != tdsReply {
		t.Fatalf("reply type %#x err %v", typ, err)
	}
	return payload
}

func TestMSSQLLogin7(t *testing.T) {
	c, fr, stop := start(t, "mssql", "hash")
	defer stop()

	c.Write(tdsPacket(tdsPrelogin, true, []byte{0x01, 0, 6, 0, 1, 0xff, tdsEncryptOff}))
	pre := readTDSReply(t, c)
	// Fixed layout VERSION, ENCRYPTION, INSTOPT, THREADID: ENCRYPTION data sits
	// right after the 21-byte header and 6-byte version.
	if len(pre) < 28 || pre[20] != 0xff || pre[27] != tdsEncryptNotSup {
		t.Fatalf("prelogin = %x", pre)
	}
	if enc, ok := preloginEncryption(pre); !ok || enc != tdsEncryptNotSup {
		t.Fatalf("encryption option = %v %v", enc, ok)
	}

	// LOGIN7 split across two packets must be reassembled.
	l7 := login7("sa", "P@ss-Mssql-9", "KALI", "sqlmap", "DB01", "master")
	c.Write(tdsPacket(tdsLogin7, false, l7[:50]))
	c.Write(tdsPacket(tdsLogin7, true, l7[50:]))
	reply := readTDSReply(t, c)
	if reply[0] != 0xAA || binary.LittleEndian.Uint32(reply[3:]) != 18456 || !strings.Contains(fromUTF16le(reply[11:11+2*27]), "Login failed for user 'sa'") {
		t.Fatalf("error token = %x", reply)
	}
	ev := fr.find("mssql_login")
	if ev == nil || ev.details["username"] != "sa" || ev.details["client_host"] != "KALI" || ev.details["client_app"] != "sqlmap" ||
		ev.details["database"] != "master" || ev.details["auth"] != "sql" {
		t.Fatalf("event = %+v", ev)
	}
	noCleartext(t, ev, "P@ss-Mssql-9")
	// The HMAC is of the de-obfuscated password, so honeytoken matching works.
	want := decoy.NewCaptureWith("hash", "node-key", "").Password("P@ss-Mssql-9")[0].Value
	if ev.details["password_hmac"] != want {
		t.Fatal("HMAC is not of the recovered password")
	}
}

func TestDeobfuscateRoundTrip(t *testing.T) {
	if got := fromUTF16le(deobfuscateTDSPassword(obfuscate("Ünïcode-Pässwörd"))); got != "Ünïcode-Pässwörd" {
		t.Fatalf("got %q", got)
	}
}
