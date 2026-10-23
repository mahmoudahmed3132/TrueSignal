package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"
)

// buildType1 is a minimal NTLM NEGOTIATE.
func buildType1() []byte {
	msg := make([]byte, 32)
	copy(msg, ntlmSignature)
	binary.LittleEndian.PutUint32(msg[8:], 1)
	binary.LittleEndian.PutUint32(msg[12:], flagUnicode|flagNTLM|flagExtendedSec)
	return msg
}

func ntlmv2Resp() []byte {
	r := make([]byte, 48) // 16 NTProofStr + 32 blob
	for i := range r {
		r[i] = byte(0xA0 + i)
	}
	return r
}

type bindReply struct {
	code      int
	matchedDN []byte
	diag      string
	saslCreds []byte
}

// ldapTestClient drives an ldapHandler over a pipe.
type ldapTestClient struct {
	t     *testing.T
	conn  net.Conn
	msgID int
	buf   []byte
}

func newLDAPTest(t *testing.T, mode string) (*ldapTestClient, *fakeReporter, func()) {
	t.Helper()
	fr := &fakeReporter{}
	h := &ldapHandler{ts: fr, proto: "ldap", port: 389, cap: newCredCapture("hash", "", "k"),
		persona: persona{hostname: "DC01", domain: "corp.local"}, ntlmMode: mode}
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() { h.serve(server); close(done) }()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	return &ldapTestClient{t: t, conn: client}, fr, func() { client.Close(); <-done }
}

func (c *ldapTestClient) bindMessage(name string, authTag byte, authVal []byte) []byte {
	c.msgID++
	body := concat(berInt(tagInteger, 3), berTLV(tagOctetStr, []byte(name)), berTLV(authTag, authVal))
	return berTLV(tagSequence, concat(berInt(tagInteger, c.msgID), berTLV(appBindRequest, body)))
}

func (c *ldapTestClient) bind(name string, authTag byte, authVal []byte) bindReply {
	c.t.Helper()
	if _, err := c.conn.Write(c.bindMessage(name, authTag, authVal)); err != nil {
		c.t.Fatalf("write: %v", err)
	}
	return c.readReply()
}

func (c *ldapTestClient) readReply() bindReply {
	c.t.Helper()
	tmp := make([]byte, 4096)
	for {
		if total, complete, ok := berElementLen(c.buf); ok && complete {
			msg := c.buf[:total]
			c.buf = c.buf[total:]
			return parseBindReply(c.t, msg)
		}
		n, err := c.conn.Read(tmp)
		if err != nil {
			c.t.Fatalf("read reply: %v", err)
		}
		c.buf = append(c.buf, tmp[:n]...)
	}
}

func parseBindReply(t *testing.T, msg []byte) bindReply {
	t.Helper()
	r := &berReader{buf: msg}
	_, outer, _ := r.readTLV()
	rr := &berReader{buf: outer}
	rr.readTLV() // msgID
	tag, body, ok := rr.readTLV()
	if !ok || tag != appBindResponse {
		t.Fatalf("reply op tag = %#x", tag)
	}
	br := &berReader{buf: body}
	_, code, _ := br.readTLV()
	_, matched, _ := br.readTLV()
	_, diag, _ := br.readTLV()
	out := bindReply{code: int(code[len(code)-1]), matchedDN: matched, diag: string(diag)}
	if !br.done() {
		if t2, v, ok := br.readTLV(); ok && t2 == tagServerSaslCreds {
			out.saslCreds = v
		}
	}
	return out
}

func saslCreds(mech string, creds []byte) []byte {
	return concat(berTLV(tagOctetStr, []byte(mech)), berTLV(tagOctetStr, creds))
}

// challengeOf pulls the 8-byte server challenge out of a Type 2.
func challengeOf(t *testing.T, token []byte) []byte {
	t.Helper()
	msg, typ, _, ok := findNTLM(token)
	if !ok || typ != 2 || len(msg) < 32 {
		t.Fatalf("no NTLM CHALLENGE in %x", token)
	}
	return msg[24:32]
}

func TestLDAPSicilyNTLMCapture(t *testing.T) {
	c, fr, stop := newLDAPTest(t, "hash")
	defer stop()

	disc := c.bind("", authSicilyDisc, nil)
	if disc.code != resultSuccess || string(disc.matchedDN) != "NTLM" {
		t.Fatalf("discovery = %+v", disc)
	}
	neg := c.bind("NTLM", authSicilyNeg, buildType1())
	if neg.code != resultSuccess || !bytes.HasPrefix(neg.matchedDN, ntlmSignature) {
		t.Fatalf("negotiate = %+v", neg)
	}
	ch := challengeOf(t, neg.matchedDN)

	resp := c.bind("", authSicilyResp, buildType3("alice", "CORP", "WS01", ntlmv2Resp()))
	if resp.code != resultInvalidCredentials || !strings.Contains(resp.diag, "data 52e") {
		t.Fatalf("authenticate = %+v", resp)
	}

	ev := fr.find("ldap_login")
	if ev == nil || ev.severity != "critical" {
		t.Fatalf("no critical ldap_login: %+v", fr.events)
	}
	if ev.details["username"] != `CORP\alice` || ev.details["workstation"] != "WS01" || ev.details["auth"] != "sicily_ntlm" {
		t.Fatalf("details = %+v", ev.details)
	}
	hc, _ := ev.details["netntlmv2"].(string)
	if !strings.HasPrefix(hc, "alice::CORP:"+hex.EncodeToString(ch)+":") {
		t.Fatalf("netntlmv2 = %q", hc)
	}
}

func TestLDAPSASLRawNTLMIdentityMode(t *testing.T) {
	c, fr, stop := newLDAPTest(t, "identity")
	defer stop()

	neg := c.bind("", authSASL, saslCreds("GSS-SPNEGO", buildType1()))
	if neg.code != resultSaslBindInProgress || !bytes.HasPrefix(neg.saslCreds, ntlmSignature) {
		t.Fatalf("negotiate = %+v", neg)
	}
	resp := c.bind("", authSASL, saslCreds("GSS-SPNEGO", buildType3("bob", "CORP", "KALI", ntlmv2Resp())))
	if resp.code != resultInvalidCredentials {
		t.Fatalf("authenticate = %+v", resp)
	}
	ev := fr.find("ldap_login")
	if ev == nil || ev.details["username"] != `CORP\bob` || ev.details["auth"] != "sasl_ntlm" {
		t.Fatalf("event = %+v", fr.events)
	}
	if _, has := ev.details["netntlmv2"]; has {
		t.Fatal("identity mode must not record the NetNTLMv2 response")
	}
}

// spnegoInit builds a NegTokenInit offering mechs with an optional token.
func spnegoInit(mechs []byte, token []byte) []byte {
	inner := ctx(0, berTLV(tagSequence, mechs))
	if token != nil {
		inner = concat(inner, ctx(2, berTLV(tagOctetStr, token)))
	}
	return berTLV(0x60, concat(spnegoOID, ctx(0, berTLV(tagSequence, inner))))
}

func spnegoResp(token []byte) []byte {
	return ctx(1, berTLV(tagSequence, ctx(2, berTLV(tagOctetStr, token))))
}

func TestLDAPSASLSPNEGOWithKerberosFallback(t *testing.T) {
	c, fr, stop := newLDAPTest(t, "hash")
	defer stop()

	krbOID := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02}
	// Optimistic Kerberos token: the decoy must steer the client to NTLM.
	first := c.bind("", authSASL, saslCreds("GSS-SPNEGO", spnegoInit(concat(krbOID, ntlmOID), []byte("kerberos-ap-req"))))
	if first.code != resultSaslBindInProgress || !bytes.Contains(first.saslCreds, ntlmOID) || bytes.Contains(first.saslCreds, ntlmSignature) {
		t.Fatalf("kerberos fallback = %+v", first)
	}

	neg := c.bind("", authSASL, saslCreds("GSS-SPNEGO", spnegoResp(buildType1())))
	if neg.code != resultSaslBindInProgress || neg.saslCreds[0] != 0xA1 {
		t.Fatalf("negotiate = %+v (want SPNEGO NegTokenResp)", neg)
	}
	ch := challengeOf(t, neg.saslCreds)

	resp := c.bind("", authSASL, saslCreds("GSS-SPNEGO", spnegoResp(buildType3("svc_sql", "CORP", "SRV9", ntlmv2Resp()))))
	if resp.code != resultInvalidCredentials {
		t.Fatalf("authenticate = %+v", resp)
	}
	ev := fr.find("ldap_login")
	if ev == nil || ev.details["username"] != `CORP\svc_sql` {
		t.Fatalf("event = %+v", fr.events)
	}
	if hc, _ := ev.details["netntlmv2"].(string); !strings.Contains(hc, hex.EncodeToString(ch)) {
		t.Fatalf("netntlmv2 = %q", hc)
	}
}

func TestLDAPMessageSplitAcrossReads(t *testing.T) {
	c, fr, stop := newLDAPTest(t, "identity")
	defer stop()

	c.bind("NTLM", authSicilyNeg, buildType1())
	msg := c.bindMessage("", authSicilyResp, buildType3("carol", "CORP", "WS02", ntlmv2Resp()))
	half := len(msg) / 2
	c.conn.Write(msg[:half])
	c.conn.Write(msg[half:])
	if r := c.readReply(); r.code != resultInvalidCredentials {
		t.Fatalf("reply = %+v", r)
	}
	if ev := fr.find("ldap_login"); ev == nil || ev.details["username"] != `CORP\carol` {
		t.Fatalf("split message not captured: %+v", fr.events)
	}
}

func TestLDAPNTLMOffRefusesMechanism(t *testing.T) {
	c, fr, stop := newLDAPTest(t, "off")
	defer stop()
	if r := c.bind("", authSicilyDisc, nil); r.code != resultAuthMethodNotSupp {
		t.Fatalf("discovery = %+v", r)
	}
	if fr.find("ldap_login") != nil {
		t.Fatal("off mode must not capture")
	}
}

func TestLDAPOtherSASLMechanismRecorded(t *testing.T) {
	c, fr, stop := newLDAPTest(t, "identity")
	defer stop()
	if r := c.bind("", authSASL, saslCreds("GSSAPI", []byte("krb"))); r.code != resultAuthMethodNotSupp {
		t.Fatalf("GSSAPI = %+v", r)
	}
	if ev := fr.find("ldap_query"); ev == nil || ev.details["sasl_mechanism"] != "GSSAPI" {
		t.Fatalf("events = %+v", fr.events)
	}
}

func TestLDAPAnonymousNTLMIsQuery(t *testing.T) {
	c, fr, stop := newLDAPTest(t, "identity")
	defer stop()
	c.bind("NTLM", authSicilyNeg, buildType1())
	c.bind("", authSicilyResp, buildType3("", "", "WS03", nil))
	if fr.find("ldap_login") != nil {
		t.Fatal("anonymous NTLM must not be a login")
	}
	if ev := fr.find("ldap_query"); ev == nil || ev.details["auth"] != "sicily_ntlm_anonymous" {
		t.Fatalf("events = %+v", fr.events)
	}
}

func TestLDAPAuthenticateWithoutChallengeIgnored(t *testing.T) {
	c, fr, stop := newLDAPTest(t, "hash")
	defer stop()
	if r := c.bind("", authSicilyResp, buildType3("eve", "CORP", "X", ntlmv2Resp())); r.code != resultInvalidCredentials {
		t.Fatalf("reply = %+v", r)
	}
	if fr.find("ldap_login") != nil {
		t.Fatal("an AUTHENTICATE without our CHALLENGE must not be reported")
	}
}

func TestNetNTLMv2SkipsNTLMv1(t *testing.T) {
	c := ntlm3{user: "u", domain: "D", ntResponse: make([]byte, 24)}
	if got := netNTLMv2(c, make([]byte, 8)); got != "" {
		t.Fatalf("NTLMv1 response formatted as mode 5600: %q", got)
	}
}
