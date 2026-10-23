package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"
)

// buildType3 assembles a minimal NTLM AUTHENTICATE with the given identity and
// NT response, matching the field layout parseNTLMType3 reads.
func buildType3(user, domain, ws string, ntResp []byte) []byte {
	const hdr = 64
	dom := utf16le(domain)
	usr := utf16le(user)
	wks := utf16le(ws)
	payload := concat(ntResp, dom, usr, wks)

	msg := make([]byte, hdr)
	copy(msg[0:], ntlmSignature)
	binary.LittleEndian.PutUint32(msg[8:], 3) // AUTHENTICATE

	off := hdr
	put := func(pos, l int) {
		binary.LittleEndian.PutUint16(msg[pos:], uint16(l))
		binary.LittleEndian.PutUint16(msg[pos+2:], uint16(l))
		binary.LittleEndian.PutUint32(msg[pos+4:], uint32(off))
		off += l
	}
	put(20, len(ntResp)) // NtChallengeResponse
	put(28, len(dom))    // DomainName
	put(36, len(usr))    // UserName
	put(44, len(wks))    // Workstation
	return append(msg, payload...)
}

// clientTLS wraps a pipe end as a TLS client. The decoy serves a self-signed
// cert by design, so the test client does not verify it.
func clientTLS(c net.Conn) *tls.Conn {
	return tls.Client(c, &tls.Config{InsecureSkipVerify: true}) // #nosec G402 - test client against the decoy's self-signed cert
}

func TestNTLMType3ParseAndFormat(t *testing.T) {
	ntResp := make([]byte, 48) // 16 NTProofStr + 32 blob
	for i := range ntResp {
		ntResp[i] = byte(i)
	}
	msg := buildType3("administrator", "CORP", "WS01", ntResp)

	c, ok := parseNTLMType3(msg)
	if !ok || c.user != "administrator" || c.domain != "CORP" || c.workstation != "WS01" {
		t.Fatalf("parsed = %+v ok=%v", c, ok)
	}
	if !bytes.Equal(c.ntResponse, ntResp) {
		t.Fatal("NT response mismatch")
	}

	ch := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	h := netNTLMv2(c, ch)
	want := "administrator::CORP:" + hex.EncodeToString(ch) + ":" +
		hex.EncodeToString(ntResp[:16]) + ":" + hex.EncodeToString(ntResp[16:])
	if h != want {
		t.Fatalf("netNTLMv2 = %q", h)
	}
}

func TestBuildNTLMChallengeIsParseable(t *testing.T) {
	ch := randomChallenge()
	c2 := buildNTLMChallenge(ch, persona{hostname: "DC01", domain: "corp.local"})
	if !bytes.HasPrefix(c2, ntlmSignature) || binary.LittleEndian.Uint32(c2[8:]) != 2 {
		t.Fatal("not a Type 2")
	}
	if !bytes.Equal(c2[24:32], ch[:8]) {
		t.Fatal("server challenge not embedded at offset 24")
	}
	// The NetBIOS domain (CORP) must appear in TargetName/TargetInfo.
	if !bytes.Contains(c2, utf16le("CORP")) {
		t.Fatal("persona domain not in challenge target info")
	}
}

func TestParseNegReq(t *testing.T) {
	variable := []byte("Cookie: mstshash=x\r\n")
	req := make([]byte, 8)
	req[0] = negReqType
	binary.LittleEndian.PutUint16(req[2:], 8)
	binary.LittleEndian.PutUint32(req[4:], protoHybrid)
	variable = append(variable, req...)
	if got := parseNegReq(variable); got&protoHybrid == 0 {
		t.Fatalf("parseNegReq = %#x, want HYBRID bit", got)
	}
	if parseNegReq([]byte("no neg here")) != 0 {
		t.Fatal("expected 0 when no neg request present")
	}
}

func TestRDPNLACaptureEndToEnd(t *testing.T) {
	per := persona{hostname: "DC01", domain: "corp.local"}
	srvTLS, err := selfSignedTLS(per)
	if err != nil {
		t.Fatalf("tls: %v", err)
	}
	fr := &fakeReporter{}
	h := &rdpHandler{ts: fr, port: 3389, persona: per, cap: newCredCapture("hash", "", "k"), ntlmMode: "hash", tlsConfig: srvTLS}

	client, server := net.Pipe()
	done := make(chan struct{})
	go func() { h.serve(server); close(done) }()

	deadline := time.Now().Add(5 * time.Second)
	client.SetDeadline(deadline)

	// X.224 CR with a HYBRID neg request (no cookie this time).
	neg := make([]byte, 8)
	neg[0] = negReqType
	binary.LittleEndian.PutUint16(neg[2:], 8)
	binary.LittleEndian.PutUint32(neg[4:], protoHybrid)
	x224 := append([]byte{0xE0, 0, 0, 0, 0, 0}, neg...)
	x224 = append([]byte{byte(len(x224))}, x224...)
	tpkt := []byte{0x03, 0x00, 0x00, byte(4 + len(x224))}
	if _, err := client.Write(append(tpkt, x224...)); err != nil {
		t.Fatalf("write CR: %v", err)
	}

	// Read the CC and confirm it selects HYBRID.
	cc := make([]byte, 64)
	n, err := client.Read(cc)
	if err != nil {
		t.Fatalf("read CC: %v", err)
	}
	if n < 19 || cc[5] != 0xD0 || cc[11] != negRspType ||
		binary.LittleEndian.Uint32(cc[15:]) != protoHybrid {
		t.Fatalf("CC did not select HYBRID: % x", cc[:n])
	}

	// TLS, then CredSSP.
	tlsClient := clientTLS(client)
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	type1 := append(append([]byte{}, ntlmSignature...), make([]byte, 24)...)
	binary.LittleEndian.PutUint32(type1[8:], 1)
	tlsClient.Write(buildChallengeTSRequest(6, type1, false))

	// Read the challenge TSRequest and pull out the server challenge.
	chReq, err := readTSRequest(tlsClient)
	if err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	m, ok := parseTSRequest(chReq)
	if !ok || m.ntlmType != 2 {
		t.Fatalf("expected Type 2, got %+v", m)
	}
	serverChallenge := m.ntlm[24:32]

	// Send the AUTHENTICATE.
	ntResp := make([]byte, 48)
	for i := range ntResp {
		ntResp[i] = byte(0xA0 + i%16)
	}
	type3 := buildType3("administrator", "CORP", "WS01", ntResp)
	tlsClient.Write(buildChallengeTSRequest(6, type3, false))

	// Drain the server's error reply so it can finish, then close.
	readTSRequest(tlsClient)
	tlsClient.Close()
	client.Close()
	<-done

	ev := fr.find("rdp_login")
	if ev == nil {
		t.Fatal("no rdp_login event from NLA")
	}
	if ev.details["username"] != "CORP\\administrator" || ev.details["workstation"] != "WS01" || ev.details["auth"] != "nla_ntlm" {
		t.Fatalf("event = %+v", ev.details)
	}
	hashcat, _ := ev.details["netntlmv2"].(string)
	wantHash := "administrator::CORP:" + hex.EncodeToString(serverChallenge) + ":" +
		hex.EncodeToString(ntResp[:16]) + ":" + hex.EncodeToString(ntResp[16:])
	if hashcat != wantHash {
		t.Fatalf("netntlmv2 = %q\nwant      %q", hashcat, wantHash)
	}
	// Even in hash mode, no password-style plaintext of the response leaks.
	if strings.Contains(hashcat, "administrator::CORP::") {
		t.Fatal("malformed hashcat string")
	}
}

func TestRDPNLAIdentityModeOmitsHash(t *testing.T) {
	per := persona{hostname: "DC01", domain: "corp.local"}
	srvTLS, _ := selfSignedTLS(per)
	fr := &fakeReporter{}
	h := &rdpHandler{ts: fr, port: 3389, persona: per, cap: newCredCapture("hash", "", "k"), ntlmMode: "identity", tlsConfig: srvTLS}

	client, server := net.Pipe()
	done := make(chan struct{})
	go func() { h.serve(server); close(done) }()
	client.SetDeadline(time.Now().Add(5 * time.Second))

	neg := make([]byte, 8)
	neg[0] = negReqType
	binary.LittleEndian.PutUint16(neg[2:], 8)
	binary.LittleEndian.PutUint32(neg[4:], protoHybrid)
	x224 := append([]byte{0xE0, 0, 0, 0, 0, 0}, neg...)
	x224 = append([]byte{byte(len(x224))}, x224...)
	client.Write(append([]byte{0x03, 0x00, 0x00, byte(4 + len(x224))}, x224...))
	cc := make([]byte, 64)
	client.Read(cc)

	tlsClient := clientTLS(client)
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	type1 := append(append([]byte{}, ntlmSignature...), make([]byte, 24)...)
	binary.LittleEndian.PutUint32(type1[8:], 1)
	tlsClient.Write(buildChallengeTSRequest(6, type1, false))
	readTSRequest(tlsClient)
	ntResp := make([]byte, 48)
	tlsClient.Write(buildChallengeTSRequest(6, buildType3("svc", "CORP", "WS", ntResp), false))
	readTSRequest(tlsClient)
	tlsClient.Close()
	client.Close()
	<-done

	ev := fr.find("rdp_login")
	if ev == nil || ev.details["username"] != "CORP\\svc" {
		t.Fatalf("event = %+v", ev)
	}
	if _, has := ev.details["netntlmv2"]; has {
		t.Fatal("identity mode must not store the NetNTLMv2 response")
	}
}
