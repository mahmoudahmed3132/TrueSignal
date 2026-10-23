package main

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"time"

	sdk "github.com/truesignal/sdk-go"
)

// rdpHandler emulates enough of the RDP connection sequence to look like a real
// Windows host and to capture who tried to log in:
//
//   - the username in the X.224 Connection Request "mstshash" cookie (sent by
//     mstsc/xfreerdp before any encryption), and
//   - when the client requests Network Level Authentication and TS_CAPTURE_NTLM
//     is not "off", the account from the CredSSP/NTLM exchange (domain\user and
//     workstation), plus, only in "hash" mode, the crackable NetNTLMv2 artifact.
type rdpHandler struct {
	ts        reporter
	port      int
	persona   persona
	cap       credcapture
	ntlmMode  string // "off" | "identity" | "hash"
	tlsConfig *tls.Config
}

var mstshashRe = regexp.MustCompile(`mstshash=([^\r\n]*)`)

// RDP negotiation protocol bits (MS-RDPBCGR).
const (
	protoRDP           = 0x00000000
	protoHybrid        = 0x00000002
	negReqType         = 0x01
	negRspType         = 0x02
	statusLogonFailure = 0xC000006D
)

func (h *rdpHandler) serve(conn net.Conn) {
	defer conn.Close()
	srcIP := remoteIP(conn)

	h.ts.ReportEventSeverity("low", "rdp_connection", srcIP, h.target(),
		sdk.EventDetails{{Key: "protocol", Value: "rdp"}, {Key: "dst_port", Value: h.port}})

	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 7 {
		return
	}
	data := buf[:n]

	// TPKT header: version 3, reserved 0, length (big-endian u16).
	if data[0] != 0x03 {
		return
	}
	tpktLen := int(binary.BigEndian.Uint16(data[2:4]))
	if tpktLen < 7 || tpktLen > n {
		tpktLen = n
	}
	x224 := data[4:tpktLen]

	// X.224 CR: LI, code 0xE0, DST-REF(2), SRC-REF(2), CLASS(1), [variable].
	if len(x224) < 6 || x224[1] != 0xE0 {
		return
	}
	srcRef := x224[4:6]
	requested := parseNegReq(x224[6:])

	// The mstshash cookie is pre-auth and present regardless of NLA.
	if m := mstshashRe.FindSubmatch(data); m != nil {
		if username := sanitizeUTF8(string(m[1])); username != "" {
			h.ts.ReportEventSeverity("critical", "rdp_login", srcIP, h.target(),
				sdk.EventDetails{
					{Key: "protocol", Value: "rdp"},
					{Key: "dst_port", Value: h.port},
					{Key: "username", Value: username},
					{Key: "auth", Value: "mstshash"},
					{Key: "note", Value: "pre-authentication cookie"},
				})
		}
	}

	// If the client asked for NLA and we're configured to capture it, select
	// HYBRID and run CredSSP; otherwise answer plain RDP.
	if h.ntlmMode != "off" && h.tlsConfig != nil && requested&protoHybrid != 0 {
		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write(h.connectionConfirm(srcRef, protoHybrid)); err != nil {
			return
		}
		h.runNLA(conn, srcIP)
		return
	}

	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	conn.Write(h.connectionConfirm(srcRef, protoRDP))
}

// runNLA performs the TLS + CredSSP/NTLM exchange and records the captured
// account. It never grants access: it answers the authenticate with a
// logon-failure NTSTATUS, exactly as a real host does for a bad password.
func (h *rdpHandler) runNLA(conn net.Conn, srcIP string) {
	tlsConn := tls.Server(conn, h.tlsConfig)
	tlsConn.SetDeadline(time.Now().Add(30 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		return
	}

	// TSRequest #1: client NTLM NEGOTIATE (Type 1).
	req1, err := readTSRequest(tlsConn)
	if err != nil {
		return
	}
	m1, ok := parseTSRequest(req1)
	if !ok || m1.ntlmType != 1 {
		return
	}

	challenge := randomChallenge()
	type2 := buildNTLMChallenge(challenge, h.persona)
	if _, err := tlsConn.Write(buildChallengeTSRequest(m1.version, type2, m1.spnego)); err != nil {
		return
	}

	// TSRequest #2: client NTLM AUTHENTICATE (Type 3).
	req2, err := readTSRequest(tlsConn)
	if err != nil {
		return
	}
	m2, ok := parseTSRequest(req2)
	if ok && m2.ntlmType == 3 {
		if creds, ok := parseNTLMType3(m2.ntlm); ok {
			h.reportNLA(srcIP, creds, challenge)
		}
	}

	// Tell the client authentication failed, like a real server.
	tlsConn.Write(buildErrorTSRequest(m1.version, statusLogonFailure))
}

func (h *rdpHandler) reportNLA(srcIP string, c ntlm3, challenge []byte) {
	h.ts.ReportEventSeverity("critical", "rdp_login", srcIP, h.target(),
		ntlmLoginDetails("rdp", h.port, c, challenge, h.ntlmMode, "nla_ntlm"))
}

// parseNegReq returns the requestedProtocols bitmask from an RDP Negotiation
// Request in the X.224 CR variable part, or 0 if absent.
func parseNegReq(variable []byte) uint32 {
	for i := 0; i+8 <= len(variable); i++ {
		if variable[i] == negReqType && binary.LittleEndian.Uint16(variable[i+2:]) == 8 {
			return binary.LittleEndian.Uint32(variable[i+4:])
		}
	}
	return 0
}

// connectionConfirm builds an X.224 Connection Confirm that echoes the client's
// SRC-REF, uses the SRC-REF 0x1234 real Windows returns (nmap fingerprints on
// it), and advertises the selected security protocol.
func (h *rdpHandler) connectionConfirm(clientSrcRef []byte, selected uint32) []byte {
	negRsp := make([]byte, 8)
	negRsp[0] = negRspType
	binary.LittleEndian.PutUint16(negRsp[2:], 8)
	binary.LittleEndian.PutUint32(negRsp[4:], selected)

	x224 := []byte{0xD0} // CC
	x224 = append(x224, clientSrcRef...)
	x224 = append(x224, 0x12, 0x34) // SRC-REF (server)
	x224 = append(x224, 0x00)       // CLASS
	x224 = append(x224, negRsp...)
	full := append([]byte{byte(len(x224))}, x224...)

	tpkt := make([]byte, 4)
	tpkt[0] = 0x03
	binary.BigEndian.PutUint16(tpkt[2:4], uint16(4+len(full)))
	return append(tpkt, full...)
}

func (h *rdpHandler) target() string {
	return fmt.Sprintf("RDP:%d (%s)", h.port, h.persona.hostname)
}

// readTSRequest reads one complete DER SEQUENCE (a CredSSP TSRequest) from the
// TLS stream, bounded so a malformed length can't make us read forever.
func readTSRequest(conn net.Conn) ([]byte, error) {
	hdr := make([]byte, 2)
	if _, err := readFull(conn, hdr); err != nil {
		return nil, err
	}
	if hdr[0] != tagSequence {
		return nil, fmt.Errorf("not a TSRequest")
	}
	bodyLen := int(hdr[1])
	prefix := hdr
	if hdr[1]&0x80 != 0 { // long-form length
		count := int(hdr[1] & 0x7f)
		if count < 1 || count > 4 {
			return nil, fmt.Errorf("bad length")
		}
		lb := make([]byte, count)
		if _, err := readFull(conn, lb); err != nil {
			return nil, err
		}
		bodyLen = 0
		for _, b := range lb {
			bodyLen = bodyLen<<8 | int(b)
		}
		prefix = append(hdr, lb...)
	}
	if bodyLen < 0 || bodyLen > 1<<16 {
		return nil, fmt.Errorf("TSRequest too large")
	}
	body := make([]byte, bodyLen)
	if _, err := readFull(conn, body); err != nil {
		return nil, err
	}
	return append(prefix, body...), nil
}

func readFull(conn net.Conn, p []byte) (int, error) {
	got := 0
	for got < len(p) {
		n, err := conn.Read(p[got:])
		got += n
		if err != nil {
			return got, err
		}
	}
	return got, nil
}
