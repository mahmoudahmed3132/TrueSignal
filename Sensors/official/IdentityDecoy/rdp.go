package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"time"

	sdk "github.com/truesignal/sdk-go"
)

// rdpHandler implements just enough of the RDP connection sequence to look like
// a real Windows host to a scanner and to capture the username an RDP client
// sends in the X.224 Connection Request "mstshash" cookie (mstsc, xfreerdp and
// most brute-force tools put the target account there before any encryption).
//
// Increment 1 captures that cookie and answers the Connection Request. Network
// Level Authentication (CredSSP/NTLM, which would yield a crackable hash) is a
// later increment; it is gated behind an explicit capture mode when added.
type rdpHandler struct {
	ts      reporter
	port    int
	persona persona
}

var mstshashRe = regexp.MustCompile(`mstshash=([^\r\n]*)`)

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

	username := ""
	if m := mstshashRe.FindSubmatch(data); m != nil {
		username = sanitizeUTF8(string(m[1]))
	}
	if username != "" {
		h.ts.ReportEventSeverity("critical", "rdp_login", srcIP, h.target(),
			sdk.EventDetails{
				{Key: "protocol", Value: "rdp"},
				{Key: "dst_port", Value: h.port},
				{Key: "username", Value: username},
				{Key: "note", Value: "mstshash cookie; pre-authentication"},
			})
	}

	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	conn.Write(h.connectionConfirm(srcRef))
}

// connectionConfirm builds an X.224 Connection Confirm that echoes the client's
// SRC-REF and uses the SRC-REF 0x1234 that real Windows returns (nmap's RDP
// fingerprint matches on that exact value).
func (h *rdpHandler) connectionConfirm(clientSrcRef []byte) []byte {
	x224 := []byte{0xD0} // CC
	x224 = append(x224, clientSrcRef...)
	x224 = append(x224, 0x12, 0x34) // SRC-REF (server)
	x224 = append(x224, 0x00)       // CLASS
	full := append([]byte{byte(len(x224))}, x224...)

	tpkt := make([]byte, 4)
	tpkt[0] = 0x03
	binary.BigEndian.PutUint16(tpkt[2:4], uint16(4+len(full)))
	return append(tpkt, full...)
}

func (h *rdpHandler) target() string {
	return fmt.Sprintf("RDP:%d (%s)", h.port, h.persona.hostname)
}
