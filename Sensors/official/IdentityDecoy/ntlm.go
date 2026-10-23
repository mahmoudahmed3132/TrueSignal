package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"unicode/utf16"
)

// Minimal NTLM for the RDP decoy: build a CHALLENGE (Type 2) and parse an
// AUTHENTICATE (Type 3) to recover the account the client tried. The NTLMv2
// response in a Type 3 is a challenge/response; with our known server
// challenge it is a crackable NetNTLMv2 artifact, so it is only recorded when
// the operator opts into TS_CAPTURE_NTLM=hash. Behaviour is re-derived from
// MS-NLMP; no third-party NTLM code.

var ntlmSignature = []byte("NTLMSSP\x00")

// NTLM negotiate flags set in our challenge. UNICODE + NTLM + TARGET_INFO +
// EXTENDED_SESSIONSECURITY makes a client compute an NTLMv2 response.
const (
	flagUnicode      = 0x00000001
	flagRequestTgt   = 0x00000004
	flagNTLM         = 0x00000200
	flagAlwaysSign   = 0x00008000
	flagTargetDomain = 0x00010000
	flagExtendedSec  = 0x00080000
	flagTargetInfo   = 0x00800000
	flagVersion      = 0x02000000
	flag128          = 0x20000000
	flag56           = 0x80000000
)

func utf16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, r := range u {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}
	return b
}

func fromUTF16le(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return sanitizeUTF8(string(utf16.Decode(u)))
}

// avPair encodes one AV_PAIR (MsvAv id + UTF-16LE value).
func avPair(id uint16, value string) []byte {
	v := utf16le(value)
	out := make([]byte, 4+len(v))
	binary.LittleEndian.PutUint16(out[0:], id)
	binary.LittleEndian.PutUint16(out[2:], uint16(len(v)))
	copy(out[4:], v)
	return out
}

// buildNTLMChallenge builds a Type 2 (CHALLENGE) carrying the given server
// challenge and a realistic TargetInfo derived from the persona.
func buildNTLMChallenge(challenge []byte, per persona) []byte {
	nb := netbios(per.domain)
	host := strings.ToUpper(per.hostname)
	fqdnHost := per.hostname
	if per.domain != "" {
		fqdnHost = per.hostname + "." + per.domain
	}

	targetName := utf16le(nb)
	targetInfo := concat(
		avPair(0x0002, nb),             // MsvAvNbDomainName
		avPair(0x0001, host),           // MsvAvNbComputerName
		avPair(0x0004, per.domain),     // MsvAvDnsDomainName
		avPair(0x0003, fqdnHost),       // MsvAvDnsComputerName
		[]byte{0x00, 0x00, 0x00, 0x00}, // MsvAvEOL
	)

	flags := uint32(flagUnicode | flagRequestTgt | flagNTLM | flagAlwaysSign |
		flagTargetDomain | flagExtendedSec | flagTargetInfo | flagVersion | flag128 | flag56)

	const headerLen = 56
	msg := make([]byte, headerLen)
	copy(msg[0:], ntlmSignature)
	binary.LittleEndian.PutUint32(msg[8:], 2) // MessageType CHALLENGE

	tnOff := uint32(headerLen)
	binary.LittleEndian.PutUint16(msg[12:], uint16(len(targetName)))
	binary.LittleEndian.PutUint16(msg[14:], uint16(len(targetName)))
	binary.LittleEndian.PutUint32(msg[16:], tnOff)

	binary.LittleEndian.PutUint32(msg[20:], flags)
	copy(msg[24:], challenge[:8])
	// 32..40 reserved (zero)

	tiOff := tnOff + uint32(len(targetName))
	binary.LittleEndian.PutUint16(msg[40:], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint16(msg[42:], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint32(msg[44:], tiOff)

	// Version 10.0.17763 (reserved + NTLMRevisionCurrent 0x0F).
	copy(msg[48:], []byte{10, 0, 0x63, 0x45, 0, 0, 0, 0x0F})

	return concat(msg, targetName, targetInfo)
}

// ntlm3 holds what a Type 3 revealed.
type ntlm3 struct {
	user        string
	domain      string
	workstation string
	ntResponse  []byte
}

func field(msg []byte, pos int) (off, length int, ok bool) {
	if pos+8 > len(msg) {
		return 0, 0, false
	}
	length = int(binary.LittleEndian.Uint16(msg[pos:]))
	off = int(binary.LittleEndian.Uint32(msg[pos+4:]))
	if off < 0 || length < 0 || off+length > len(msg) {
		return 0, 0, false
	}
	return off, length, true
}

// parseNTLMType3 extracts the identity and NT response from an AUTHENTICATE.
func parseNTLMType3(msg []byte) (ntlm3, bool) {
	if len(msg) < 52 || binary.LittleEndian.Uint32(msg[8:]) != 3 {
		return ntlm3{}, false
	}
	var out ntlm3
	if off, l, ok := field(msg, 20); ok { // NtChallengeResponse
		out.ntResponse = append([]byte(nil), msg[off:off+l]...)
	}
	if off, l, ok := field(msg, 28); ok { // DomainName
		out.domain = fromUTF16le(msg[off : off+l])
	}
	if off, l, ok := field(msg, 36); ok { // UserName
		out.user = fromUTF16le(msg[off : off+l])
	}
	if off, l, ok := field(msg, 44); ok { // Workstation
		out.workstation = fromUTF16le(msg[off : off+l])
	}
	return out, true
}

// netNTLMv2 formats the hashcat mode 5600 string so a captured response can be
// handed to offline analysis: user::domain:serverChallenge:NTProofStr:blob.
func netNTLMv2(c ntlm3, serverChallenge []byte) string {
	if len(c.ntResponse) < 16 {
		return ""
	}
	ntProof := c.ntResponse[:16]
	blob := c.ntResponse[16:]
	return c.user + "::" + c.domain + ":" +
		hex.EncodeToString(serverChallenge[:8]) + ":" +
		hex.EncodeToString(ntProof) + ":" + hex.EncodeToString(blob)
}

// netbios returns the NetBIOS domain name (uppercase first label).
func netbios(domain string) string {
	label := domain
	if i := strings.IndexByte(domain, '.'); i >= 0 {
		label = domain[:i]
	}
	if label == "" {
		label = "WORKGROUP"
	}
	return strings.ToUpper(label)
}

func randomChallenge() []byte {
	b := make([]byte, 8)
	rand.Read(b)
	return b
}
