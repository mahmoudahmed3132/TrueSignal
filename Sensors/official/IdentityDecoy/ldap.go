package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	sdk "github.com/truesignal/sdk-go"
)

// Minimal BER/DER reader and writer for the slice of LDAP the honeypot needs:
// read a bind request, read a search request's base object, and write a
// bindResponse / searchResultDone. It is deliberately small — it never has to
// speak the whole protocol, only enough that ldapsearch, BloodHound's LDAP
// collector and password-spray tools get a believable reply and have their
// credentials recorded.

// LDAP/BER tags used here.
const (
	tagInteger    = 0x02
	tagOctetStr   = 0x04
	tagEnumerated = 0x0A
	tagSequence   = 0x30

	appBindRequest      = 0x60 // [APPLICATION 0] constructed
	appBindResponse     = 0x61 // [APPLICATION 1] constructed
	appSearchRequest    = 0x63 // [APPLICATION 3] constructed
	appSearchResultDone = 0x65 // [APPLICATION 5] constructed
	appUnbindRequest    = 0x42 // [APPLICATION 2] primitive

	authSimple     = 0x80 // [0] simple authentication (primitive)
	authSASL       = 0xA3 // [3] SaslCredentials (constructed)
	authSicilyDisc = 0x89 // [9] sicilyPackageDiscovery (MS-ADTS 5.1.1.1.3)
	authSicilyNeg  = 0x8A // [10] sicilyNegotiate: NTLM NEGOTIATE
	authSicilyResp = 0x8B // [11] sicilyResponse: NTLM AUTHENTICATE

	tagServerSaslCreds = 0x87 // bindResponse serverSaslCreds [7]

	resultSuccess            = 0
	resultAuthMethodNotSupp  = 7
	resultInvalidCredentials = 49
	resultSaslBindInProgress = 14

	// AD-style diagnostic for a bad password (data 52e = ERROR_LOGON_FAILURE),
	// so a bind failure reads like a real domain controller.
	adInvalidCreds = "80090308: LdapErr: DSID-0C090447, comment: AcceptSecurityContext error, data 52e, v4563"

	ldapMaxMessage = 1 << 20 // 1 MiB cap on a single LDAP message
)

// berReader walks a BER-encoded buffer.
type berReader struct {
	buf []byte
	pos int
}

func (r *berReader) done() bool { return r.pos >= len(r.buf) }

// readTLV returns the next element's tag and raw value, advancing past it.
func (r *berReader) readTLV() (tag byte, value []byte, ok bool) {
	if r.pos+2 > len(r.buf) {
		return 0, nil, false
	}
	tag = r.buf[r.pos]
	r.pos++
	n := int(r.buf[r.pos])
	r.pos++
	if n&0x80 != 0 { // long-form length
		count := n & 0x7f
		if count == 0 || count > 4 || r.pos+count > len(r.buf) {
			return 0, nil, false
		}
		n = 0
		for i := 0; i < count; i++ {
			n = n<<8 | int(r.buf[r.pos])
			r.pos++
		}
	}
	if n < 0 || n > ldapMaxMessage || r.pos+n > len(r.buf) {
		return 0, nil, false
	}
	value = r.buf[r.pos : r.pos+n]
	r.pos += n
	return tag, value, true
}

// berTLV encodes one tag/value element with DER length.
func berTLV(tag byte, value []byte) []byte {
	out := []byte{tag}
	n := len(value)
	switch {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, value...)
}

func berInt(tag byte, v int) []byte {
	if v == 0 {
		return berTLV(tag, []byte{0})
	}
	var b []byte
	for v > 0 {
		b = append([]byte{byte(v & 0xff)}, b...)
		v >>= 8
	}
	if b[0]&0x80 != 0 { // keep it positive
		b = append([]byte{0}, b...)
	}
	return berTLV(tag, b)
}

// bindResult holds what a bind request revealed.
type bindResult struct {
	name     string // bind DN or user
	password string
	simple   bool // simple-bind credentials were present
	anon     bool // anonymous (empty-password) bind
	authTag  byte // authentication CHOICE tag
	authVal  []byte
}

// parseBind reads a bindRequest body: version INTEGER, name OCTET STRING,
// authentication. Simple credentials are extracted here; other mechanisms
// keep their raw value for handleNTLMBind.
func parseBind(body []byte) (bindResult, bool) {
	r := &berReader{buf: body}
	if _, _, ok := r.readTLV(); !ok { // version
		return bindResult{}, false
	}
	_, name, ok := r.readTLV() // name
	if !ok {
		return bindResult{}, false
	}
	tag, val, ok := r.readTLV() // authentication
	if !ok {
		return bindResult{}, false
	}
	res := bindResult{name: sanitizeUTF8(string(name)), authTag: tag, authVal: val}
	if tag == authSimple {
		res.simple = true
		res.password = string(val)
		res.anon = len(val) == 0
	}
	return res, true
}

// berElementLen returns the total size of the first BER element in buf.
// complete is false while more bytes are needed; ok is false when the header
// is malformed or the element exceeds ldapMaxMessage.
func berElementLen(buf []byte) (total int, complete, ok bool) {
	if len(buf) < 2 {
		return 0, false, true
	}
	n := int(buf[1])
	hdr := 2
	if n&0x80 != 0 {
		count := n & 0x7f
		if count == 0 || count > 4 {
			return 0, false, false
		}
		if len(buf) < 2+count {
			return 0, false, true
		}
		n = 0
		for i := 0; i < count; i++ {
			n = n<<8 | int(buf[2+i])
		}
		hdr += count
	}
	if n < 0 || n > ldapMaxMessage {
		return 0, false, false
	}
	total = hdr + n
	return total, len(buf) >= total, true
}

// ldapHandler serves one LDAP (or LDAPS) connection.
type ldapHandler struct {
	ts      reporter
	proto   string // "ldap" | "ldaps"
	port    int
	cap     credcapture
	persona persona

	ntlmMode  string // TS_CAPTURE_NTLM: identity | hash | off
	challenge []byte // server challenge of the NTLM exchange in progress
	spnego    bool   // the SASL exchange is SPNEGO-framed
}

func (h *ldapHandler) serve(conn net.Conn) {
	defer conn.Close()
	srcIP := remoteIP(conn)

	h.ts.ReportEventSeverity("low", h.proto+"_connection", srcIP, h.target(),
		sdk.EventDetails{{Key: "protocol", Value: h.proto}, {Key: "dst_port", Value: h.port}})

	buf := make([]byte, 8192)
	var pending []byte
	deadline := time.Now().Add(60 * time.Second)
	for {
		conn.SetReadDeadline(deadline)
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			return
		}
		// A message (an NTLM AUTHENTICATE in particular) can span reads, so
		// buffer until each LDAPMessage is complete.
		pending = append(pending, buf[:n]...)
		for len(pending) > 0 {
			total, complete, ok := berElementLen(pending)
			if !ok {
				return
			}
			if !complete {
				break
			}
			r := &berReader{buf: pending[:total]}
			tag, body, ok := r.readTLV() // LDAPMessage SEQUENCE
			if !ok || tag != tagSequence {
				return
			}
			if !h.handleMessage(conn, body) {
				return
			}
			pending = pending[total:]
		}
	}
}

// handleMessage processes one LDAPMessage and writes a reply. It returns false
// when the connection should close.
func (h *ldapHandler) handleMessage(conn net.Conn, msg []byte) bool {
	r := &berReader{buf: msg}
	_, idBytes, ok := r.readTLV() // messageID INTEGER
	if !ok {
		return false
	}
	opTag, opBody, ok := r.readTLV() // protocolOp
	if !ok {
		return false
	}
	msgID := berTLV(tagInteger, idBytes)

	switch opTag {
	case appBindRequest:
		return h.handleBind(conn, msgID, opBody)
	case appSearchRequest:
		h.handleSearch(conn, msgID, opBody)
		return true
	case appUnbindRequest:
		return false
	default:
		// Unknown op: stay connected but say nothing, like a server that
		// ignores operations it will not service.
		return true
	}
}

func (h *ldapHandler) handleBind(conn net.Conn, msgID, body []byte) bool {
	res, ok := parseBind(body)
	if !ok {
		return false
	}
	switch res.authTag {
	case authSicilyDisc, authSicilyNeg, authSicilyResp, authSASL:
		return h.handleNTLMBind(conn, msgID, res)
	}

	var code int
	var diag string
	if res.anon || !res.simple {
		// Anonymous or a mechanism we don't capture: accept, reveal nothing.
		code = resultSuccess
	} else {
		code = resultInvalidCredentials
		diag = adInvalidCreds
		details := sdk.EventDetails{
			{Key: "protocol", Value: h.proto},
			{Key: "dst_port", Value: h.port},
			{Key: "bind_dn", Value: res.name},
			{Key: "auth", Value: "simple"},
		}
		details = append(details, h.cap.password(res.password)...)
		h.ts.ReportEventSeverity("critical", h.proto+"_login", remoteIP(conn), h.target(), details)
	}
	if res.anon && res.name != "" {
		h.ts.ReportEventSeverity("medium", h.proto+"_query", remoteIP(conn), h.target(),
			sdk.EventDetails{{Key: "protocol", Value: h.proto}, {Key: "anonymous_bind_dn", Value: res.name}})
	}

	h.writeBindResponse(conn, msgID, code, nil, diag, nil)
	return true
}

// writeBindResponse sends a bindResponse. matchedDN carries the Sicily
// package list or NTLM challenge; saslCreds, when non-nil, is serverSaslCreds.
func (h *ldapHandler) writeBindResponse(conn net.Conn, msgID []byte, code int, matchedDN []byte, diag string, saslCreds []byte) {
	fields := concat(
		berInt(tagEnumerated, code),
		berTLV(tagOctetStr, matchedDN),
		berTLV(tagOctetStr, []byte(diag)),
	)
	if saslCreds != nil {
		fields = concat(fields, berTLV(tagServerSaslCreds, saslCreds))
	}
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	conn.Write(berTLV(tagSequence, concat(msgID, berTLV(appBindResponse, fields))))
}

func (h *ldapHandler) handleSearch(conn net.Conn, msgID, body []byte) {
	// First element of a searchRequest is baseObject (LDAPDN OCTET STRING).
	r := &berReader{buf: body}
	base := ""
	if _, b, ok := r.readTLV(); ok {
		base = sanitizeUTF8(string(b))
	}
	h.ts.ReportEventSeverity("medium", h.proto+"_query", remoteIP(conn), h.target(),
		sdk.EventDetails{
			{Key: "protocol", Value: h.proto},
			{Key: "dst_port", Value: h.port},
			{Key: "base_dn", Value: base},
		})

	// Reply searchResultDone(success) with no entries: an empty directory that
	// does not error, so a scanner keeps probing instead of giving up.
	done := berTLV(appSearchResultDone, concat(
		berInt(tagEnumerated, resultSuccess),
		berTLV(tagOctetStr, nil),
		berTLV(tagOctetStr, nil),
	))
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	conn.Write(berTLV(tagSequence, concat(msgID, done)))
}

func (h *ldapHandler) target() string {
	return fmt.Sprintf("%s:%d (%s)", strings.ToUpper(h.proto), h.port, h.persona.hostname)
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
