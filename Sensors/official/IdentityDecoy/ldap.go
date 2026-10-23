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

	authSimple = 0x80 // [0] simple authentication (primitive)

	resultSuccess            = 0
	resultInvalidCredentials = 49

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
}

// parseBind reads a bindRequest body: version INTEGER, name OCTET STRING,
// authentication. Only simple authentication is extracted here.
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
	res := bindResult{name: sanitizeUTF8(string(name))}
	if tag == authSimple {
		res.simple = true
		res.password = string(val)
		res.anon = len(val) == 0
	}
	return res, true
}

// ldapHandler serves one LDAP (or LDAPS) connection.
type ldapHandler struct {
	ts      reporter
	proto   string // "ldap" | "ldaps"
	port    int
	cap     credcapture
	persona persona
}

func (h *ldapHandler) serve(conn net.Conn) {
	defer conn.Close()
	srcIP := remoteIP(conn)

	h.ts.ReportEventSeverity("low", h.proto+"_connection", srcIP, h.target(),
		sdk.EventDetails{{Key: "protocol", Value: h.proto}, {Key: "dst_port", Value: h.port}})

	buf := make([]byte, 8192)
	deadline := time.Now().Add(60 * time.Second)
	for {
		conn.SetReadDeadline(deadline)
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			return
		}
		r := &berReader{buf: buf[:n]}
		for !r.done() {
			tag, body, ok := r.readTLV() // LDAPMessage SEQUENCE
			if !ok || tag != tagSequence {
				return
			}
			if !h.handleMessage(conn, body) {
				return
			}
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

	resp := berTLV(appBindResponse, concat(
		berInt(tagEnumerated, code),
		berTLV(tagOctetStr, nil),          // matchedDN
		berTLV(tagOctetStr, []byte(diag)), // diagnosticMessage
	))
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	conn.Write(berTLV(tagSequence, concat(msgID, resp)))
	return true
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
