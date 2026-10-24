package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"

	sdk "github.com/truesignal/sdk-go"
	"github.com/truesignal/sdk-go/decoy"
)

// MySQL client/server protocol, just far enough to read a HandshakeResponse41
// and refuse it. mysql_native_password is a challenge/response, so the
// password itself is never on the wire; the username, default database and the
// client's connection attributes (program name, OS user, ...) are.

const (
	mysqlServerVersion = "8.0.36"

	capLongPassword      = 0x00000001
	capFoundRows         = 0x00000002
	capLongFlag          = 0x00000004
	capConnectWithDB     = 0x00000008
	capProtocol41        = 0x00000200
	capTransactions      = 0x00002000
	capSecureConnection  = 0x00008000
	capMultiStatements   = 0x00010000
	capMultiResults      = 0x00020000
	capPluginAuth        = 0x00080000
	capConnectAttrs      = 0x00100000
	capPluginAuthLenenc  = 0x00200000
	capSSL               = 0x00000800
	mysqlErAccessDenied  = 1045
	mysqlServerCapsLower = capLongPassword | capFoundRows | capLongFlag | capConnectWithDB | capProtocol41 | capTransactions | capSecureConnection
	mysqlServerCapsUpper = (capMultiStatements | capMultiResults | capPluginAuth | capConnectAttrs | capPluginAuthLenenc) >> 16
)

func writeMySQLPacket(conn net.Conn, seq byte, payload []byte) error {
	hdr := []byte{byte(len(payload)), byte(len(payload) >> 8), byte(len(payload) >> 16), seq}
	_, err := conn.Write(append(hdr, payload...))
	return err
}

func readMySQLPacket(conn net.Conn) (seq byte, payload []byte, err error) {
	hdr, err := readFull(conn, 4)
	if err != nil {
		return 0, nil, err
	}
	n := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	if n > maxPacket {
		return 0, nil, fmt.Errorf("packet too large")
	}
	payload, err = readFull(conn, n)
	return hdr[3], payload, err
}

// mysqlGreeting is a protocol-10 initial handshake advertising
// mysql_native_password and no TLS, so clients in the default "preferred" TLS
// mode continue in clear.
func mysqlGreeting() []byte {
	salt := make([]byte, 20)
	rand.Read(salt)
	for i := range salt { // the salt must not contain NUL
		if salt[i] == 0 {
			salt[i] = 'x'
		}
	}
	var b bytes.Buffer
	b.WriteByte(10)
	b.WriteString(mysqlServerVersion)
	b.WriteByte(0)
	connID := make([]byte, 4)
	rand.Read(connID)
	connID[3] = 0
	b.Write(connID)
	b.Write(salt[:8])
	b.WriteByte(0)
	binary.Write(&b, binary.LittleEndian, uint16(mysqlServerCapsLower))
	b.WriteByte(255)                                 // utf8mb4_0900_ai_ci
	binary.Write(&b, binary.LittleEndian, uint16(2)) // SERVER_STATUS_AUTOCOMMIT
	binary.Write(&b, binary.LittleEndian, uint16(mysqlServerCapsUpper))
	b.WriteByte(21)
	b.Write(make([]byte, 10))
	b.Write(salt[8:])
	b.WriteByte(0)
	b.WriteString("mysql_native_password")
	b.WriteByte(0)
	return b.Bytes()
}

// mysqlReader walks a HandshakeResponse41.
type mysqlReader struct {
	b   []byte
	pos int
	bad bool
}

func (r *mysqlReader) take(n int) []byte {
	if r.bad || n < 0 || r.pos+n > len(r.b) {
		r.bad = true
		return nil
	}
	v := r.b[r.pos : r.pos+n]
	r.pos += n
	return v
}

func (r *mysqlReader) cstring() string {
	if r.bad {
		return ""
	}
	i := bytes.IndexByte(r.b[r.pos:], 0)
	if i < 0 {
		r.bad = true
		return ""
	}
	s := string(r.b[r.pos : r.pos+i])
	r.pos += i + 1
	return s
}

func (r *mysqlReader) lenenc() int {
	first := r.take(1)
	if first == nil {
		return 0
	}
	switch first[0] {
	case 0xfc:
		v := r.take(2)
		if v == nil {
			return 0
		}
		return int(binary.LittleEndian.Uint16(v))
	case 0xfd:
		v := r.take(3)
		if v == nil {
			return 0
		}
		return int(v[0]) | int(v[1])<<8 | int(v[2])<<16
	case 0xfe:
		r.bad = true // 8-byte lengths are never legitimate in a login
		return 0
	default:
		return int(first[0])
	}
}

func (r *mysqlReader) lenencString() string {
	return string(r.take(r.lenenc()))
}

// parseMySQLLogin reads a HandshakeResponse41. ok is false for anything else
// (including an SSLRequest, which a client sends only if TLS was offered).
func parseMySQLLogin(p []byte) (l login, ok bool) {
	r := &mysqlReader{b: p}
	capsB := r.take(4)
	r.take(4 + 1 + 23) // max packet, charset, filler
	if r.bad {
		return login{}, false
	}
	caps := binary.LittleEndian.Uint32(capsB)
	if caps&capProtocol41 == 0 {
		return login{}, false
	}
	l.username = r.cstring()
	var authLen int
	switch {
	case caps&capPluginAuthLenenc != 0:
		authLen = r.lenenc()
	case caps&capSecureConnection != 0:
		if b := r.take(1); b != nil {
			authLen = int(b[0])
		}
	default:
		authLen = len(r.b) - r.pos // NUL-terminated legacy form
		if i := bytes.IndexByte(r.b[r.pos:], 0); i >= 0 {
			authLen = i + 1
		}
	}
	authResp := r.take(authLen)
	if r.bad {
		return login{}, false
	}
	if caps&capConnectWithDB != 0 && r.pos < len(r.b) {
		l.database = r.cstring()
	}
	plugin := ""
	if caps&capPluginAuth != 0 && r.pos < len(r.b) {
		plugin = r.cstring()
	}
	attrs := map[string]string{}
	if caps&capConnectAttrs != 0 && r.pos < len(r.b) {
		total := r.lenenc()
		end := r.pos + total
		for !r.bad && r.pos < end && r.pos < len(r.b) && len(attrs) < 32 {
			k := r.lenencString()
			v := r.lenencString()
			if !r.bad {
				attrs[decoy.Sanitize(k, 64)] = v
			}
		}
	}
	l.application = attrs["program_name"]
	l.auth = plugin
	if l.auth == "" {
		l.auth = "mysql_native_password"
	}
	l.extra = sdk.EventDetails{{Key: "password_submitted", Value: len(authResp) > 0}}
	if v := attrs["_os"]; v != "" {
		l.extra = append(l.extra, sdk.EventDetail{Key: "client_os", Value: decoy.Sanitize(v, 64)})
	}
	if v := attrs["_client_name"]; v != "" {
		l.extra = append(l.extra, sdk.EventDetail{Key: "client_library", Value: decoy.Sanitize(v, 64)})
	}
	return l, true
}

func (h *handler) serveMySQL(conn net.Conn) {
	if err := writeMySQLPacket(conn, 0, mysqlGreeting()); err != nil {
		return
	}
	seq, payload, err := readMySQLPacket(conn)
	if err != nil {
		return
	}
	l, ok := parseMySQLLogin(payload)
	if !ok {
		return
	}
	h.report(conn, l)

	using := "NO"
	if submitted, _ := l.extra[0].Value.(bool); submitted {
		using = "YES"
	}
	msg := fmt.Sprintf("Access denied for user '%s'@'%s' (using password: %s)",
		decoy.Sanitize(l.username, 64), decoy.RemoteIP(conn.RemoteAddr()), using)
	var e bytes.Buffer
	e.WriteByte(0xff)
	binary.Write(&e, binary.LittleEndian, uint16(mysqlErAccessDenied))
	e.WriteString("#28000")
	e.WriteString(msg)
	writeMySQLPacket(conn, seq+1, e.Bytes())
}
