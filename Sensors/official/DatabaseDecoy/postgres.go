package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// PostgreSQL frontend/backend protocol v3. The decoy declines TLS/GSS
// encryption, reads the StartupMessage and then asks for a cleartext password
// (AuthenticationCleartextPassword). libpq and most drivers comply unless the
// client pins the authentication method, so the password is captured, through
// the capture policy, then refused with SQLSTATE 28P01 like a real server.

const (
	pgProtocol3     = 196608
	pgSSLRequest    = 80877103
	pgGSSENCRequest = 80877104
	pgCancelRequest = 80877102
)

func readPgStartup(conn net.Conn) (code uint32, body []byte, err error) {
	hdr, err := readFull(conn, 8)
	if err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint32(hdr[:4]))
	if n < 8 || n > maxPacket {
		return 0, nil, fmt.Errorf("bad startup length")
	}
	body, err = readFull(conn, n-8)
	return binary.BigEndian.Uint32(hdr[4:]), body, err
}

func parsePgParams(body []byte) map[string]string {
	out := map[string]string{}
	parts := bytes.Split(body, []byte{0})
	for i := 0; i+1 < len(parts) && len(out) < 32; i += 2 {
		if len(parts[i]) == 0 {
			break
		}
		out[string(parts[i])] = string(parts[i+1])
	}
	return out
}

func pgMessage(typ byte, body []byte) []byte {
	msg := []byte{typ, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(msg[1:], uint32(len(body)+4))
	return append(msg, body...)
}

func pgError(sqlstate, message string) []byte {
	var b bytes.Buffer
	for _, f := range []struct {
		code byte
		val  string
	}{{'S', "FATAL"}, {'V', "FATAL"}, {'C', sqlstate}, {'M', message}, {'R', "auth_failed"}} {
		b.WriteByte(f.code)
		b.WriteString(f.val)
		b.WriteByte(0)
	}
	b.WriteByte(0)
	return pgMessage('E', b.Bytes())
}

func (h *handler) servePostgres(conn net.Conn) {
	var params map[string]string
	for i := 0; i < 3; i++ { // SSLRequest and GSSENCRequest may precede the startup
		code, body, err := readPgStartup(conn)
		if err != nil {
			return
		}
		switch code {
		case pgSSLRequest, pgGSSENCRequest:
			if _, err := conn.Write([]byte{'N'}); err != nil {
				return
			}
			continue
		case pgProtocol3:
			params = parsePgParams(body)
		default: // CancelRequest, protocol 2, garbage
			return
		}
		break
	}
	if params == nil {
		return
	}
	l := login{
		username:    params["user"],
		database:    params["database"],
		application: params["application_name"],
		auth:        "cleartext",
	}

	// AuthenticationCleartextPassword.
	if _, err := conn.Write(pgMessage('R', []byte{0, 0, 0, 3})); err != nil {
		return
	}
	hdr, err := readFull(conn, 5)
	if err == nil && hdr[0] == 'p' {
		n := int(binary.BigEndian.Uint32(hdr[1:]))
		if n >= 4 && n <= maxPacket {
			if body, err := readFull(conn, n-4); err == nil {
				pw := strings.TrimRight(string(body), "\x00")
				l.password = &pw
			}
		}
	}
	if l.password == nil {
		l.auth = "cleartext_declined"
	}
	h.report(conn, l)
	conn.Write(pgError("28P01", fmt.Sprintf("password authentication failed for user \"%s\"", l.username)))
}
