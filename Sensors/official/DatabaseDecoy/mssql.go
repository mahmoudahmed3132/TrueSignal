package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"unicode/utf16"

	sdk "github.com/truesignal/sdk-go"
)

// Microsoft SQL Server, TDS 7.x (MS-TDS). The decoy answers PRELOGIN with
// ENCRYPT_NOT_SUP, so clients that do not insist on TLS (sqlcmd/ODBC with
// Encrypt=no, impacket mssqlclient, most attack tools) send LOGIN7 in clear.
// LOGIN7 carries the user name and a password that is only nibble-swapped
// and XORed with 0xA5, so it is recovered and goes through the capture policy.
// The login is refused with error 18456, as SQL Server does.

const (
	tdsPrelogin = 0x12
	tdsLogin7   = 0x10
	tdsReply    = 0x04

	tdsEncryptOff    = 0x00
	tdsEncryptOn     = 0x01
	tdsEncryptNotSup = 0x02
	tdsEncryptReq    = 0x03
)

// readTDSMessage reads one TDS message, reassembling packets until EOM.
func readTDSMessage(conn net.Conn) (typ byte, payload []byte, err error) {
	for {
		hdr, err := readFull(conn, 8)
		if err != nil {
			return 0, nil, err
		}
		n := int(binary.BigEndian.Uint16(hdr[2:4]))
		if n < 8 || len(payload)+n > maxPacket {
			return 0, nil, fmt.Errorf("bad TDS length")
		}
		body, err := readFull(conn, n-8)
		if err != nil {
			return 0, nil, err
		}
		typ = hdr[0]
		payload = append(payload, body...)
		if hdr[1]&0x01 != 0 { // EOM
			return typ, payload, nil
		}
	}
}

func writeTDS(conn net.Conn, typ byte, payload []byte) error {
	hdr := []byte{typ, 0x01, 0, 0, 0, 0, 1, 0}
	binary.BigEndian.PutUint16(hdr[2:], uint16(len(payload)+8))
	_, err := conn.Write(append(hdr, payload...))
	return err
}

// preloginEncryption returns the client's ENCRYPTION option (tests use it to
// check the response).
func preloginEncryption(p []byte) (byte, bool) {
	for i := 0; i+5 <= len(p) && p[i] != 0xff; i += 5 {
		if p[i] != 0x01 {
			continue
		}
		off := int(binary.BigEndian.Uint16(p[i+1:]))
		if l := int(binary.BigEndian.Uint16(p[i+3:])); l >= 1 && off < len(p) {
			return p[off], true
		}
	}
	return 0, false
}

// preloginResponse: VERSION 16.0.1000, ENCRYPTION NOT_SUP, INSTOPT,
// THREADID (empty), in that order and nothing else. Some clients (impacket's
// TDS_PRELOGIN) parse exactly this fixed layout, so an extra option such as
// MARS would make them misread ENCRYPTION.
func preloginResponse() []byte {
	type opt struct {
		token byte
		data  []byte
	}
	opts := []opt{
		{0x00, []byte{16, 0, 0x03, 0xE8, 0, 0}},
		{0x01, []byte{tdsEncryptNotSup}},
		{0x02, []byte{0}},
		{0x03, nil},
	}
	headerLen := len(opts)*5 + 1
	var hdr, data bytes.Buffer
	for _, o := range opts {
		hdr.WriteByte(o.token)
		binary.Write(&hdr, binary.BigEndian, uint16(headerLen+data.Len()))
		binary.Write(&hdr, binary.BigEndian, uint16(len(o.data)))
		data.Write(o.data)
	}
	hdr.WriteByte(0xff)
	return append(hdr.Bytes(), data.Bytes()...)
}

func utf16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, r := range u {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}
	return b
}

func fromUTF16le(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u))
}

// login7Field reads an (offset, length-in-characters) pair at pos.
func login7Field(p []byte, pos int) []byte {
	if pos+4 > len(p) {
		return nil
	}
	off := int(binary.LittleEndian.Uint16(p[pos:]))
	n := int(binary.LittleEndian.Uint16(p[pos+2:])) * 2
	if off+n > len(p) {
		return nil
	}
	return p[off : off+n]
}

// deobfuscateTDSPassword reverses LOGIN7 password encoding: each byte was
// nibble-swapped, then XORed with 0xA5.
func deobfuscateTDSPassword(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		c ^= 0xA5
		out[i] = c<<4 | c>>4
	}
	return out
}

// parseLogin7 extracts identity and password from a LOGIN7 payload.
func parseLogin7(p []byte) (login, bool) {
	if len(p) < 94 {
		return login{}, false
	}
	l := login{
		clientHost:  fromUTF16le(login7Field(p, 36)),
		username:    fromUTF16le(login7Field(p, 40)),
		application: fromUTF16le(login7Field(p, 48)),
		database:    fromUTF16le(login7Field(p, 68)),
		auth:        "sql",
	}
	server := fromUTF16le(login7Field(p, 52))
	if sspiLen := binary.LittleEndian.Uint16(p[80:]); sspiLen > 0 {
		l.auth = "sspi" // Windows integrated auth (NTLM/Kerberos); no SQL password
	} else {
		pw := fromUTF16le(deobfuscateTDSPassword(login7Field(p, 44)))
		l.password = &pw
	}
	if server != "" {
		l.extra = append(l.extra, sdk.EventDetail{Key: "server_name", Value: server})
	}
	return l, true
}

// tdsLoginFailed builds an ERROR token (18456) followed by DONE(error).
func tdsLoginFailed(user, server string) []byte {
	msg := utf16le(fmt.Sprintf("Login failed for user '%s'.", user))
	srv := utf16le(server)
	var tok bytes.Buffer
	binary.Write(&tok, binary.LittleEndian, uint32(18456))
	tok.WriteByte(1)  // state
	tok.WriteByte(14) // class
	binary.Write(&tok, binary.LittleEndian, uint16(len(msg)/2))
	tok.Write(msg)
	tok.WriteByte(byte(len(srv) / 2))
	tok.Write(srv)
	tok.WriteByte(0) // proc name
	binary.Write(&tok, binary.LittleEndian, uint32(1))

	var out bytes.Buffer
	out.WriteByte(0xAA)
	binary.Write(&out, binary.LittleEndian, uint16(tok.Len()))
	out.Write(tok.Bytes())
	out.WriteByte(0xFD) // DONE
	binary.Write(&out, binary.LittleEndian, uint16(0x0002))
	binary.Write(&out, binary.LittleEndian, uint16(0))
	binary.Write(&out, binary.LittleEndian, uint64(0))
	return out.Bytes()
}

func (h *handler) serveMSSQL(conn net.Conn) {
	typ, payload, err := readTDSMessage(conn)
	if err != nil || typ != tdsPrelogin {
		return
	}
	if err := writeTDS(conn, tdsReply, preloginResponse()); err != nil {
		return
	}
	// A client that requires TLS (ENCRYPTION=REQ) disconnects here; its
	// mssql_connection event is all there is to record.
	typ, payload, err = readTDSMessage(conn)
	if err != nil || typ != tdsLogin7 {
		return
	}
	l, ok := parseLogin7(payload)
	if !ok {
		return
	}
	h.report(conn, l)
	writeTDS(conn, tdsReply, tdsLoginFailed(l.username, h.persona.hostname))
}
