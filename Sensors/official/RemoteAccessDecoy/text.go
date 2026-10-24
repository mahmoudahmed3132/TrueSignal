package main

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/truesignal/sdk-go/decoy"
)

// Telnet and FTP are line protocols that carry credentials in clear, so the
// decoy gets the password itself; it goes through the capture policy.

const maxLine = 512

// telnet option bytes
const (
	iac  = 255
	will = 251
	wont = 252
	do   = 253
	dont = 254
	sb   = 250
	se   = 240
	echo = 1
	sga  = 3
)

// readTelnetLine reads one line, discarding telnet negotiation (IAC
// sequences, including subnegotiation) and handling CR, CR LF and CR NUL.
func readTelnetLine(r *bufio.Reader) (string, error) {
	var line []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		switch {
		case b == iac:
			cmd, err := r.ReadByte()
			if err != nil {
				return "", err
			}
			switch cmd {
			case will, wont, do, dont:
				if _, err := r.ReadByte(); err != nil {
					return "", err
				}
			case sb:
				for { // skip to IAC SE
					c, err := r.ReadByte()
					if err != nil {
						return "", err
					}
					if c == iac {
						if n, _ := r.ReadByte(); n == se {
							break
						}
					}
				}
			case iac:
				line = append(line, iac)
			}
		case b == '\r' || b == '\n':
			if b == '\r' {
				if next, err := r.Peek(1); err == nil && (next[0] == '\n' || next[0] == 0) {
					r.ReadByte()
				}
			}
			return string(line), nil
		case b == 0x7f || b == 0x08: // DEL / backspace
			if len(line) > 0 {
				line = line[:len(line)-1]
			}
		default:
			if len(line) < maxLine {
				line = append(line, b)
			}
		}
	}
}

func (h *handler) serveTelnet(conn net.Conn) {
	src := decoy.RemoteIP(conn.RemoteAddr())
	r := bufio.NewReader(conn)
	// The server echoes (so the password prompt can suppress echo) and
	// suppresses go-ahead, like a stock Linux telnetd.
	conn.Write([]byte{iac, will, echo, iac, will, sga, iac, do, 31 /* NAWS */})
	fmt.Fprintf(conn, "%s\r\n", h.persona.os)
	for i := 0; i < 3; i++ {
		fmt.Fprintf(conn, "%s login: ", h.persona.hostname)
		user, err := readTelnetLine(r)
		if err != nil {
			return
		}
		conn.Write([]byte("Password: "))
		pw, err := readTelnetLine(r)
		if err != nil {
			return
		}
		h.reportLogin(src, user, "password", &pw, nil)
		time.Sleep(2 * time.Second) // the PAM failure delay a real host imposes
		conn.Write([]byte("\r\nLogin incorrect\r\n"))
	}
}

func (h *handler) serveFTP(conn net.Conn) {
	src := decoy.RemoteIP(conn.RemoteAddr())
	r := bufio.NewReaderSize(conn, maxLine)
	reply := func(s string) { conn.Write([]byte(s + "\r\n")) }
	reply("220 (vsFTPd 3.0.5)")
	user := ""
	for i := 0; i < 20; i++ {
		// ReadSlice is bounded by the reader's buffer (maxLine): an over-long
		// command is refused and the connection closed, so a client cannot
		// make the sensor buffer unbounded input.
		line, err := r.ReadSlice('\n')
		if err == bufio.ErrBufferFull {
			reply("500 Command too long.")
			return
		}
		if err != nil && len(line) == 0 {
			return
		}
		raw := strings.TrimRight(string(line), "\r\n")
		cmd, arg, _ := strings.Cut(raw, " ")
		switch strings.ToUpper(cmd) {
		case "USER":
			user = arg
			reply("331 Please specify the password.")
		case "PASS":
			if user == "" {
				reply("503 Login with USER first.")
				continue
			}
			auth := "password"
			if strings.EqualFold(user, "anonymous") || strings.EqualFold(user, "ftp") {
				auth = "anonymous"
			}
			pw := arg
			h.reportLogin(src, user, auth, &pw, nil)
			time.Sleep(time.Second)
			reply("530 Login incorrect.")
			user = ""
		case "QUIT":
			reply("221 Goodbye.")
			return
		case "SYST":
			reply("215 UNIX Type: L8")
		case "FEAT":
			reply("211-Features:\r\n EPRT\r\n EPSV\r\n MDTM\r\n PASV\r\n REST STREAM\r\n SIZE\r\n TVFS\r\n UTF8\r\n211 End")
		case "NOOP":
			reply("200 NOOP ok.")
		default:
			reply("530 Please login with USER and PASS.")
		}
		if err != nil {
			return
		}
	}
}
