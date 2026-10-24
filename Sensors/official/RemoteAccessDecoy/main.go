// RemoteAccessDecoy emulates SSH, Telnet and FTP logins so an attacker who
// tries to log in (password spraying, credential reuse, default-credential
// sweeps) is detected and the account and password they used are recorded.
// No session is ever granted. Ported in concept from the Trapster Community
// honeypot (0xBallpoint, AGPLv3+); the Go implementation and capture policy
// are TrueSignal's.
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	sdk "github.com/truesignal/sdk-go"
	"github.com/truesignal/sdk-go/decoy"
)

type persona struct {
	hostname string
	os       string // banner flavour, e.g. "Ubuntu 22.04.4 LTS"
}

type handler struct {
	ts      decoy.Reporter
	proto   string
	port    int
	cap     decoy.Capture
	persona persona
	limit   *decoy.Limiter
	// connLimit bounds connection-only events separately, so a connect flood
	// cannot fill the SDK queue nor use up the login budget.
	connLimit *decoy.Limiter
	ssh       *sshServer
}

const (
	connTimeout     = 60 * time.Second
	loginsPerMinute = 20
	maxAttempts     = 6 // per connection, like sshd MaxAuthTries
)

func main() {
	ts, err := sdk.NewSensor()
	if err != nil {
		log.Fatalf("[!] FATAL: %v", err)
	}
	ts.SetTestPayload("ssh_login", "Wizard Firedrill", "SSH:22 (srv01)", sdk.EventDetails{
		{Key: "test_message", Value: "Wizard triggered a synthetic event firedrill."},
		{Key: "protocol", Value: "ssh"},
		{Key: "username", Value: "root"},
		{Key: "auth", Value: "password"},
		{Key: "password_hmac", Value: "firedrill"},
	})
	if ts.TestMode {
		if ts.RunTestMode() {
			os.Exit(0)
		}
		os.Exit(1)
	}

	per := persona{
		hostname: decoy.Getenv("TS_PERSONA_HOSTNAME", "srv01"),
		os:       decoy.Getenv("TS_PERSONA_OS", "Ubuntu 22.04.4 LTS"),
	}
	capture := decoy.NewCapture()
	services, err := decoy.ParseServices(decoy.Getenv("TS_SERVICES", "ssh:2222,telnet:23,ftp:21"), "ssh", "telnet", "ftp")
	if err != nil {
		log.Fatalf("[!] FATAL: %v", err)
	}

	var sshSrv *sshServer
	for _, s := range services {
		if s.Proto == "ssh" {
			// Derived from the node key: stable across restarts (a changing host
			// key is a honeypot tell) without writing to the read-only rootfs.
			sshSrv, err = newSSHServer(os.Getenv("TS_HUB_KEY"), decoy.Getenv("TS_SSH_VERSION", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"))
			if err != nil {
				log.Fatalf("[!] FATAL: ssh host key: %v", err)
			}
			break
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	limit := decoy.NewLimiter(loginsPerMinute, time.Minute)
	connLimit := decoy.NewLimiter(loginsPerMinute, time.Minute)
	var lc net.ListenConfig
	for _, s := range services {
		ln, err := lc.Listen(ctx, "tcp", fmt.Sprintf("0.0.0.0:%d", s.Port))
		if err != nil {
			log.Fatalf("[!] FATAL: bind %s/%d: %v", s.Proto, s.Port, err)
		}
		h := &handler{ts: ts, proto: s.Proto, port: s.Port, cap: capture, persona: per, limit: limit, connLimit: connLimit, ssh: sshSrv}
		log.Printf("[+] RemoteAccessDecoy serving %s on port %d as %s", s.Proto, s.Port, per.hostname)
		go decoy.Accept(ctx, ln, h.serve)
	}

	if err := ts.Start(); err != nil {
		log.Fatalf("[!] FATAL: %v", err)
	}
	defer ts.Stop()
	<-ctx.Done()
	log.Println("[*] RemoteAccessDecoy shutting down.")
}

func (h *handler) serve(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(connTimeout))
	src := decoy.RemoteIP(conn.RemoteAddr())
	if ok, suppressed := h.connLimit.Allow(src); ok {
		d := sdk.EventDetails{{Key: "protocol", Value: h.proto}, {Key: "dst_port", Value: h.port}}
		if suppressed > 0 {
			d = append(d, sdk.EventDetail{Key: "suppressed_since_last", Value: suppressed})
		}
		h.ts.ReportEventSeverity("low", h.proto+"_connection", src, h.target(), d)
	}
	switch h.proto {
	case "ssh":
		h.serveSSH(conn)
	case "telnet":
		h.serveTelnet(conn)
	case "ftp":
		h.serveFTP(conn)
	}
}

func (h *handler) target() string {
	return fmt.Sprintf("%s:%d (%s)", strings.ToUpper(h.proto), h.port, h.persona.hostname)
}

// reportLogin records one login attempt as a critical <proto>_login. password
// is nil when the attempt carried none (e.g. an SSH public key). extra carries
// protocol-specific fields such as the client version.
func (h *handler) reportLogin(src, user, auth string, password *string, extra sdk.EventDetails) {
	ok, suppressed := h.limit.Allow(src)
	if !ok {
		return
	}
	d := sdk.EventDetails{
		{Key: "protocol", Value: h.proto},
		{Key: "dst_port", Value: h.port},
		{Key: "username", Value: decoy.Sanitize(user, 256)},
		{Key: "auth", Value: auth},
	}
	if password != nil {
		d = append(d, h.cap.Password(*password)...)
	}
	d = append(d, extra...)
	if suppressed > 0 {
		d = append(d, sdk.EventDetail{Key: "suppressed_since_last", Value: suppressed})
	}
	h.ts.ReportEventSeverity("critical", h.proto+"_login", src, h.target(), d)
}
