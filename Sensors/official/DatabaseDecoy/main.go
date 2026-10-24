// DatabaseDecoy emulates MySQL, PostgreSQL and Microsoft SQL Server up to the
// login step, so an attacker who tries a database (often with credentials
// lifted from a config file) is detected and the account they used recorded.
// Logins are always refused. Ported in concept from the Trapster Community
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
	"syscall"
	"time"

	sdk "github.com/truesignal/sdk-go"
	"github.com/truesignal/sdk-go/decoy"
)

// persona is the identity the database servers claim.
type persona struct {
	hostname string
}

// handler serves one connection for one protocol.
type handler struct {
	ts      decoy.Reporter
	proto   string
	port    int
	cap     decoy.Capture
	persona persona
	limit   *decoy.Limiter
}

const (
	connTimeout = 30 * time.Second
	// Login events per source per minute before a spray is summarised.
	loginsPerMinute = 20
	maxPacket       = 64 << 10 // largest login packet accepted
)

func main() {
	ts, err := sdk.NewSensor()
	if err != nil {
		log.Fatalf("[!] FATAL: %v", err)
	}
	ts.SetTestPayload("postgres_login", "Wizard Firedrill", "POSTGRES:5432 (DB01)", sdk.EventDetails{
		{Key: "test_message", Value: "Wizard triggered a synthetic event firedrill."},
		{Key: "protocol", Value: "postgres"},
		{Key: "username", Value: "postgres"},
		{Key: "database", Value: "app"},
		{Key: "password_hmac", Value: "firedrill"},
	})
	if ts.TestMode {
		if ts.RunTestMode() {
			os.Exit(0)
		}
		os.Exit(1)
	}

	per := persona{hostname: decoy.Getenv("TS_PERSONA_HOSTNAME", "DB01")}
	capture := decoy.NewCapture()
	services, err := decoy.ParseServices(decoy.Getenv("TS_SERVICES", "mysql:3306,postgres:5432,mssql:1433"), "mysql", "postgres", "mssql")
	if err != nil {
		log.Fatalf("[!] FATAL: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	limit := decoy.NewLimiter(loginsPerMinute, time.Minute)
	var lc net.ListenConfig
	for _, s := range services {
		ln, err := lc.Listen(ctx, "tcp", fmt.Sprintf("0.0.0.0:%d", s.Port))
		if err != nil {
			log.Fatalf("[!] FATAL: bind %s/%d: %v", s.Proto, s.Port, err)
		}
		h := &handler{ts: ts, proto: s.Proto, port: s.Port, cap: capture, persona: per, limit: limit}
		log.Printf("[+] DatabaseDecoy serving %s on port %d as %s", s.Proto, s.Port, per.hostname)
		go decoy.Accept(ctx, ln, h.serve)
	}

	if err := ts.Start(); err != nil {
		log.Fatalf("[!] FATAL: %v", err)
	}
	defer ts.Stop()
	<-ctx.Done()
	log.Println("[*] DatabaseDecoy shutting down.")
}

func (h *handler) serve(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(connTimeout))
	h.ts.ReportEventSeverity("low", h.proto+"_connection", decoy.RemoteIP(conn.RemoteAddr()), h.target(),
		sdk.EventDetails{{Key: "protocol", Value: h.proto}, {Key: "dst_port", Value: h.port}})
	switch h.proto {
	case "mysql":
		h.serveMySQL(conn)
	case "postgres":
		h.servePostgres(conn)
	case "mssql":
		h.serveMSSQL(conn)
	}
}

func (h *handler) target() string {
	return fmt.Sprintf("%s:%d (%s)", map[string]string{"mysql": "MYSQL", "postgres": "POSTGRES", "mssql": "MSSQL"}[h.proto], h.port, h.persona.hostname)
}

// login is what a client revealed while logging in.
type login struct {
	username    string
	database    string
	application string
	clientHost  string
	auth        string
	password    *string // cleartext when the protocol yields it
	extra       sdk.EventDetails
}

// report records a login attempt as a critical <proto>_login. The password,
// when the protocol gives it in clear, goes through the capture policy. Past
// loginsPerMinute from one source, attempts are counted instead and the count
// rides on the next reported one.
func (h *handler) report(conn net.Conn, l login) {
	src := decoy.RemoteIP(conn.RemoteAddr())
	ok, suppressed := h.limit.Allow(src)
	if !ok {
		return
	}
	d := sdk.EventDetails{
		{Key: "protocol", Value: h.proto},
		{Key: "dst_port", Value: h.port},
		{Key: "username", Value: decoy.Sanitize(l.username, 256)},
	}
	for _, kv := range []struct{ k, v string }{
		{"database", l.database}, {"client_app", l.application}, {"client_host", l.clientHost}, {"auth", l.auth},
	} {
		if kv.v != "" {
			d = append(d, sdk.EventDetail{Key: kv.k, Value: decoy.Sanitize(kv.v, 256)})
		}
	}
	if l.password != nil {
		d = append(d, h.cap.Password(*l.password)...)
	}
	d = append(d, l.extra...)
	if suppressed > 0 {
		d = append(d, sdk.EventDetail{Key: "suppressed_since_last", Value: suppressed})
	}
	h.ts.ReportEventSeverity("critical", h.proto+"_login", src, h.target(), d)
}

func readFull(conn net.Conn, n int) ([]byte, error) {
	buf := make([]byte, n)
	got := 0
	for got < n {
		k, err := conn.Read(buf[got:])
		got += k
		if err != nil {
			return nil, err
		}
	}
	return buf, nil
}
