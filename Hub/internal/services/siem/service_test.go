package siem

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/truesignal/hub/internal/models"
)

func TestSyslogForwardingRFC5424(t *testing.T) {
	// Start a local TCP listener to act as the SIEM server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	defer listener.Close()

	address := listener.Addr().String()

	// Initialize the SIEM service
	svc := NewService(nil)
	svc.UpdateConfig(address, "tcp")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	svc.StartWorker(ctx)

	// Create a test event
	eventTime := time.Date(2023, time.August, 7, 15, 4, 5, 0, time.UTC)
	event := models.Event{
		ID:           123,
		NodeID:       "node-01",
		Timestamp:    eventTime.Format(time.RFC3339),
		Severity:     "critical",
		EventTrigger: "File access",
		Source:       "192.168.1.100",
		Target:       "10.0.0.5",
		SensorID:     "sensor-01",
		Details:      json.RawMessage(`{"file": "/etc/shadow"}`),
	}

	// Send the event
	svc.QueueEvent(event)

	// Accept the connection from the service
	conn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Failed to accept connection: %v", err)
	}
	defer conn.Close()

	// Read the forwarded syslog message
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)
	msg, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read from connection: %v", err)
	}

	// Output the received message
	t.Logf("Received syslog message: %s", msg)

	// RFC5424 Regex Check
	// <PRIVAL>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
	rfc5424Regex := `^<(\d+)>([1-9]\d{0,2})\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\[.*?\]|-)(?:\s+(.*))?\n$`
	re := regexp.MustCompile(rfc5424Regex)
	
	if !re.MatchString(msg) {
		t.Errorf("Message does not strictly match RFC5424.\nMessage: %q\nRegex: %s", msg, rfc5424Regex)
	} else {
		matches := re.FindStringSubmatch(msg)
		t.Logf("Matches: PRI=%s, VER=%s, TS=%q, HOST=%s, APP=%s, PROC=%s, MSGID=%s, SD=%s, MSG=%s", 
			matches[1], matches[2], matches[3], matches[4], matches[5], matches[6], matches[7], matches[8], matches[9])
	}
}

func TestFormatSyslog_EscapesAttackerControlledValues(t *testing.T) {
	svc := NewService(nil, Options{PEN: "99999"})
	msg := svc.formatSyslog(models.Event{
		ID:           7,
		NodeID:       "node-01",
		Timestamp:    "2026-01-01T00:00:00Z",
		Severity:     "critical",
		EventTrigger: "web_login_attempt",
		Source:       "10.0.0.9",
		Target:       `x"] [fake@1 k="v`,
		SensorID:     "ts-sensor-web-router-decoy",
		Details:      json.RawMessage("{\"attempted_username\":\"a]\\\"b\\nINJECTED\"}"),
	})

	if strings.Contains(msg, "\n") {
		t.Fatalf("message must be a single line: %q", msg)
	}
	if !strings.Contains(msg, `[truesignal@99999 `) {
		t.Fatalf("SD-ID must carry the configured PEN: %q", msg)
	}
	if !strings.Contains(msg, `target="x\"\] [fake@1 k=\"v"`) {
		t.Fatalf("SD param value not escaped per RFC 5424: %q", msg)
	}
	// The JSON body must parse back to the original details.
	idx := strings.Index(msg, "] {")
	if idx < 0 {
		t.Fatalf("no JSON body: %q", msg)
	}
	var body struct {
		Details map[string]string `json:"details"`
	}
	if err := json.Unmarshal([]byte(msg[idx+2:]), &body); err != nil {
		t.Fatalf("body is not JSON: %v (%q)", err, msg[idx+2:])
	}
	if body.Details["attempted_username"] != "a]\"b\nINJECTED" {
		t.Fatalf("details round-trip failed: %#v", body.Details)
	}
}

func TestFormatAudit(t *testing.T) {
	svc := NewService(nil)
	msg := svc.formatAudit(AuditRecord{Action: "PATCH /api/v2/config", Path: "/api/v2/config", Status: 200, ActorIP: "10.1.1.1"})
	if !strings.HasPrefix(msg, "<133>1 ") || !strings.Contains(msg, " - AUDIT [truesignal-audit@32473 action=\"PATCH /api/v2/config\"") {
		t.Fatalf("unexpected audit format: %q", msg)
	}
}
