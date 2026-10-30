package event

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/truesignal/hub/internal/geo"
	"github.com/truesignal/hub/internal/models"
	"github.com/truesignal/hub/internal/services/honeytoken"
	"github.com/truesignal/hub/internal/services/siem"
)

// SIEM detection samples (Docs/siem/detection-rules.md).
//
// The corpus in Docs/siem/testdata/detection-samples.ndjson is what the Hub
// really emits: each case goes through ProcessEvent / EmitSystemEvent (source
// lists, beacon resolution, the honeytoken_used raise, asset and GeoIP
// enrichment) and the real SIEM service's ECS stream output, captured over
// TCP. scripts/siem-rules/run-elastic.py replays it into Elasticsearch and runs
// the rules in Docs/siem/elastic/ against it.
//
// The test fails when the emitted documents drift from the corpus, so a
// change to the event shape or the ECS mapping forces the rules to be
// re-checked. Regenerate with:
//
//	TS_UPDATE_SIEM_SAMPLES=1 go test ./internal/services/event -run TestSIEMDetectionSamples
//
// Only @timestamp and event.created are normalised (the Hub stamps them with
// the wall clock); the replay sets @timestamp from each case's offset.

const samplesFile = "../../../../Docs/siem/testdata/detection-samples.ndjson"

// sampleCase is one scenario. OffsetSec places it on the replay timeline
// (seconds before the replay time).
type sampleCase struct {
	Name      string
	OffsetSec int
	Node      string
	Event     *models.Event // sensor-reported event (ProcessEvent)
	System    *systemEvent  // Hub-raised liveness (EmitSystemEvent)
	Audit     *siem.AuditRecord
}

type systemEvent struct {
	sensor, trigger, severity string
	details                   map[string]any
}

const (
	nodeA   = "node-a1b2c3d4"
	nodeB   = "node-e5f6a7b8"
	nodeDMZ = "node-0dd0beac"

	beaconDomain = "beacon.example"
	htUser       = "svc_ledger1a2b"
)

func ev(sensor, trigger, severity, source, target string, details map[string]any) *models.Event {
	raw, _ := json.Marshal(details)
	return &models.Event{SensorID: sensor, EventTrigger: trigger, Severity: severity, Source: source, Target: target, Details: raw}
}

func beaconEv(source string, details map[string]any) *models.Event {
	channel, _ := details["channel"].(string)
	return ev("ts-sensor-token-receiver", "beacon_triggered", "critical", source,
		strings.ToUpper(channel)+" ("+beaconDomain+")", details)
}

func dnsBeacon(token, resolver, clientSubnet string) map[string]any {
	d := map[string]any{"token": token, "channel": "dns", "query_name": token + "." + beaconDomain,
		"query_type": "A", "transport": "udp", "resolver": resolver}
	if clientSubnet != "" {
		d["client_subnet"] = clientSubnet
	}
	return d
}

func saturated(listener, top string) *models.Event {
	return ev("ts-sensor-token-receiver", "receiver_saturated", "medium", top,
		strings.ToUpper(listener)+" listener ("+beaconDomain+")", map[string]any{
			"listener": listener, "refused_per_source": 40, "refused_total_cap": 0, "distinct_sources": 3,
			"top_source_refusals": []map[string]any{{"source": top, "refused": 37}},
		})
}

func login(sensor, proto string, port int, source, user string) *models.Event {
	return ev(sensor, proto+"_login", "critical", source, fmt.Sprintf("%s (port %d)", strings.ToUpper(proto), port),
		map[string]any{"protocol": proto, "dst_port": port, "username": user, "auth": "password", "password_hmac": "hmac-sha256:0f1e2d3c"})
}

func audit(action, path string, status int, ip string) *siem.AuditRecord {
	return &siem.AuditRecord{Time: time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC), Action: action, Path: path, Status: status, ActorIP: ip}
}

func sampleCases() []sampleCase {
	var cs []sampleCase
	add := func(c sampleCase) { cs = append(cs, c) }

	// Beacons (Token Receiver on the DMZ node).
	add(sampleCase{Name: "beacon_dns_client_subnet_eg", OffsetSec: 120, Node: nodeDMZ,
		Event: beaconEv("81.2.69.160", dnsBeacon("tokdns01", "81.2.69.160", "198.51.100.77/24"))})
	add(sampleCase{Name: "beacon_dns_resolver_only_gb", OffsetSec: 115, Node: nodeDMZ,
		Event: beaconEv("81.2.69.160", dnsBeacon("tokdns01", "81.2.69.160", ""))})
	add(sampleCase{Name: "beacon_http_us", OffsetSec: 110, Node: nodeDMZ,
		Event: beaconEv("203.0.113.9", map[string]any{"token": "tokweb01", "channel": "http", "method": "GET",
			"host": beaconDomain, "path": "/tokweb01.gif", "user_agent": "Microsoft Office/16.0"})})
	add(sampleCase{Name: "beacon_dns_private_resolver", OffsetSec: 105, Node: nodeDMZ,
		Event: beaconEv("10.30.0.53", dnsBeacon("tokkube01", "10.30.0.53", ""))})
	add(sampleCase{Name: "beacon_dns_asset_resolver", OffsetSec: 100, Node: nodeDMZ,
		Event: beaconEv("203.0.113.53", dnsBeacon("tokdns01", "203.0.113.53", ""))})
	add(sampleCase{Name: "beacon_known_from_whitelisted", OffsetSec: 95, Node: nodeDMZ,
		Event: beaconEv("10.10.0.5", dnsBeacon("tokdns01", "10.10.0.5", ""))})
	add(sampleCase{Name: "beacon_unknown_token", OffsetSec: 90, Node: nodeDMZ,
		Event: beaconEv("81.2.69.161", dnsBeacon("tokgone01", "81.2.69.161", ""))})
	add(sampleCase{Name: "beacon_unknown_whitelisted", OffsetSec: 85, Node: nodeDMZ,
		Event: beaconEv("10.10.0.5", dnsBeacon("tokgone01", "10.10.0.5", ""))})

	// Receiver saturation: at most one per listener per 5 minutes.
	for i, off := range []int{14 * 60, 9 * 60, 4 * 60} {
		add(sampleCase{Name: fmt.Sprintf("saturated_dns_%d", i+1), OffsetSec: off, Node: nodeDMZ, Event: saturated("dns", "81.2.69.170")})
	}
	for i, off := range []int{13 * 60, 3 * 60} {
		add(sampleCase{Name: fmt.Sprintf("saturated_http_%d", i+1), OffsetSec: off, Node: nodeDMZ, Event: saturated("http", "81.2.69.171")})
	}

	// Logins against decoys.
	add(sampleCase{Name: "ssh_login", OffsetSec: 80, Node: nodeA, Event: login("ts-sensor-remote-access-decoy", "ssh", 22, "10.40.0.9", "root")})
	add(sampleCase{Name: "ssh_login_publickey", OffsetSec: 79, Node: nodeA, Event: ev("ts-sensor-remote-access-decoy", "ssh_login", "critical", "10.40.0.9", "SSH (port 22)",
		map[string]any{"protocol": "ssh", "dst_port": 22, "username": "deploy", "auth": "publickey", "key_type": "ssh-ed25519",
			"key_fingerprint": "SHA256:Q0VSVElGSUNBVEUtTk9ULUEtUkVBTC1LRVktMDAwMDAw", "client_version": "SSH-2.0-OpenSSH_9.6"})})
	add(sampleCase{Name: "rdp_login", OffsetSec: 78, Node: nodeA, Event: ev("ts-sensor-identity-decoy", "rdp_login", "critical", "10.40.0.9", "RDP (port 3389)",
		map[string]any{"protocol": "rdp", "dst_port": 3389, "username": `CORP\admin`, "auth": "ntlm", "workstation": "WS-0001"})})
	add(sampleCase{Name: "mysql_login", OffsetSec: 76, Node: nodeB, Event: login("ts-sensor-database-decoy", "mysql", 3306, "10.40.0.10", "app")})
	add(sampleCase{Name: "web_login_attempt", OffsetSec: 74, Node: nodeB, Event: ev("ts-sensor-web-router-decoy", "web_login_attempt", "critical", "10.40.0.11", "HTTP (port 8080)",
		map[string]any{"username": "admin", "password_hmac": "hmac-sha256:9a8b7c6d", "auth": "form", "skin": "router", "path": "/login", "method": "POST", "user_agent": "Mozilla/5.0", "dst_port": 8080})})
	add(sampleCase{Name: "ldap_login_honeytoken", OffsetSec: 72, Node: nodeA, Event: login("ts-sensor-identity-decoy", "ldap", 389, "10.40.0.12", `CORP\`+htUser)})
	add(sampleCase{Name: "postgres_login_honeytoken_whitelisted", OffsetSec: 70, Node: nodeB, Event: login("ts-sensor-database-decoy", "postgres", 5432, "10.10.0.5", htUser)})
	add(sampleCase{Name: "ssh_login_whitelisted", OffsetSec: 68, Node: nodeA, Event: login("ts-sensor-remote-access-decoy", "ssh", 22, "10.10.0.5", "root")})
	add(sampleCase{Name: "ssh_login_known_scanner", OffsetSec: 66, Node: nodeA, Event: login("ts-sensor-remote-access-decoy", "ssh", 22, "10.10.0.6", "root")})

	// Scan, then touch (sequence by source.ip within 1 h).
	add(sampleCase{Name: "stt_scan", OffsetSec: 40 * 60, Node: nodeB, Event: ev("ts-sensor-network-scan-detector", "network_scan_detected", "high", "10.50.0.7", nodeB,
		map[string]any{"scan_type": "syn", "ports_hit": []int{22, 80, 443, 3389}, "count": 4, "window_sec": 10})})
	add(sampleCase{Name: "stt_touch", OffsetSec: 10 * 60, Node: nodeA, Event: ev("ts-sensor-web-router-decoy", "web_path_probe", "medium", "10.50.0.7", "HTTP (port 8080)",
		map[string]any{"path": "/.env", "method": "GET", "user_agent": "curl/8.5.0", "dst_port": 8080})})
	add(sampleCase{Name: "stt_reverse_touch", OffsetSec: 40 * 60, Node: nodeB, Event: ev("ts-sensor-network-service-decoy", "snmp_query", "medium", "10.50.0.8", "SNMP (port 161)",
		map[string]any{"protocol": "snmp", "dst_port": 161, "community_hmac": "hmac-sha256:11aa", "pdu": "get"})})
	add(sampleCase{Name: "stt_reverse_scan", OffsetSec: 10 * 60, Node: nodeB, Event: ev("ts-sensor-icmp-canary", "icmp_scan_received", "low", "10.50.0.8", nodeB,
		map[string]any{"icmp_type": 8, "icmp_id": 1, "icmp_seq": 1, "packet_size": 64})})
	add(sampleCase{Name: "stt_scan_conn_only", OffsetSec: 30 * 60, Node: nodeB, Event: ev("ts-sensor-icmp-canary", "icmp_scan_received", "low", "10.50.0.9", nodeB,
		map[string]any{"icmp_type": 8, "icmp_id": 2, "icmp_seq": 1, "packet_size": 64})})
	add(sampleCase{Name: "stt_conn_only", OffsetSec: 20 * 60, Node: nodeB, Event: ev("ts-sensor-tcp-tarpit", "tcp_connection", "high", "10.50.0.9", "TCP (port 445)",
		map[string]any{"dst_port": 445, "phase": "connect", "action_taken": "hold"})})
	add(sampleCase{Name: "scanner_scan", OffsetSec: 30 * 60, Node: nodeB, Event: ev("ts-sensor-network-scan-detector", "network_scan_detected", "high", "10.10.0.6", nodeB,
		map[string]any{"scan_type": "syn", "ports_hit": []int{22}, "count": 1, "window_sec": 10})})

	add(sampleCase{Name: "scan_recent", OffsetSec: 100, Node: nodeA, Event: ev("ts-sensor-network-scan-detector", "network_scan_detected", "high", "10.50.0.20", nodeA,
		map[string]any{"scan_type": "syn", "ports_hit": []int{21, 23, 445}, "count": 3, "window_sec": 10})})
	add(sampleCase{Name: "scanner_conn_recent", OffsetSec: 98, Node: nodeA, Event: ev("ts-sensor-tcp-tarpit", "tcp_connection", "high", "10.10.0.6", "TCP (port 23)",
		map[string]any{"dst_port": 23, "phase": "connect", "action_taken": "hold"})})

	// Asset criticality.
	add(sampleCase{Name: "asset_critical_dns_query", OffsetSec: 64, Node: nodeB, Event: ev("ts-sensor-network-service-decoy", "dns_query", "medium", "10.20.4.17", "DNS (port 53)",
		map[string]any{"protocol": "dns", "dst_port": 53, "query_name": "corp.example", "query_type": "AXFR"})})
	add(sampleCase{Name: "asset_medium_snmp_query", OffsetSec: 62, Node: nodeB, Event: ev("ts-sensor-network-service-decoy", "snmp_query", "medium", "10.20.4.30", "SNMP (port 161)",
		map[string]any{"protocol": "snmp", "dst_port": 161, "community_hmac": "hmac-sha256:22bb", "pdu": "get"})})
	add(sampleCase{Name: "file_tampered", OffsetSec: 60, Node: nodeA, Event: ev("ts-sensor-file-canary", "decoy_file_tampered", "critical", "local", "/srv/backup/db.env",
		map[string]any{"path": "/srv/backup/db.env", "action": "modify", "category": "credentials"})})

	// Liveness (Hub-raised).
	add(sampleCase{Name: "hb_lost_dark", OffsetSec: 3 * 3600, Node: nodeA, System: &systemEvent{"ts-sensor-tcp-tarpit", "sensor_heartbeat_lost", "high",
		map[string]any{"reason": "heartbeat_timeout", "timeout_sec": 60, "last_heartbeat": "2026-10-30T00:00:00Z"}}})
	add(sampleCase{Name: "hb_lost_then_recovered", OffsetSec: 3 * 3600, Node: nodeB, System: &systemEvent{"ts-sensor-icmp-canary", "sensor_heartbeat_lost", "high",
		map[string]any{"reason": "heartbeat_timeout", "timeout_sec": 60, "last_heartbeat": "2026-10-30T00:00:00Z"}}})
	add(sampleCase{Name: "hb_recovered", OffsetSec: 150 * 60, Node: nodeB, System: &systemEvent{"ts-sensor-icmp-canary", "sensor_recovered", "info",
		map[string]any{"config_rev": "rev_0a1b2c3d"}}})
	add(sampleCase{Name: "hb_lost_recent", OffsetSec: 120, Node: nodeB, System: &systemEvent{"ts-sensor-database-decoy", "sensor_heartbeat_lost", "high",
		map[string]any{"reason": "heartbeat_timeout", "timeout_sec": 60, "last_heartbeat": "2026-10-30T00:00:00Z"}}})
	add(sampleCase{Name: "sensor_stopped", OffsetSec: 6 * 60, Node: nodeA, System: &systemEvent{"ts-sensor-file-canary", "sensor_stopped", "low",
		map[string]any{"reason": "SIGTERM"}}})
	add(sampleCase{Name: "hb_lost_after_stop", OffsetSec: 60, Node: nodeA, System: &systemEvent{"ts-sensor-file-canary", "sensor_heartbeat_lost", "high",
		map[string]any{"reason": "not_restarted_after_stop", "timeout_sec": 300, "last_heartbeat": "2026-10-30T00:00:00Z"}}})

	// Audit records (actions as Hub/cmd/hub/main.go and api.AuditMiddleware build them).
	add(sampleCase{Name: "audit_mfa_reset", OffsetSec: 58, Audit: audit("MFA RESET (mfa-reset command, 2026-10-30T00:00:00Z)", "cli:mfa-reset", 200, "local")})
	add(sampleCase{Name: "audit_mfa_disable", OffsetSec: 56, Audit: audit("POST /api/v2/auth/mfa/disable", "/api/v2/auth/mfa/disable", 200, "10.60.0.4")})
	add(sampleCase{Name: "audit_mfa_disable_failed", OffsetSec: 55, Audit: audit("POST /api/v2/auth/mfa/disable", "/api/v2/auth/mfa/disable", 401, "10.60.0.4")})
	add(sampleCase{Name: "audit_config_change", OffsetSec: 54, Audit: audit("PATCH /api/v2/config", "/api/v2/config", 200, "10.60.0.4")})
	add(sampleCase{Name: "audit_clear_events", OffsetSec: 52, Audit: audit("DELETE /api/v2/events", "/api/v2/events", 200, "10.60.0.4")})
	add(sampleCase{Name: "audit_silence_sensor", OffsetSec: 51, Audit: audit("PATCH /api/v2/nodes/{nodeId}/sensors/{sensorId}/silence",
		"/api/v2/nodes/"+nodeA+"/sensors/ts-sensor-tcp-tarpit/silence", 200, "10.60.0.4")})
	add(sampleCase{Name: "audit_config_change_denied", OffsetSec: 50, Audit: audit("PATCH /api/v2/config", "/api/v2/config", 403, "10.60.0.4")})
	add(sampleCase{Name: "audit_login_ok", OffsetSec: 49, Audit: audit("POST /login", "/login", 200, "10.60.0.4")})
	for i := 0; i < 6; i++ {
		add(sampleCase{Name: fmt.Sprintf("audit_login_fail_a%d", i+1), OffsetSec: 9*60 - i*50, Audit: audit("POST /login", "/login", 401, "198.51.100.23")})
	}
	for i := 0; i < 3; i++ {
		add(sampleCase{Name: fmt.Sprintf("audit_login_fail_b%d", i+1), OffsetSec: 8*60 - i*50, Audit: audit("POST /login", "/login", 401, "198.51.100.24")})
	}
	return cs
}

// Fakes for the resolvers the Hub wires in production (beacon, honeytoken).

type sampleBeacons struct{}

func (sampleBeacons) Resolve(token string) (*models.Beacon, error) {
	known := map[string]*models.Beacon{
		"tokdns01":  {ID: "bcn-0001", Token: "tokdns01", Type: "dns", Name: "finance share DNS token", Domain: beaconDomain},
		"tokweb01":  {ID: "bcn-0002", Token: "tokweb01", Type: "web_bug", Name: "board pack web bug", Domain: beaconDomain},
		"tokkube01": {ID: "bcn-0003", Token: "tokkube01", Type: "kubeconfig", Name: "ci kubeconfig", Domain: beaconDomain},
	}
	return known[token], nil
}
func (sampleBeacons) RecordUse(string) error { return nil }

type sampleHoneytokens struct{}

func (sampleHoneytokens) Match(e models.Event) ([]honeytoken.Match, error) {
	var d map[string]any
	_ = json.Unmarshal(e.Details, &d)
	u, _ := d["username"].(string)
	if u == htUser || strings.HasSuffix(u, `\`+htUser) {
		return []honeytoken.Match{{Token: models.Honeytoken{ID: "ht-0001", Username: htUser, NodeID: nodeA, SensorID: "ts-sensor-file-canary"}, MatchedOn: "username"}}, nil
	}
	return nil, nil
}
func (sampleHoneytokens) RecordUse(string) error { return nil }

// countingSIEM forwards to the real SIEM service and counts documents, so
// the capture knows how many lines each case produced.
type countingSIEM struct {
	real *siem.Service
	n    int
}

func (c *countingSIEM) QueueEvent(e models.Event) { c.n++; c.real.QueueEvent(e) }

type sampleLine struct {
	Case      string         `json:"case"`
	OffsetSec int            `json:"offset_sec"`
	Doc       map[string]any `json:"doc"`
}

func generateSamples(t *testing.T) []sampleLine {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	real := siem.NewService(nil)
	real.UpdateConfig(siem.Output{Address: ln.Addr().String(), Protocol: "tcp", Format: siem.FormatECS})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	real.StartWorker(ctx)

	// The worker dials on its first record, so accept in the background.
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()
	var conn net.Conn
	var reader *bufio.Reader
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	readDoc := func() map[string]any {
		if conn == nil {
			select {
			case conn = <-accepted:
			case <-time.After(10 * time.Second):
			}
			if conn == nil {
				t.Fatal("SIEM worker never connected")
			}
			reader = bufio.NewReader(conn)
		}
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		line, err := reader.ReadBytes('\n')
		if err != nil {
			t.Fatalf("reading SIEM output: %v", err)
		}
		var doc map[string]any
		if err := json.Unmarshal(line, &doc); err != nil {
			t.Fatalf("SIEM output is not JSON: %v: %s", err, line)
		}
		return doc
	}

	st := &fakeStore{
		registered: true,
		whitelist:  "10.10.0.5",
		scanners:   "10.10.0.6",
		assets: `[{"name":"asset-critical-01","address":"10.20.4.17","criticality":"critical"},` +
			`{"name":"asset-medium-01","address":"10.20.4.30","criticality":"medium"},` +
			`{"name":"resolver-egress-01","address":"203.0.113.53","criticality":"medium"}]`,
	}
	cnt := &countingSIEM{real: real}
	svc := NewService(st, &counter{}, cnt, &notifyRec{})
	svc.SetBeaconResolver(sampleBeacons{})
	svc.SetHoneytokenMatcher(sampleHoneytokens{})
	mmdb, err := os.ReadFile("../../geo/testdata/dbip-city-test.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(t.TempDir(), "dbip-city-lite.mmdb")
	if err := os.WriteFile(dbPath, mmdb, 0o600); err != nil {
		t.Fatal(err)
	}
	g := geo.New(dbPath, false)
	defer g.Close()
	svc.SetGeo(g)

	var out []sampleLine
	for _, c := range sampleCases() {
		before := cnt.n
		switch {
		case c.Event != nil:
			if err := svc.ProcessEvent(c.Event, c.Node); err != nil {
				t.Fatalf("%s: %v", c.Name, err)
			}
		case c.System != nil:
			svc.EmitSystemEvent(c.Node, c.System.sensor, c.System.trigger, c.System.severity, c.System.details)
		case c.Audit != nil:
			real.QueueAudit(*c.Audit)
			cnt.n++
		}
		for i := before; i < cnt.n; i++ {
			doc := readDoc()
			// Wall-clock fields; the replay sets them from offset_sec.
			doc["@timestamp"] = "1970-01-01T00:00:00Z"
			if e, ok := doc["event"].(map[string]any); ok {
				delete(e, "created")
			}
			name := c.Name
			if i > before {
				name = fmt.Sprintf("%s#%d", c.Name, i-before+1)
			}
			out = append(out, sampleLine{Case: name, OffsetSec: c.OffsetSec, Doc: doc})
		}
	}
	return out
}

func TestSIEMDetectionSamples(t *testing.T) {
	got := generateSamples(t)
	var buf bytes.Buffer
	for _, l := range got {
		b, err := json.Marshal(l)
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	if os.Getenv("TS_UPDATE_SIEM_SAMPLES") == "1" {
		if err := os.MkdirAll(filepath.Dir(samplesFile), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(samplesFile, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %d samples to %s", len(got), samplesFile)
	}
	want, err := os.ReadFile(samplesFile)
	if err != nil {
		t.Fatalf("%v (regenerate with TS_UPDATE_SIEM_SAMPLES=1)", err)
	}
	if !bytes.Equal(want, buf.Bytes()) {
		wl, gl := bytes.Split(want, []byte("\n")), bytes.Split(buf.Bytes(), []byte("\n"))
		for i := 0; i < len(wl) && i < len(gl); i++ {
			if !bytes.Equal(wl[i], gl[i]) {
				t.Fatalf("SIEM output changed at sample %d; re-run the rule tests (scripts/siem-rules) and regenerate with TS_UPDATE_SIEM_SAMPLES=1.\nwant: %s\ngot:  %s", i+1, wl[i], gl[i])
			}
		}
		t.Fatalf("SIEM output changed (%d samples, want %d); regenerate with TS_UPDATE_SIEM_SAMPLES=1", len(gl), len(wl))
	}

	// The Hub, not the rules, enforces the list bypass: known beacons and
	// honeytoken_used are never flagged, so "not whitelisted" filters are safe
	// for every rule.
	for _, l := range got {
		ts, ok := l.Doc["truesignal"].(map[string]any)
		if !ok {
			continue // audit record
		}
		trigger := ts["trigger"]
		details, _ := ts["details"].(map[string]any)
		_, known := details["beacon"]
		if (trigger == "honeytoken_used" || (trigger == "beacon_triggered" && known)) && (ts["whitelisted"] == true || ts["known_scanner"] == true) {
			t.Errorf("%s: %s is flagged whitelisted/known_scanner", l.Case, trigger)
		}
	}
}

// ecsFieldRef matches field references in rule queries: ECS and truesignal
// namespaces only, so query keywords and values are not picked up.
var ecsFieldRef = regexp.MustCompile(`\b(?:event|source|destination|truesignal|threat|host|user|url|observer|http|file|user_agent|log)\.[A-Za-z_][\w.]*(?:\[\])?`)

// quotedFieldArg matches string literals LogScale uses as field names
// (in(field="…"), array:contains("…")); other literals are values.
var quotedFieldArg = regexp.MustCompile(`(?:field=|array:contains\()"([^"]*)"`)

var stringLiteral = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)

// fieldRefs returns the field names a query references.
func fieldRefs(query string) []string {
	var refs []string
	for _, m := range quotedFieldArg.FindAllStringSubmatch(query, -1) {
		refs = append(refs, m[1])
	}
	return append(refs, ecsFieldRef.FindAllString(stringLiteral.ReplaceAllString(query, `""`), -1)...)
}

// TestSIEMRuleFieldsExist checks that every field the Elastic rules and the
// LogScale queries reference exists in a document the Hub emits.
func TestSIEMRuleFieldsExist(t *testing.T) {
	want, err := os.ReadFile(samplesFile)
	if err != nil {
		t.Fatal(err)
	}
	present := map[string]bool{}   // dotted paths (Elastic: arrays are transparent)
	flattened := map[string]bool{} // LogScale json-parser names (arrays as name[])
	for _, line := range bytes.Split(bytes.TrimSpace(want), []byte("\n")) {
		var l sampleLine
		if err := json.Unmarshal(line, &l); err != nil {
			t.Fatal(err)
		}
		collectPaths(l.Doc, "", present, flattened)
	}

	elastic, _ := filepath.Glob("../../../../Docs/siem/elastic/truesignal-*.json")
	logscale, _ := filepath.Glob("../../../../Docs/siem/logscale/truesignal-*.logscale")
	if len(elastic) < 2 || len(logscale) < 1 {
		t.Fatalf("rules not found: %d elastic, %d logscale", len(elastic), len(logscale))
	}
	for _, f := range elastic {
		var rule map[string]any
		b, _ := os.ReadFile(f)
		if err := json.Unmarshal(b, &rule); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if rule["rule_id"] == "truesignal-honeytoken-authentication" {
			continue // queries other products' logs, not TrueSignal's
		}
		text := fmt.Sprint(rule["query"])
		if th, ok := rule["threshold"].(map[string]any); ok {
			text += " " + fmt.Sprint(th["field"])
		}
		for _, ref := range fieldRefs(text) {
			if !present[strings.TrimSuffix(ref, "[]")] {
				t.Errorf("%s: field %s is not in any emitted document", filepath.Base(f), ref)
			}
		}
	}
	for _, f := range logscale {
		b, _ := os.ReadFile(f)
		var body []string
		for _, ln := range strings.Split(string(b), "\n") {
			if !strings.HasPrefix(strings.TrimSpace(ln), "//") {
				body = append(body, ln)
			}
		}
		for _, ref := range fieldRefs(strings.Join(body, "\n")) {
			if !flattened[ref] {
				t.Errorf("%s: field %s is not in any emitted document (LogScale json-parser name)", filepath.Base(f), ref)
			}
		}
	}
}

func collectPaths(v any, prefix string, present, flattened map[string]bool) {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			collectPaths(child, p, present, flattened)
		}
	case []any:
		present[prefix] = true
		flattened[prefix+"[]"] = true
		for _, child := range x {
			if m, ok := child.(map[string]any); ok {
				collectPaths(m, prefix, present, map[string]bool{})
			}
		}
	default:
		present[prefix] = true
		flattened[prefix] = true
	}
}

// TestSIEMRulesDocumented checks that every Elastic rule has a LogScale twin
// and a section in Docs/siem/detection-rules.md.
func TestSIEMRulesDocumented(t *testing.T) {
	doc, err := os.ReadFile("../../../../Docs/siem/detection-rules.md")
	if err != nil {
		t.Fatal(err)
	}
	elastic, _ := filepath.Glob("../../../../Docs/siem/elastic/truesignal-*.json")
	for _, f := range elastic {
		id := strings.TrimSuffix(filepath.Base(f), ".json")
		if id == "truesignal-honeytoken-authentication" {
			continue // documented in honeytoken-detection.md
		}
		if _, err := os.Stat("../../../../Docs/siem/logscale/" + id + ".logscale"); err != nil {
			t.Errorf("%s: no LogScale query", id)
		}
		if !bytes.Contains(doc, []byte("### "+id+"\n")) {
			t.Errorf("%s: no section in detection-rules.md", id)
		}
	}
}
