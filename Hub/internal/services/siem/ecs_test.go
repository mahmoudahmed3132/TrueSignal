package siem

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/truesignal/hub/internal/models"
)

func ldapLoginEvent() models.Event {
	return models.Event{
		ID:           42,
		NodeID:       "node-0a1b2c3d",
		SensorID:     "ts-sensor-identity-decoy",
		Timestamp:    "2026-10-24T08:00:00Z",
		EventTrigger: "ldap_login",
		Severity:     "critical",
		Source:       "10.20.30.40",
		Target:       "LDAP:389 (DC01)",
		Details:      json.RawMessage(`{"protocol":"ldap","dst_port":389,"username":"CORP\\alice","workstation":"WS01","auth":"sicily_ntlm","netntlmv2":"alice::CORP:00:11:22"}`),
	}
}

// get walks a decoded JSON document by dotted path.
func get(doc map[string]any, path string) any {
	var cur any = doc
	for _, p := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[p]
	}
	return cur
}

// roundTrip marshals and decodes a document the way a receiver sees it.
func roundTrip(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestECSEventMapping(t *testing.T) {
	svc := NewService(nil)
	doc := roundTrip(t, svc.ecsEvent(ldapLoginEvent()))

	want := map[string]any{
		"@timestamp":          "2026-10-24T08:00:00Z",
		"ecs.version":         ecsVersion,
		"event.kind":          "alert",
		"event.action":        "ldap_login",
		"event.severity":      float64(99),
		"event.outcome":       "failure",
		"event.dataset":       "truesignal.alert",
		"event.id":            "42",
		"source.ip":           "10.20.30.40",
		"destination.port":    float64(389),
		"user.name":           "alice",
		"user.domain":         "CORP",
		"observer.type":       "honeypot",
		"host.id":             "node-0a1b2c3d",
		"truesignal.trigger":  "ldap_login",
		"truesignal.severity": "critical",
	}
	for path, v := range want {
		if got := get(doc, path); got != v {
			t.Errorf("%s = %#v, want %#v", path, got, v)
		}
	}
	cats, _ := get(doc, "event.category").([]any)
	if len(cats) != 2 || cats[0] != "intrusion_detection" || cats[1] != "authentication" {
		t.Errorf("event.category = %v", cats)
	}
	// Captured secrets stay under truesignal.details, never in ECS user.*.
	if get(doc, "truesignal.details.netntlmv2") == nil {
		t.Error("details not preserved under truesignal.details")
	}
	if u, _ := json.Marshal(doc["user"]); strings.Contains(string(u), "alice::") {
		t.Errorf("secret leaked into user: %s", u)
	}
}

func TestECSNonIPSourceAndWhitelist(t *testing.T) {
	svc := NewService(nil)
	ev := ldapLoginEvent()
	ev.Source = "Wizard Firedrill"
	ev.Whitelisted = true
	doc := roundTrip(t, svc.ecsEvent(ev))
	if get(doc, "source.ip") != nil || get(doc, "source.address") != "Wizard Firedrill" {
		t.Errorf("source = %v", doc["source"])
	}
	if get(doc, "event.kind") != "event" {
		t.Errorf("whitelisted event.kind = %v, want event", get(doc, "event.kind"))
	}
}

func TestECSKnownScanner(t *testing.T) {
	svc := NewService(nil)
	ev := ldapLoginEvent()
	ev.KnownScanner = true
	doc := roundTrip(t, svc.ecsEvent(ev))
	if get(doc, "event.kind") != "event" || get(doc, "truesignal.known_scanner") != true {
		t.Errorf("kind = %v, known_scanner = %v", get(doc, "event.kind"), get(doc, "truesignal.known_scanner"))
	}
	tags, _ := json.Marshal(doc["tags"])
	if !strings.Contains(string(tags), "known_scanner") {
		t.Errorf("tags = %s", tags)
	}
}

func TestECSLivenessAndFileMapping(t *testing.T) {
	svc := NewService(nil)
	live := roundTrip(t, svc.ecsEvent(models.Event{EventTrigger: "sensor_heartbeat_lost", Severity: "high", Source: "truesignal-hub"}))
	if get(live, "event.kind") != "event" || get(live, "event.category").([]any)[0] != "host" {
		t.Errorf("liveness = %v", live["event"])
	}
	file := roundTrip(t, svc.ecsEvent(models.Event{EventTrigger: "decoy_file_accessed", Severity: "high",
		Details: json.RawMessage(`{"path":"/srv/finance/payroll.xlsx"}`)}))
	if get(file, "file.path") != "/srv/finance/payroll.xlsx" || get(file, "url") != nil {
		t.Errorf("file mapping = %v / %v", file["file"], file["url"])
	}
}

func TestECSHoneytokenUsed(t *testing.T) {
	svc := NewService(nil)
	doc := roundTrip(t, svc.ecsEvent(models.Event{EventTrigger: "honeytoken_used", Severity: "critical", Source: "10.1.2.3",
		Details: json.RawMessage(`{"honeytoken_username":"svc_backup7f3a","planted_node_id":"node-a"}`)}))
	cats, _ := get(doc, "event.category").([]any)
	if get(doc, "user.name") != "svc_backup7f3a" || len(cats) != 2 || cats[1] != "authentication" || get(doc, "event.outcome") != "failure" {
		t.Fatalf("honeytoken_used ECS = %v", doc)
	}
}

func TestECSAuditMapping(t *testing.T) {
	svc := NewService(nil)
	doc := roundTrip(t, svc.ecsAudit(AuditRecord{Action: "POST /login", Path: "/login", Status: 401, ActorIP: "10.1.1.1"}))
	if get(doc, "event.dataset") != "truesignal.audit" || get(doc, "event.outcome") != "failure" ||
		get(doc, "event.category").([]any)[0] != "authentication" || get(doc, "source.ip") != "10.1.1.1" {
		t.Errorf("audit = %v", doc)
	}
}

func TestECSOverTCPIsOneJSONLine(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	svc := NewService(nil)
	svc.UpdateConfig(Output{Address: ln.Addr().String(), Protocol: "tcp", Format: "ECS"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.StartWorker(ctx)

	ev := ldapLoginEvent()
	ev.Details = json.RawMessage(`{"attempted_username":"x\ny"}`)
	svc.QueueEvent(ev)

	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(line), &doc); err != nil {
		t.Fatalf("not one JSON line: %v (%q)", err, line)
	}
	if get(doc, "user.name") != "x\ny" || get(doc, "event.action") != "ldap_login" {
		t.Fatalf("doc = %v", doc)
	}
}

// capture records requests received by a test HTTPS server.
type capture struct {
	mu   sync.Mutex
	reqs []*http.Request
	body []string
}

func (c *capture) add(r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	c.mu.Lock()
	c.reqs = append(c.reqs, r)
	c.body = append(c.body, string(b))
	c.mu.Unlock()
}

func httpsService(ts *httptest.Server) *Service {
	svc := NewService(nil)
	client := ts.Client()
	client.CheckRedirect = svc.httpClient.CheckRedirect
	svc.httpClient = client
	return svc
}

func TestElasticBulkOutput(t *testing.T) {
	var got capture
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.add(r)
		w.Write([]byte(`{"errors":false,"items":[{"create":{"status":201}}]}`))
	}))
	defer ts.Close()

	svc := httpsService(ts)
	out := Output{Address: ts.URL + "/logs-truesignal-default", Protocol: ProtocolElastic, Token: "ZW5jb2RlZA=="}
	svc.UpdateConfig(out)
	svc.processHTTPWithRetry(context.Background(), svc.output(), queueItem{event: ptr(ldapLoginEvent())})

	if len(got.reqs) != 1 {
		t.Fatalf("requests = %d", len(got.reqs))
	}
	r := got.reqs[0]
	if r.URL.Path != "/logs-truesignal-default/_bulk" || r.Header.Get("Authorization") != "ApiKey ZW5jb2RlZA==" ||
		r.Header.Get("Content-Type") != "application/x-ndjson" {
		t.Fatalf("request = %s %s auth=%q ct=%q", r.Method, r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Type"))
	}
	lines := strings.Split(strings.TrimRight(got.body[0], "\n"), "\n")
	if len(lines) != 2 || lines[0] != `{"create":{}}` {
		t.Fatalf("bulk body = %q", got.body[0])
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &doc); err != nil || get(doc, "event.action") != "ldap_login" {
		t.Fatalf("bulk doc = %q (%v)", lines[1], err)
	}
}

func TestLogScaleHECOutput(t *testing.T) {
	var got capture
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.add(r)
		w.Write([]byte(`{"text":"Success","code":0}`))
	}))
	defer ts.Close()

	svc := httpsService(ts)
	out := Output{Address: ts.URL + "/api/v1/ingest/hec", Protocol: ProtocolLogScale, Token: "ingest-token"}
	if fact := svc.sendHTTP(context.Background(), out.Protocol, out.Address, out.Token, svc.ecsEvent(ldapLoginEvent())); fact.IsError {
		t.Fatal(fact.Err)
	}
	r := got.reqs[0]
	if r.URL.Path != "/api/v1/ingest/hec" || r.Header.Get("Authorization") != "Bearer ingest-token" {
		t.Fatalf("request = %s auth=%q", r.URL.Path, r.Header.Get("Authorization"))
	}
	var hec map[string]any
	if err := json.Unmarshal([]byte(got.body[0]), &hec); err != nil {
		t.Fatal(err)
	}
	if hec["sourcetype"] != "truesignal" || hec["host"] != "node-0a1b2c3d" || get(hec, "event.event.action") != "ldap_login" {
		t.Fatalf("hec = %v", hec)
	}
	if ts, _ := hec["time"].(float64); int64(ts) != time.Date(2026, 10, 24, 8, 0, 0, 0, time.UTC).Unix() {
		t.Fatalf("hec time = %v", hec["time"])
	}
}

func TestHTTPOutcomeClassification(t *testing.T) {
	cases := []struct {
		name           string
		status         int
		body           string
		err, transient bool
	}{
		{"ok", 200, `{}`, false, false},
		{"unavailable", 503, ``, true, true},
		{"throttled", 429, ``, true, true},
		{"bad token", 401, `{"error":"unauthorized"}`, true, false},
		{"mapping error", 200, `{"errors":true,"items":[{"create":{"status":400,"error":{"type":"document_parsing_exception"}}}]}`, true, false},
		{"bulk item throttled", 200, `{"errors":true,"items":[{"create":{"status":429}}]}`, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				w.Write([]byte(tc.body))
			}))
			defer ts.Close()
			svc := httpsService(ts)
			fact := svc.sendHTTP(context.Background(), ProtocolElastic, ts.URL+"/logs-x", "k", svc.ecsEvent(ldapLoginEvent()))
			if fact.IsError != tc.err || fact.IsTransient != tc.transient {
				t.Fatalf("fact = %+v", fact)
			}
		})
	}
}

func TestHTTPOutputDoesNotFollowRedirects(t *testing.T) {
	var leaked bool
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("Authorization") != ""
	}))
	defer other.Close()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer ts.Close()

	svc := httpsService(ts)
	fact := svc.sendHTTP(context.Background(), ProtocolLogScale, ts.URL+"/hec", "secret", svc.ecsEvent(ldapLoginEvent()))
	if !fact.IsError || fact.IsTransient {
		t.Fatalf("redirect should be a terminal error, got %+v", fact)
	}
	if leaked {
		t.Fatal("token followed the redirect")
	}
}

func ptr[T any](v T) *T { return &v }

func TestHoneytokenRecordsNeverCarrySecret(t *testing.T) {
	svc := NewService(nil)
	h := models.Honeytoken{ID: "ht_1a2b3c4d", Username: "svc_backup7f3a", Secret: "Qx7pLm2Rv9TzKw!", NodeID: "node-a", SensorID: "ts-sensor-file-canary", CreatedAt: "2026-10-24T00:00:00Z"}

	line := svc.formatHoneytoken(h)
	if !strings.HasPrefix(line, "<134>1 ") || !strings.Contains(line, " - HONEYTOKEN [truesignal-honeytoken@32473 honeytoken_id=\"ht_1a2b3c4d\" username=\"svc_backup7f3a\"") {
		t.Fatalf("syslog = %q", line)
	}
	doc := roundTrip(t, svc.ecsHoneytoken(h))
	if get(doc, "event.dataset") != "truesignal.honeytoken" || get(doc, "event.kind") != "enrichment" ||
		get(doc, "user.name") != "svc_backup7f3a" || get(doc, "threat.indicator.type") != "user-account" ||
		get(doc, "truesignal.honeytoken.planted_node_id") != "node-a" {
		t.Fatalf("ecs = %v", doc)
	}
	ecsJSON, _ := json.Marshal(doc)
	for _, out := range []string{line, string(ecsJSON)} {
		if strings.Contains(out, h.Secret) {
			t.Fatalf("secret leaked: %s", out)
		}
	}
	// QueueHoneytoken strips the secret before it reaches the queue.
	svc.QueueHoneytoken(h)
	if item := <-svc.eventQueue; item.honeytoken == nil || item.honeytoken.Secret != "" {
		t.Fatalf("queued record = %+v", item.honeytoken)
	}
}
