package honeytoken_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/truesignal/hub/internal/models"
	"github.com/truesignal/hub/internal/services/event"
	"github.com/truesignal/hub/internal/services/honeytoken"
	"github.com/truesignal/hub/internal/store"
)

func newStore(t *testing.T) *store.SQLiteStore {
	t.Helper()
	st, err := store.NewStore(filepath.Join(t.TempDir(), "ts.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.DB.Close() })
	return st
}

func addSensor(t *testing.T, st *store.SQLiteStore, nodeID string, sensorIDs ...string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := st.DB.Exec(`INSERT INTO nodes (id, alias, api_key, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		nodeID, nodeID+"-alias", "k-"+nodeID, now, now); err != nil {
		t.Fatal(err)
	}
	for _, s := range sensorIDs {
		if _, err := st.DB.Exec(`INSERT INTO node_sensors (node_id, sensor_id, custom_name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
			nodeID, s, s, now, now); err != nil {
			t.Fatal(err)
		}
	}
}

// decoyHMAC reproduces the sensors' credcapture HMAC and key ID.
func decoyHMAC(key, value string) (string, string) {
	return honeytokenHMAC(key, value), honeytokenHMAC(key, "truesignal-key-id")[:8]
}

func event_(trigger string, details map[string]any) models.Event {
	raw, _ := json.Marshal(details)
	return models.Event{EventTrigger: trigger, Severity: "critical", Source: "10.9.8.7", SensorID: "ts-sensor-identity-decoy", Details: raw}
}

func TestTokenForIsStableAndDistinct(t *testing.T) {
	svc := honeytoken.NewService(newStore(t))
	a1, err := svc.TokenFor("node-a", "ts-sensor-file-canary")
	if err != nil {
		t.Fatal(err)
	}
	a2, _ := svc.TokenFor("node-a", "ts-sensor-file-canary")
	b, _ := svc.TokenFor("node-b", "ts-sensor-file-canary")
	if a1.Username != a2.Username || a1.Secret != a2.Secret {
		t.Fatal("token must be stable per sensor")
	}
	if a1.Username == b.Username || a1.Secret == b.Secret {
		t.Fatal("tokens must differ per sensor")
	}
	if !strings.HasPrefix(a1.Username, "svc_") || len(a1.Secret) < 12 || strings.ContainsAny(a1.Secret, `:\`) {
		t.Fatalf("unexpected token shape %q / %q", a1.Username, a1.Secret)
	}
}

func TestMatchUsernameForms(t *testing.T) {
	svc := honeytoken.NewService(newStore(t))
	tok, _ := svc.TokenFor("node-a", "ts-sensor-file-canary")
	up := strings.ToUpper(tok.Username)
	cases := map[string]map[string]any{
		"ntlm DOMAIN\\user": {"username": `CORP\` + up},
		"upn":               {"username": tok.Username + "@corp.local"},
		"mstshash":          {"username": tok.Username},
		"bind dn":           {"bind_dn": "CN=" + tok.Username + ",OU=Service,DC=corp,DC=local"},
		"web login":         {"attempted_username": tok.Username},
	}
	for name, d := range cases {
		m, err := svc.Match(event_("ldap_login", d))
		if err != nil || len(m) != 1 || m[0].Token.ID != tok.ID || m[0].MatchedOn != "username" {
			t.Errorf("%s: matches=%+v err=%v", name, m, err)
		}
	}
	if m, _ := svc.Match(event_("ldap_login", map[string]any{"username": `CORP\administrator`})); len(m) != 0 {
		t.Errorf("unrelated user matched: %+v", m)
	}
}

func onNode(e models.Event, nodeID string) models.Event { e.NodeID = nodeID; return e }

func TestNodeCaptureKeysArePerNode(t *testing.T) {
	st := newStore(t)
	svc := honeytoken.NewService(st)
	ka, _ := svc.NodeCaptureKey("node-a")
	kb, _ := svc.NodeCaptureKey("node-b")
	master, _ := st.GetConfigValue("capture_master_key")
	if ka == "" || ka == kb || ka == master || kb == master {
		t.Fatalf("node keys must be distinct and never the master (a=%q b=%q)", ka, kb)
	}
	if again, _ := svc.NodeCaptureKey("node-a"); again != ka {
		t.Fatal("node key must be stable")
	}
}

func TestMatchPasswordByNodeHMAC(t *testing.T) {
	svc := honeytoken.NewService(newStore(t))
	tok, _ := svc.TokenFor("node-a", "ts-sensor-file-canary") // planted on A
	kb, _ := svc.NodeCaptureKey("node-b")

	// Used against a decoy on node B: B's key HMAC matches.
	h, id := decoyHMAC(kb, tok.Secret)
	m, _ := svc.Match(onNode(event_("web_login_attempt", map[string]any{"attempted_username": "admin", "attempted_password_hmac": h, "hmac_key_id": id}), "node-b"))
	if len(m) != 1 || m[0].MatchedOn != "password" || m[0].Token.NodeID != "node-a" {
		t.Fatalf("cross-node password match failed: %+v", m)
	}
	m, _ = svc.Match(onNode(event_("ldap_login", map[string]any{"bind_dn": "cn=" + tok.Username + ",dc=corp", "password_hmac": h, "hmac_key_id": id}), "node-b"))
	if len(m) != 1 || m[0].MatchedOn != "username+password" {
		t.Fatalf("combined match = %+v", m)
	}

	// Node isolation: node B's key does not validate on node C.
	if m, _ := svc.Match(onNode(event_("ldap_login", map[string]any{"password_hmac": h, "hmac_key_id": id}), "node-c")); len(m) != 0 {
		t.Fatalf("node-b HMAC accepted on node-c: %+v", m)
	}
	// An HMAC from an unrelated key is ignored.
	other, otherID := decoyHMAC("not-a-node-key", tok.Secret)
	if m, _ := svc.Match(onNode(event_("ldap_login", map[string]any{"password_hmac": other, "hmac_key_id": otherID}), "node-b")); len(m) != 0 {
		t.Fatalf("foreign-key HMAC matched: %+v", m)
	}
	// Plain capture mode.
	if m, _ := svc.Match(onNode(event_("ldap_login", map[string]any{"password": tok.Secret}), "node-b")); len(m) != 1 {
		t.Fatalf("plaintext password not matched: %+v", m)
	}
	// Hub-raised honeytoken events are never re-matched.
	if m, _ := svc.Match(event_(honeytoken.Trigger, map[string]any{"username": tok.Username})); len(m) != 0 {
		t.Fatal("honeytoken_used re-matched")
	}
}

type recordingPublisher struct {
	mu  sync.Mutex
	got []models.Honeytoken
}

func (r *recordingPublisher) QueueHoneytoken(h models.Honeytoken) {
	r.mu.Lock()
	r.got = append(r.got, h)
	r.mu.Unlock()
}

func (r *recordingPublisher) snapshot() []models.Honeytoken {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]models.Honeytoken(nil), r.got...)
}

func TestPublisherGetsNewAndResyncedTokens(t *testing.T) {
	svc := honeytoken.NewService(newStore(t))
	pub := &recordingPublisher{}
	svc.SetPublisher(pub)
	tok, _ := svc.TokenFor("node-a", "ts-sensor-file-canary")
	svc.TokenFor("node-a", "ts-sensor-file-canary") // existing: not republished
	if got := pub.snapshot(); len(got) != 1 || got[0].Username != tok.Username {
		t.Fatalf("creation publish = %+v", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.StartWatchlistSync(ctx, time.Hour)
	deadline := time.Now().Add(2 * time.Second)
	for len(pub.snapshot()) < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := pub.snapshot(); len(got) != 2 {
		t.Fatalf("startup resync did not publish: %+v", got)
	}
}

func TestFactoryResetKeepsHoneytokensUnlessPurged(t *testing.T) {
	st := newStore(t)
	svc := honeytoken.NewService(st)
	tok, _ := svc.TokenFor("node-a", "ts-sensor-file-canary")
	ka, _ := svc.NodeCaptureKey("node-a")

	if err := st.FactoryReset(false); err != nil {
		t.Fatal(err)
	}
	if kb, _ := svc.NodeCaptureKey("node-a"); kb != ka {
		t.Fatal("master key must survive a default factory reset")
	}
	if m, _ := svc.Match(event_("ldap_login", map[string]any{"username": tok.Username})); len(m) != 1 {
		t.Fatal("honeytoken must still match after a default factory reset")
	}

	if err := st.FactoryReset(true); err != nil {
		t.Fatal(err)
	}
	if list, _ := svc.List(); len(list) != 0 {
		t.Fatalf("purge left honeytokens: %+v", list)
	}
	if kc, _ := svc.NodeCaptureKey("node-a"); kc == ka {
		t.Fatal("purge must rotate the master key")
	}
}

type nopSiem struct{ events []models.Event }

func (n *nopSiem) QueueEvent(e models.Event) { n.events = append(n.events, e) }

type nopNotify struct{ events []models.Event }

func (n *nopNotify) Dispatch(e models.Event) { n.events = append(n.events, e) }

type nopWS struct{}

func (nopWS) Broadcast(string, interface{}) {}

func TestEventPipelineRaisesHoneytokenUsed(t *testing.T) {
	st := newStore(t)
	addSensor(t, st, "node-a", "ts-sensor-file-canary")
	addSensor(t, st, "node-b", "ts-sensor-identity-decoy")

	ht := honeytoken.NewService(st)
	tok, _ := ht.TokenFor("node-a", "ts-sensor-file-canary")

	siem, notify := &nopSiem{}, &nopNotify{}
	evs := event.NewService(st, nopWS{}, siem, notify)
	evs.SetHoneytokenMatcher(ht)
	// Even an allow-listed source cannot hide a honeytoken use.
	if err := st.UpdateConfigValue("whitelisted_sources", "10.9.8.7"); err != nil {
		t.Fatal(err)
	}

	e := event_("rdp_login", map[string]any{"protocol": "rdp", "dst_port": 3389, "username": `CORP\` + tok.Username, "auth": "nla_ntlm"})
	if err := evs.ProcessEvent(&e, "node-b"); err != nil {
		t.Fatal(err)
	}

	var alert *models.Event
	for i := range siem.events {
		if siem.events[i].EventTrigger == honeytoken.Trigger {
			alert = &siem.events[i]
		}
	}
	if alert == nil {
		t.Fatalf("no honeytoken_used in SIEM feed: %+v", siem.events)
	}
	if alert.Whitelisted || alert.Severity != "critical" || alert.NodeID != "node-b" || alert.Source != "10.9.8.7" {
		t.Fatalf("alert = %+v", alert)
	}
	var d map[string]any
	_ = json.Unmarshal(alert.Details, &d)
	if d["planted_node_id"] != "node-a" || d["planted_sensor_id"] != "ts-sensor-file-canary" || d["matched_on"] != "username" || d["protocol"] != "rdp" {
		t.Fatalf("details = %v", d)
	}
	if len(notify.events) != 1 || notify.events[0].EventTrigger != honeytoken.Trigger {
		t.Fatalf("webhook should fire for the honeytoken alert only (source is whitelisted): %+v", notify.events)
	}

	list, _ := ht.List()
	if len(list) != 1 || list[0].UseCount != 1 || list[0].LastUsedAt == "" {
		t.Fatalf("use not recorded: %+v", list)
	}
}

func TestSensorCannotForgeHoneytokenUsed(t *testing.T) {
	st := newStore(t)
	addSensor(t, st, "node-b", "ts-sensor-identity-decoy")
	evs := event.NewService(st, nopWS{}, &nopSiem{}, &nopNotify{})
	e := event_(honeytoken.Trigger, map[string]any{})
	if err := evs.ProcessEvent(&e, "node-b"); err != event.ErrReservedTrigger {
		t.Fatalf("err = %v, want ErrReservedTrigger", err)
	}
}

func TestListNeverSerialisesSecret(t *testing.T) {
	svc := honeytoken.NewService(newStore(t))
	tok, _ := svc.TokenFor("node-a", "ts-sensor-file-canary")
	list, _ := svc.List()
	b, _ := json.Marshal(list)
	if strings.Contains(string(b), tok.Secret) {
		t.Fatalf("secret material serialised: %s", b)
	}
}

func honeytokenHMAC(key, value string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}
