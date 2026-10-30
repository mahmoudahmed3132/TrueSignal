package beacon_test

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/truesignal/hub/internal/models"
	"github.com/truesignal/hub/internal/services/beacon"
	"github.com/truesignal/hub/internal/services/event"
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

// addReceiver registers a Token Receiver on nodeID serving domain.
func addReceiver(t *testing.T, st *store.SQLiteStore, nodeID, domain string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := st.DB.Exec(`INSERT INTO nodes (id, alias, api_key, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		nodeID, nodeID, "k-"+nodeID, now, now); err != nil {
		t.Fatal(err)
	}
	cfg, _ := json.Marshal(map[string]any{"TS_BEACON_DOMAIN": domain})
	if _, err := st.DB.Exec(`INSERT INTO node_sensors (node_id, sensor_id, custom_name, config_values, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		nodeID, beacon.ReceiverSensorID, "receiver", string(cfg), now, now); err != nil {
		t.Fatal(err)
	}
}

type nopSiem struct{ events []models.Event }

func (n *nopSiem) QueueEvent(e models.Event) { n.events = append(n.events, e) }

type nopNotify struct{ events []models.Event }

func (n *nopNotify) Dispatch(e models.Event) { n.events = append(n.events, e) }

type nopWS struct{}

func (nopWS) Broadcast(string, interface{}) {}

func TestCreateValidatesAndDefaultsDomain(t *testing.T) {
	st := newStore(t)
	svc := beacon.NewService(st)
	if _, err := svc.Create(beacon.CreateRequest{Type: "dns", Name: "x"}); !errors.Is(err, beacon.ErrInvalid) {
		t.Fatalf("no receiver: err = %v", err)
	}
	addReceiver(t, st, "node-dmz", "T.Example.com.")
	b, err := svc.Create(beacon.CreateRequest{Type: "kubeconfig", Name: "EKS prod, jump host ~/.kube"})
	if err != nil {
		t.Fatal(err)
	}
	if b.Domain != "t.example.com" || len(b.Token) != 24 || b.ID == "" {
		t.Fatalf("beacon = %+v", b)
	}
	for _, bad := range []beacon.CreateRequest{
		{Type: "aws", Name: "x"},
		{Type: "dns", Name: ""},
		{Type: "dns", Name: "x", Domain: "not a domain"},
	} {
		if _, err := svc.Create(bad); !errors.Is(err, beacon.ErrInvalid) {
			t.Errorf("%+v: err = %v", bad, err)
		}
	}
	key, _ := svc.ReceiverKey()
	master, _ := st.GetConfigValue("beacon_master_key")
	if key == "" || key == master {
		t.Fatal("receiver key must be derived, never the master")
	}
}

func TestEventPipelineResolvesBeacon(t *testing.T) {
	st := newStore(t)
	addReceiver(t, st, "node-dmz", "t.example.com")
	bs := beacon.NewService(st)
	b, err := bs.Create(beacon.CreateRequest{Type: "dns", Name: "Finance share"})
	if err != nil {
		t.Fatal(err)
	}
	siem, notify := &nopSiem{}, &nopNotify{}
	evs := event.NewService(st, nopWS{}, siem, notify)
	evs.SetBeaconResolver(bs)
	// The reporting resolver is whitelisted: a beacon still alerts.
	if err := st.UpdateConfigValue("whitelisted_sources", "8.8.8.8"); err != nil {
		t.Fatal(err)
	}

	raw, _ := json.Marshal(map[string]any{"token": b.Token, "channel": "dns", "beacon": "forged"})
	e := models.Event{SensorID: beacon.ReceiverSensorID, EventTrigger: beacon.Trigger, Severity: "low", Source: "8.8.8.8", Details: raw}
	if err := evs.ProcessEvent(&e, "node-dmz"); err != nil {
		t.Fatal(err)
	}
	got := siem.events[0]
	var d map[string]any
	_ = json.Unmarshal(got.Details, &d)
	info, _ := d["beacon"].(map[string]any)
	if got.Severity != "critical" || got.Whitelisted || info["id"] != b.ID || info["name"] != "Finance share" || info["type"] != "dns" {
		t.Fatalf("event = %+v details = %v", got, d)
	}
	if len(notify.events) != 1 {
		t.Fatalf("notify = %d", len(notify.events))
	}
	list, _ := bs.List()
	if list[0].UseCount != 1 || list[0].LastUsedAt == "" {
		t.Fatalf("use not recorded: %+v", list[0])
	}

	// Unknown token: kept as evidence, medium, lists apply.
	raw, _ = json.Marshal(map[string]any{"token": "bbbbbbbbbbbbbbbbbbbbbbbb", "channel": "http"})
	e = models.Event{SensorID: beacon.ReceiverSensorID, EventTrigger: beacon.Trigger, Severity: "critical", Source: "8.8.8.8", Details: raw}
	if err := evs.ProcessEvent(&e, "node-dmz"); err != nil {
		t.Fatal(err)
	}
	got = siem.events[1]
	d = nil
	_ = json.Unmarshal(got.Details, &d)
	if got.Severity != "medium" || !got.Whitelisted || d["beacon_known"] != false || d["beacon"] != nil {
		t.Fatalf("unknown token: event = %+v details = %v", got, d)
	}
}

func TestDeleteAndFactoryReset(t *testing.T) {
	st := newStore(t)
	addReceiver(t, st, "node-dmz", "t.example.com")
	bs := beacon.NewService(st)
	b, _ := bs.Create(beacon.CreateRequest{Type: "web_bug", Name: "HR mail"})
	key, _ := bs.ReceiverKey()

	if err := st.FactoryReset(false); err != nil {
		t.Fatal(err)
	}
	if again, _ := bs.ReceiverKey(); again != key {
		t.Fatal("receiver key must survive a reset without purge")
	}
	if got, _ := bs.Get(b.ID); got == nil {
		t.Fatal("beacon must survive a reset without purge")
	}
	if ok, _ := bs.Delete(b.ID); !ok {
		t.Fatal("delete failed")
	}
	b2, _ := bs.Create(beacon.CreateRequest{Type: "dns", Name: "x", Domain: "t.example.com"})
	if err := st.FactoryReset(true); err != nil {
		t.Fatal(err)
	}
	if got, _ := bs.Get(b2.ID); got != nil {
		t.Fatal("purge must delete beacons")
	}
	if again, _ := bs.ReceiverKey(); again == key {
		t.Fatal("purge must rotate the receiver key")
	}
}
