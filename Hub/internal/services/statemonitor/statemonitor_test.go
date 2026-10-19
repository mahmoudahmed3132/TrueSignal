package statemonitor

import (
	"database/sql"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/truesignal/hub/internal/store"
)

type nopBroadcaster struct{}

func (nopBroadcaster) Broadcast(string, interface{}) {}

type recorder struct {
	mu     sync.Mutex
	events []string
}

func (r *recorder) EmitSystemEvent(nodeID, sensorID, trigger, severity string, _ map[string]any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, sensorID+":"+trigger+":"+severity)
}

func newDB(t *testing.T) *sql.DB {
	t.Helper()
	st, err := store.NewStore(filepath.Join(t.TempDir(), "sm.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.DB.Close() })
	if _, err := st.DB.Exec(`
		INSERT INTO nodes (id, alias, api_key, created_at, updated_at) VALUES ('n1','N1','sha256:x','x','x');
		INSERT INTO node_sensors (node_id, sensor_id, custom_name, created_at, updated_at) VALUES
			('n1','live','L','x','x'), ('n1','pending','P','x','x'), ('n1','stopped','S','x','x');
	`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return st.DB
}

func TestMonitor_AlertsOnHeartbeatLossNotOnPendingSensors(t *testing.T) {
	db := newDB(t)
	now := time.Now().UTC()
	old := now.Add(-5 * time.Minute).Format(time.RFC3339)
	if _, err := db.Exec(`
		UPDATE node_sensors SET last_heartbeat = ? WHERE sensor_id = 'live';
		INSERT INTO sensor_status_changes (node_id, sensor_id, status, timestamp) VALUES ('n1','live','online',?);
	`, old, old); err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	m := NewStateMonitor(db, nopBroadcaster{}, rec)

	m.monitor(now)
	m.monitor(now.Add(10 * time.Minute)) // later ticks must not re-alert

	if len(rec.events) != 1 || rec.events[0] != "live:sensor_heartbeat_lost:high" {
		t.Fatalf("expected exactly one heartbeat-lost alert for 'live', got %v", rec.events)
	}
}

func TestMonitor_EscalatesStoppedSensorThatStaysDown(t *testing.T) {
	db := newDB(t)
	now := time.Now().UTC()
	t0 := now.Add(-10 * time.Minute).Format(time.RFC3339)
	t1 := now.Add(-6 * time.Minute).Format(time.RFC3339)
	longAgo := now.Add(-2 * time.Hour).Format(time.RFC3339)
	if _, err := db.Exec(`
		UPDATE node_sensors SET last_heartbeat = ? WHERE sensor_id = 'stopped';
		INSERT INTO sensor_status_changes (node_id, sensor_id, status, timestamp) VALUES
			('n1','stopped','online',?), ('n1','stopped','offline',?);
	`, longAgo, t0, t1); err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	m := NewStateMonitor(db, nopBroadcaster{}, rec)
	m.monitor(now)
	m.monitor(now.Add(time.Minute))

	found := 0
	for _, e := range rec.events {
		if e == "stopped:sensor_heartbeat_lost:high" {
			found++
		}
	}
	if found != 1 {
		t.Fatalf("expected one escalation for 'stopped', got %v", rec.events)
	}
}
