package store

import (
	"path/filepath"
	"testing"
	"time"
)

func createTestNodeAndSensors(t *testing.T, st *SQLiteStore, nodeID string, sensorIDs ...string) {
	nowStr := time.Now().UTC().Format(time.RFC3339)
	_, err := st.DB.Exec(`
		INSERT INTO nodes (id, alias, api_key, created_at, updated_at) 
		VALUES (?, ?, ?, ?, ?)
	`, nodeID, "test-alias", "test-key-"+nodeID, nowStr, nowStr)
	if err != nil {
		t.Fatalf("Failed to insert test node: %v", err)
	}

	for _, sID := range sensorIDs {
		_, err := st.DB.Exec(`
			INSERT INTO node_sensors (node_id, sensor_id, custom_name, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?)
		`, nodeID, sID, "test-sensor-"+sID, nowStr, nowStr)
		if err != nil {
			t.Fatalf("Failed to insert test node_sensor: %v", err)
		}
	}
}

func TestEnforceRetention_PreservesBaselineStatusChange(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test_retention.db")
	st, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create test store: %v", err)
	}
	defer st.DB.Close()

	createTestNodeAndSensors(t, st, "node1", "sensor1")

	now := time.Now().UTC()

	// Insert status changes for node1:sensor1
	// 1. 60 days ago (online)
	// 2. 50 days ago (offline)
	// 3. 40 days ago (online) - Active state at Day -30 cutoff
	// 4. 20 days ago (offline)
	// 5. 10 days ago (online) - Latest state overall
	timestamps := []struct {
		status    string
		timestamp time.Time
	}{
		{"online", now.AddDate(0, 0, -60)},
		{"offline", now.AddDate(0, 0, -50)},
		{"online", now.AddDate(0, 0, -40)},
		{"offline", now.AddDate(0, 0, -20)},
		{"online", now.AddDate(0, 0, -10)},
	}

	for _, ts := range timestamps {
		if err := st.InsertStatusChange("node1", "sensor1", ts.status, ts.timestamp.Format(time.RFC3339)); err != nil {
			t.Fatalf("Failed to insert status change: %v", err)
		}
	}

	// Purge records older than 30 days
	if err := st.EnforceRetention(0, 0, 30); err != nil {
		t.Fatalf("EnforceRetention failed: %v", err)
	}

	// Verify records remaining in database
	rows, err := st.DB.Query("SELECT status, timestamp FROM sensor_status_changes WHERE node_id = 'node1' AND sensor_id = 'sensor1' ORDER BY timestamp ASC")
	if err != nil {
		t.Fatalf("Failed to query remaining rows: %v", err)
	}
	defer rows.Close()

	type resultRow struct {
		status    string
		timestamp string
	}
	var results []resultRow
	for rows.Next() {
		var r resultRow
		if err := rows.Scan(&r.status, &r.timestamp); err != nil {
			t.Fatalf("Failed to scan row: %v", err)
		}
		results = append(results, r)
	}

	// Should preserve:
	// - 40 days ago (baseline at cutoff)
	// - 20 days ago (in-window)
	// - 10 days ago (latest in-window)
	if len(results) != 3 {
		t.Fatalf("Expected 3 records preserved (baseline + in-window), got %d: %+v", len(results), results)
	}

	expected40d := timestamps[2].timestamp.Format(time.RFC3339)
	if results[0].timestamp != expected40d || results[0].status != "online" {
		t.Errorf("Expected first preserved row to be 40d baseline (online, %s), got (%s, %s)", expected40d, results[0].status, results[0].timestamp)
	}

	expected20d := timestamps[3].timestamp.Format(time.RFC3339)
	if results[1].timestamp != expected20d || results[1].status != "offline" {
		t.Errorf("Expected second preserved row to be 20d (offline, %s), got (%s, %s)", expected20d, results[1].status, results[1].timestamp)
	}

	expected10d := timestamps[4].timestamp.Format(time.RFC3339)
	if results[2].timestamp != expected10d || results[2].status != "online" {
		t.Errorf("Expected third preserved row to be 10d (online, %s), got (%s, %s)", expected10d, results[2].status, results[2].timestamp)
	}
}

func TestGetStatusChangesSince_IncludesBaseline(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test_status_changes.db")
	st, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create test store: %v", err)
	}
	defer st.DB.Close()

	createTestNodeAndSensors(t, st, "node1", "sensor1", "sensor2")

	now := time.Now().UTC()
	cutoff := now.AddDate(0, 0, -30)

	// Sensor 1: Came online 45 days ago, went offline 10 days ago
	_ = st.InsertStatusChange("node1", "sensor1", "online", now.AddDate(0, 0, -45).Format(time.RFC3339))
	_ = st.InsertStatusChange("node1", "sensor1", "offline", now.AddDate(0, 0, -10).Format(time.RFC3339))

	// Sensor 2: Came online 50 days ago, no changes since
	_ = st.InsertStatusChange("node1", "sensor2", "online", now.AddDate(0, 0, -50).Format(time.RFC3339))

	changes, err := st.GetStatusChangesSince(cutoff.Format(time.RFC3339))
	if err != nil {
		t.Fatalf("GetStatusChangesSince failed: %v", err)
	}

	// Sensor 1 should have 2 records (45d baseline + 10d in-window)
	// Sensor 2 should have 1 record (50d baseline)
	sensor1Count := 0
	sensor2Count := 0
	for _, c := range changes {
		if c.SensorID == "sensor1" {
			sensor1Count++
		}
		if c.SensorID == "sensor2" {
			sensor2Count++
		}
	}

	if sensor1Count != 2 {
		t.Errorf("Expected 2 records for sensor1, got %d", sensor1Count)
	}
	if sensor2Count != 1 {
		t.Errorf("Expected 1 baseline record for sensor2, got %d", sensor2Count)
	}
}

func TestGetSourceActivity(t *testing.T) {
	st, err := NewStore(filepath.Join(t.TempDir(), "sources.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.DB.Close()
	if _, err := st.DB.Exec(`INSERT INTO events (node_id, sensor_id, timestamp, event_trigger, source) VALUES
		('n1','s1','2026-10-01T00:00:00Z','tcp_connection','10.0.0.5'),
		('n1','s2','2026-10-03T00:00:00Z','ldap_login','10.0.0.5'),
		('n2','s1','2026-10-02T00:00:00Z','tcp_connection','10.0.0.5'),
		('n2','s1','2026-10-02T00:00:00Z','tcp_connection','10.0.0.9'),
		('n2','s1','2026-10-04T00:00:00Z','sensor_heartbeat_lost','truesignal-hub')`); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetSourceActivity([]string{"sensor_heartbeat_lost"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d sources, want 2 (liveness excluded): %+v", len(got), got)
	}
	for _, a := range got {
		if a.Source == "10.0.0.5" && (a.Events != 3 || a.Decoys != 3 || a.FirstSeen != "2026-10-01T00:00:00Z" || a.LastSeen != "2026-10-03T00:00:00Z") {
			t.Errorf("10.0.0.5 = %+v", a)
		}
	}
}
