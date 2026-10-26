package store

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
)

func TestGetSensorsForUptime_FirstSeenPreservedAfterPurge(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_sensors.db")

	dsn := fmt.Sprintf("%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("Failed to open sqlite: %v", err)
	}
	defer db.Close()

	if err := RunMigrations(db, dbPath); err != nil {
		t.Fatalf("RunMigrations failed: %v", err)
	}

	st := &SQLiteStore{DB: db}

	// 1. Seed node and sensor created 60 days ago
	createdAt := "2026-06-01T00:00:00Z"
	_, err = db.Exec(`
		INSERT INTO nodes (id, alias, api_key, created_at, updated_at)
		VALUES ('n1', 'Node 1', 'key1', ?, ?);
		INSERT INTO node_sensors (node_id, sensor_id, custom_name, created_at, updated_at)
		VALUES ('n1', 's1', 'Sensor 1', ?, ?);
	`, createdAt, createdAt, createdAt, createdAt)
	if err != nil {
		t.Fatalf("Failed to seed node & sensor: %v", err)
	}

	// 2. Add status changes where the oldest retained is only from yesterday
	yesterday := "2026-07-30T12:00:00Z"
	_, err = db.Exec(`
		INSERT INTO sensor_status_changes (node_id, sensor_id, status, timestamp)
		VALUES ('n1', 's1', 'online', ?);
	`, yesterday)
	if err != nil {
		t.Fatalf("Failed to insert status change: %v", err)
	}

	// 3. Call GetSensorsForUptime
	sensors, err := st.GetSensorsForUptime("2026-07-31T00:00:00Z")
	if err != nil {
		t.Fatalf("GetSensorsForUptime failed: %v", err)
	}

	if len(sensors) != 1 {
		t.Fatalf("Expected 1 sensor, got %d", len(sensors))
	}

	// 4. Verify FirstSeen reflects created_at (2026-06-01), NOT yesterday's status change
	if sensors[0].FirstSeen != createdAt {
		t.Errorf("Expected FirstSeen to be %s (sensor creation date), got %s", createdAt, sensors[0].FirstSeen)
	}
}

func TestListDeployedSensors(t *testing.T) {
	st, err := NewStore(filepath.Join(t.TempDir(), "deployed.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.DB.Close()
	now := "2026-10-26T00:00:00Z"
	if _, err := st.DB.Exec(`
		INSERT INTO nodes (id, alias, api_key, created_at, updated_at) VALUES ('n1','a','k1',?,?), ('n2','b','k2',?,?);
		INSERT INTO node_sensors (node_id, sensor_id, custom_name, created_at, updated_at)
		VALUES ('n1','s1','x',?,?), ('n1','s2','x',?,?), ('n2','s1','x',?,?);`,
		now, now, now, now, now, now, now, now, now, now); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		node, sensor string
		want         int
	}{{"", "", 3}, {"n1", "", 2}, {"", "s1", 2}, {"n2", "s2", 0}} {
		got, err := st.ListDeployedSensors(c.node, c.sensor)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != c.want {
			t.Errorf("ListDeployedSensors(%q,%q) = %d rows, want %d", c.node, c.sensor, len(got), c.want)
		}
	}
}
