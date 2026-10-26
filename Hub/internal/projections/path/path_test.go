package path

import (
	"testing"

	"github.com/truesignal/hub/internal/models"
)

func TestBuild(t *testing.T) {
	ev := func(ts, node, sensor, trigger, sev string) models.Event {
		return models.Event{Timestamp: ts, NodeID: node, SensorID: sensor, EventTrigger: trigger, Severity: sev, Source: "10.0.0.5"}
	}
	d := Build("10.0.0.5", []models.Event{
		ev("2026-10-01T10:00:00Z", "n2", "scan", "network_scan_detected", "high"),
		ev("2026-10-01T10:05:00Z", "n1", "tarpit", "tcp_connection", "low"),
		ev("2026-10-01T10:06:00Z", "n2", "scan", "network_scan_detected", "high"),
		ev("2026-10-01T10:07:00Z", "n2", "scan", "sensor_heartbeat_lost", "high"), // liveness, skipped
		ev("2026-10-01T10:10:00Z", "n1", "identity", "ldap_login", "critical"),
		ev("2026-10-01T10:20:00Z", "n3", "remote", "ssh_login", "critical"),
		ev("2026-10-01T10:30:00Z", "n1", "identity", "honeytoken_used", "critical"),
	}, false)

	if d.Events != 6 || d.FirstSeen != "2026-10-01T10:00:00Z" || d.LastSeen != "2026-10-01T10:30:00Z" {
		t.Fatalf("summary = %d %s %s", d.Events, d.FirstSeen, d.LastSeen)
	}
	order := []string{"scan", "tarpit", "identity", "remote"}
	if len(d.Steps) != len(order) {
		t.Fatalf("steps = %+v", d.Steps)
	}
	for i, s := range order {
		if d.Steps[i].SensorID != s {
			t.Errorf("step %d = %s, want %s", i, d.Steps[i].SensorID, s)
		}
	}
	if d.Steps[0].Events != 2 || d.Steps[0].LastSeen != "2026-10-01T10:06:00Z" || d.Steps[0].Techniques[0] != "T1046" {
		t.Errorf("first step = %+v", d.Steps[0])
	}
	// Discovery (scan) -> Credential Access (ldap_login) -> Lateral Movement
	// (ssh_login) -> Valid Accounts as ONE step with its four tactics.
	want := []string{"T1046", "T1110", "T1021.004", "T1078"}
	if len(d.Progression) != len(want) {
		t.Fatalf("progression = %+v", d.Progression)
	}
	for i, id := range want {
		if d.Progression[i].Technique != id {
			t.Errorf("step %d = %s, want %s", i, d.Progression[i].Technique, id)
		}
	}
	if n := len(d.Progression[3].Tactics); n != 4 {
		t.Errorf("T1078 step has %d tactics, want 4", n)
	}
	if d.Timeline[0].Attack == nil {
		t.Error("timeline events carry no ATT&CK mapping")
	}
}
