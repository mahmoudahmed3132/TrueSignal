package report

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/truesignal/hub/internal/assets"
	"github.com/truesignal/hub/internal/models"
	"github.com/truesignal/hub/internal/store"
)

func TestBuild(t *testing.T) {
	from := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	ev := func(ts, src, trigger, sev string) models.Event {
		return models.Event{Timestamp: ts, Source: src, NodeID: "n1", SensorID: "s-" + trigger, EventTrigger: trigger, Severity: sev, Details: json.RawMessage(`{}`)}
	}
	ht := ev("2026-10-03T08:00:00Z", "10.0.0.9", "honeytoken_used", "critical")
	ht.Details = json.RawMessage(`{"honeytoken_username":"svc_backup"}`)
	active := []models.Event{
		ev("2026-09-30T23:59:59Z", "10.0.0.5", "tcp_connection", "low"), // before the range
		ev("2026-10-01T00:00:00Z", "10.0.0.5", "tcp_connection", "low"),
		ev("2026-10-01T05:00:00Z", "10.0.0.5", "ssh_login", "critical"),
		ev("2026-10-02T05:00:00Z", "10.0.0.7", "tcp_connection", "low"),
		ev("2026-10-02T06:00:00Z", "truesignal-hub", "sensor_heartbeat_lost", "high"), // liveness
		ht,
		ev("2026-10-04T00:00:00Z", "10.0.0.5", "tcp_connection", "low"), // end is exclusive
	}
	archived := []models.Event{ev("2026-10-02T00:00:00Z", "10.9.9.9", "tcp_connection", "low"), ev("2026-11-01T00:00:00Z", "10.9.9.9", "tcp_connection", "low")}
	inv := assets.NewIndex([]assets.Asset{{Name: "pg", Address: "10.0.0.9", Criticality: "critical"}})

	d := Build(active, archived, []store.DeployedSensor{{NodeID: "n1", SensorID: "s-tcp_connection"}}, nil, inv, from, to, to)

	if d.Summary.Events != 4 || d.Severity.Critical != 2 || d.Severity.Low != 2 || d.ArchivedEvents != 1 {
		t.Fatalf("events=%d sev=%+v archived=%d", d.Summary.Events, d.Severity, d.ArchivedEvents)
	}
	if len(d.Daily) != 3 || d.Daily[0].Date != "2026-10-01" || d.Daily[0].Events != 2 || d.Daily[0].Critical != 1 || d.Daily[2].Events != 1 {
		t.Fatalf("daily = %+v", d.Daily)
	}
	// Known asset first, then by critical count.
	if d.SourcesTotal != 3 || d.TopSources[0].Source != "10.0.0.9" || d.TopSources[0].Asset == nil || d.TopSources[1].Source != "10.0.0.5" || d.TopSources[1].Decoys != 2 {
		t.Fatalf("sources = %+v", d.TopSources)
	}
	if len(d.HoneytokenUses) != 1 || d.HoneytokenUses[0].Username != "svc_backup" {
		t.Fatalf("honeytoken uses = %+v", d.HoneytokenUses)
	}
	if len(d.Techniques) == 0 || d.Techniques[0].ID != "T1046" {
		t.Fatalf("techniques = %+v", d.Techniques)
	}
}
