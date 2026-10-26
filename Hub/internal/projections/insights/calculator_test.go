package insights

import (
	"testing"
	"time"

	"github.com/truesignal/hub/internal/models"
	"github.com/truesignal/hub/internal/store"
)

func ev(node, sensor, trigger, sev, src string, at time.Time) models.Event {
	return models.Event{NodeID: node, SensorID: sensor, EventTrigger: trigger, Severity: sev, Source: src, Timestamp: at.Format(time.RFC3339)}
}

func TestCalculate(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	decoys := []store.DeployedSensor{
		{NodeID: "n1", SensorID: "ts-sensor-tcp-tarpit"},
		{NodeID: "n2", SensorID: "ts-sensor-tcp-tarpit"},
		{NodeID: "n1", SensorID: "ts-sensor-identity-decoy"},
		{NodeID: "n1", SensorID: "ts-sensor-file-canary"},
	}
	events := []models.Event{
		ev("n1", "ts-sensor-tcp-tarpit", "tcp_connection", "low", "10.0.0.5", now.Add(-time.Hour)),
		ev("n1", "ts-sensor-tcp-tarpit", "tcp_connection", "low", "10.0.0.5", now.Add(-2*time.Hour)),
		ev("n1", "ts-sensor-identity-decoy", "ldap_login", "critical", "10.0.0.5", now.Add(-time.Hour)),
		ev("n1", "ts-sensor-identity-decoy", "rdp_login", "critical", "10.0.0.9", now.Add(-time.Hour)),
		// Liveness is not attacker activity.
		ev("n2", "ts-sensor-tcp-tarpit", "sensor_heartbeat_lost", "high", "truesignal-hub", now.Add(-time.Hour)),
		// Outside a 24H window.
		ev("n2", "ts-sensor-tcp-tarpit", "tcp_connection", "low", "10.0.0.7", now.Add(-48*time.Hour)),
		// A sensor since removed from its node still counts as activity.
		ev("n3", "ts-sensor-web-router-decoy", "web_login_attempt", "critical", "10.0.0.8", now.Add(-time.Hour)),
	}
	tokens := []models.Honeytoken{{ID: "a", UseCount: 2}, {ID: "b"}}

	tf, since := Since("24H", now)
	got := Calculate(events, decoys, tokens, tf, since)

	if got.Events != 5 || got.CriticalEvents != 3 || got.UniqueSources != 3 {
		t.Fatalf("events/critical/sources = %d/%d/%d, want 5/3/3", got.Events, got.CriticalEvents, got.UniqueSources)
	}
	if got.DecoysDeployed != 4 || got.DecoysTouched != 2 || got.DecoyTypesDeployed != 3 {
		t.Fatalf("deployed/touched/types = %d/%d/%d, want 4/2/3", got.DecoysDeployed, got.DecoysTouched, got.DecoyTypesDeployed)
	}
	// tcp_connection T1046, ldap_login T1110 (rdp_login T1021.001), web_login_attempt T1110.
	if got.TechniquesObserved != 3 {
		t.Fatalf("techniques observed = %d, want 3", got.TechniquesObserved)
	}
	if got.HoneytokensTotal != 2 || got.HoneytokensUsed != 1 {
		t.Fatalf("honeytokens = %d/%d, want 2/1", got.HoneytokensTotal, got.HoneytokensUsed)
	}

	byID := map[string]TypeStat{}
	for _, s := range got.ByType {
		byID[s.SensorID] = s
	}
	want := map[string]TypeStat{
		"ts-sensor-tcp-tarpit":       {SensorID: "ts-sensor-tcp-tarpit", Events: 2, UniqueSources: 1, Deployed: 2, Touched: 1},
		"ts-sensor-identity-decoy":   {SensorID: "ts-sensor-identity-decoy", Events: 2, UniqueSources: 2, Deployed: 1, Touched: 1},
		"ts-sensor-file-canary":      {SensorID: "ts-sensor-file-canary", Deployed: 1},
		"ts-sensor-web-router-decoy": {SensorID: "ts-sensor-web-router-decoy", Events: 1, UniqueSources: 1},
	}
	if len(byID) != len(want) {
		t.Fatalf("byType has %d types, want %d: %+v", len(byID), len(want), got.ByType)
	}
	for id, w := range want {
		if byID[id] != w {
			t.Errorf("%s = %+v, want %+v", id, byID[id], w)
		}
	}
	// Busiest first, ties by ID; untouched types last.
	if got.ByType[0].SensorID != "ts-sensor-identity-decoy" || got.ByType[len(got.ByType)-1].SensorID != "ts-sensor-file-canary" {
		t.Errorf("order = %+v", got.ByType)
	}

	_, allSince := Since("alltime", now)
	if all := Calculate(events, decoys, tokens, "alltime", allSince); all.Events != 6 || all.DecoysTouched != 3 {
		t.Errorf("alltime events/touched = %d/%d, want 6/3", all.Events, all.DecoysTouched)
	}
}
