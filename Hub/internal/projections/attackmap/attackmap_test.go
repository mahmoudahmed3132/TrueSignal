package attackmap

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/truesignal/hub/internal/attack"
	"github.com/truesignal/hub/internal/models"
)

func TestCalculateAndLayer(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	at := now.Add(-time.Hour).Format(time.RFC3339)
	events := []models.Event{
		{EventTrigger: "ssh_login", Source: "10.0.0.5", Timestamp: at},
		{EventTrigger: "ssh_login", Source: "10.0.0.6", Timestamp: at},
		{EventTrigger: "mysql_login", Source: "10.0.0.5", Timestamp: at},
		{EventTrigger: "web_page_view", Source: "10.0.0.5", Timestamp: at},               // unmapped
		{EventTrigger: "sensor_heartbeat_lost", Source: "truesignal-hub", Timestamp: at}, // liveness
	}
	d := Calculate(events, "alltime", time.Time{})
	if d.MappedEvents != 3 {
		t.Fatalf("mapped = %d, want 3", d.MappedEvents)
	}
	by := map[string]TechniqueStat{}
	for _, s := range d.Techniques {
		by[s.ID] = s
	}
	if s := by["T1021.004"]; s.PrimaryEvents != 2 || s.Sources != 2 {
		t.Errorf("T1021.004 = %+v", s)
	}
	// T1110: primary for mysql_login, secondary for both ssh_login events.
	if s := by["T1110"]; s.PrimaryEvents != 1 || s.SecondaryEvents != 2 || len(s.Triggers) != 2 {
		t.Errorf("T1110 = %+v", s)
	}
	if d.TechniquesCovered != len(attack.Covered()) || len(d.Techniques) != d.TechniquesCovered {
		t.Errorf("covered = %d, listed = %d", d.TechniquesCovered, len(d.Techniques))
	}
	if d.TechniquesObserved != 3 { // T1021.004, T1110, T1078
		t.Errorf("observed = %d, want 3", d.TechniquesObserved)
	}

	b, _ := json.Marshal(Layer(d, now))
	var layer struct {
		Domain     string                 `json:"domain"`
		Versions   struct{ Layer string } `json:"versions"`
		Techniques []struct {
			TechniqueID string `json:"techniqueID"`
			Score       int    `json:"score"`
		} `json:"techniques"`
		Gradient struct{ MaxValue int } `json:"gradient"`
	}
	if err := json.Unmarshal(b, &layer); err != nil {
		t.Fatal(err)
	}
	if layer.Domain != "enterprise-attack" || layer.Versions.Layer != "4.5" || layer.Gradient.MaxValue != 2 {
		t.Errorf("layer header = %+v", layer)
	}
	for _, lt := range layer.Techniques {
		if lt.TechniqueID == "T1021.004" && lt.Score != 2 {
			t.Errorf("T1021.004 score = %d", lt.Score)
		}
	}
}
