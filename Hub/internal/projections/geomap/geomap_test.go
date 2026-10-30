package geomap

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/truesignal/hub/internal/geo"
	"github.com/truesignal/hub/internal/models"
)

// fakeLocator places a few addresses; client subnets win as in geo.
type fakeLocator struct{}

func (fakeLocator) Status() geo.Status {
	return geo.Status{Enabled: true, Attribution: geo.Attribution}
}

func (fakeLocator) ForEvent(source string, details map[string]any) *geo.Location {
	if cs, _ := details["client_subnet"].(string); cs == "198.51.100.0/24" {
		return &geo.Location{CountryCode: "EG", Country: "Egypt", City: "Cairo", Lat: 30.0444, Lon: 31.2357, Basis: "client_subnet", Address: "198.51.100.0"}
	}
	switch source {
	case "81.2.69.1", "81.2.69.2:443":
		return &geo.Location{CountryCode: "GB", Country: "United Kingdom", City: "London", Lat: 51.5142, Lon: -0.0931, Basis: "source", Address: source}
	case "203.0.113.5":
		return &geo.Location{CountryCode: "US", Country: "United States", Basis: "source", Address: source} // country only
	}
	return nil
}

func ev(trigger, source, severity, ts string, details map[string]any) models.Event {
	raw, _ := json.Marshal(details)
	return models.Event{EventTrigger: trigger, Source: source, Severity: severity, Timestamp: ts, Details: raw}
}

func TestCalculate(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	events := []models.Event{
		ev("web_login_attempt", "81.2.69.1", "high", "2026-10-30T10:00:00Z", nil),
		ev("ssh_login", "81.2.69.2:443", "critical", "2026-10-30T11:00:00Z", nil),
		ev("beacon_triggered", "8.8.8.8", "critical", "2026-10-30T11:30:00Z", map[string]any{"client_subnet": "198.51.100.0/24"}),
		ev("tcp_connection", "203.0.113.5", "low", "2026-10-30T11:40:00Z", nil),
		ev("ssh_login", "10.20.4.17", "critical", "2026-10-30T11:50:00Z", nil),
		ev("dns_query", "1.1.1.1", "medium", "2026-10-30T11:55:00Z", nil),                  // public, not in the DB
		ev("sensor_heartbeat_lost", "truesignal-hub", "high", "2026-10-30T11:56:00Z", nil), // liveness: ignored
		ev("ssh_login", "81.2.69.1", "critical", "2026-10-01T00:00:00Z", nil),              // out of range
	}
	d := Calculate(events, fakeLocator{}, "24H", now.Add(-24*time.Hour))
	if d.Events != 6 || d.LocatedEvents != 4 || d.InternalEvents != 1 || d.UnlocatedEvents != 1 {
		t.Fatalf("counts: %+v", d)
	}
	if len(d.Points) != 2 {
		t.Fatalf("points (country-only has no point): %+v", d.Points)
	}
	london := d.Points[0]
	if london.City != "London" || london.Events != 2 || london.SourceCount != 2 || london.MaxSeverity != "critical" ||
		london.LastSeen != "2026-10-30T11:00:00Z" || london.Lat != 51.51 || len(london.Triggers) != 2 {
		t.Fatalf("london = %+v", london)
	}
	cairo := d.Points[1]
	if cairo.City != "Cairo" || cairo.BeaconEvents != 1 || cairo.Sources[0] != "198.51.100.0" {
		t.Fatalf("cairo = %+v", cairo)
	}
	if len(d.Countries) != 3 || d.Countries[0].CountryCode != "GB" || d.Countries[0].Events != 2 || d.Countries[0].Sources != 2 {
		t.Fatalf("countries = %+v", d.Countries)
	}
	if !d.GeoIP.Enabled {
		t.Fatal("status missing")
	}
}
