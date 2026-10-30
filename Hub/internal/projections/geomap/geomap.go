// Package geomap aggregates located decoy activity for the map page: one
// point per place (city-level coordinates) and a per-country table.
package geomap

import (
	"context"
	"fmt"
	"math"
	"net"
	"net/netip"
	"sort"
	"time"

	"github.com/truesignal/hub/internal/geo"
	"github.com/truesignal/hub/internal/models"
	"github.com/truesignal/hub/internal/projections/insights"
)

// maxPointSources caps the sources listed per point (sourceCount is exact).
const maxPointSources = 20

// Point is the activity located at one place.
type Point struct {
	Lat          float64  `json:"lat"`
	Lon          float64  `json:"lon"`
	City         string   `json:"city"`
	Region       string   `json:"region"`
	Country      string   `json:"country"`
	CountryCode  string   `json:"countryCode"`
	Events       int      `json:"events"`
	BeaconEvents int      `json:"beaconEvents"`
	SourceCount  int      `json:"sourceCount"`
	Sources      []string `json:"sources"`
	Triggers     []string `json:"triggers"`
	MaxSeverity  string   `json:"maxSeverity"`
	LastSeen     string   `json:"lastSeen"`
}

// Country is the activity located in one country.
type Country struct {
	CountryCode string `json:"countryCode"`
	Country     string `json:"country"`
	Events      int    `json:"events"`
	Sources     int    `json:"sources"`
}

// DTO is the read-model behind GET /api/v2/geo.
type DTO struct {
	Timeframe string     `json:"timeframe"`
	GeoIP     geo.Status `json:"geoip"`
	// Events in range (attacker activity only), split by how they placed:
	// located, internal (private/CGNAT/... source, never looked up) and
	// unlocated (public or a name, but not in the database).
	Events          int       `json:"events"`
	LocatedEvents   int       `json:"locatedEvents"`
	InternalEvents  int       `json:"internalEvents"`
	UnlocatedEvents int       `json:"unlocatedEvents"`
	Points          []Point   `json:"points"`
	Countries       []Country `json:"countries"`
}

// Locator places one event (geo.Service.ForEvent).
type Locator interface {
	ForEvent(source string, details map[string]any) *geo.Location
	Status() geo.Status
}

type ProjectionStore interface {
	GetEvents(isArchived int, nodeID, sensorID string) ([]models.Event, error)
}

func Build(ctx context.Context, st ProjectionStore, loc Locator, timeframe, nodeID, sensorID string, viewingArchive int) (*DTO, error) {
	timeframe, since := insights.Since(timeframe, time.Now().UTC())
	events, err := st.GetEvents(viewingArchive, nodeID, sensorID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch events for the map: %w", err)
	}
	return Calculate(events, loc, timeframe, since), nil
}

var severityRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// internalSource reports an address the map never looks up (private,
// CGNAT, loopback, ...), as opposed to a name or an unlisted public address.
func internalSource(source string) bool {
	a := addrOf(source)
	return a.IsValid() && !geo.Public(a)
}

// Calculate aggregates events since `since` (zero = all time).
func Calculate(events []models.Event, loc Locator, timeframe string, since time.Time) *DTO {
	dto := &DTO{Timeframe: timeframe, GeoIP: loc.Status(), Points: []Point{}, Countries: []Country{}}
	type pointAgg struct {
		p        *Point
		sources  map[string]bool
		triggers map[string]bool
	}
	points := map[string]*pointAgg{}
	countries := map[string]*Country{}
	countrySources := map[string]map[string]bool{}

	for _, e := range events {
		if !insights.IsAttackerEvent(e) {
			continue
		}
		if !since.IsZero() {
			ts, err := time.Parse(time.RFC3339, e.Timestamp)
			if err != nil || ts.Before(since) {
				continue
			}
		}
		dto.Events++
		l := loc.ForEvent(e.Source, geo.ClientSubnetDetails(e.Details))
		if l == nil {
			if internalSource(e.Source) {
				dto.InternalEvents++
			} else {
				dto.UnlocatedEvents++
			}
			continue
		}
		dto.LocatedEvents++
		who := l.Address // the located address: the source, or the beacon's client subnet

		if l.Lat != 0 || l.Lon != 0 {
			key := fmt.Sprintf("%.2f,%.2f", round2(l.Lat), round2(l.Lon))
			a := points[key]
			if a == nil {
				a = &pointAgg{
					p:        &Point{Lat: round2(l.Lat), Lon: round2(l.Lon), City: l.City, Region: l.Region, Country: l.Country, CountryCode: l.CountryCode, MaxSeverity: e.Severity},
					sources:  map[string]bool{},
					triggers: map[string]bool{},
				}
				points[key] = a
			}
			a.p.Events++
			if e.EventTrigger == "beacon_triggered" {
				a.p.BeaconEvents++
			}
			a.sources[who] = true
			a.triggers[e.EventTrigger] = true
			if severityRank[e.Severity] > severityRank[a.p.MaxSeverity] {
				a.p.MaxSeverity = e.Severity
			}
			if e.Timestamp > a.p.LastSeen {
				a.p.LastSeen = e.Timestamp
			}
		}

		cc := l.CountryCode
		if cc == "" {
			cc = "??"
		}
		c := countries[cc]
		if c == nil {
			c = &Country{CountryCode: cc, Country: l.Country}
			countries[cc] = c
			countrySources[cc] = map[string]bool{}
		}
		c.Events++
		countrySources[cc][who] = true
	}

	for _, a := range points {
		a.p.SourceCount = len(a.sources)
		a.p.Sources = sortedKeys(a.sources, maxPointSources)
		a.p.Triggers = sortedKeys(a.triggers, 0)
		dto.Points = append(dto.Points, *a.p)
	}
	sort.Slice(dto.Points, func(i, j int) bool {
		if dto.Points[i].Events != dto.Points[j].Events {
			return dto.Points[i].Events > dto.Points[j].Events
		}
		return dto.Points[i].City < dto.Points[j].City
	})
	for cc, c := range countries {
		c.Sources = len(countrySources[cc])
		dto.Countries = append(dto.Countries, *c)
	}
	sort.Slice(dto.Countries, func(i, j int) bool {
		if dto.Countries[i].Events != dto.Countries[j].Events {
			return dto.Countries[i].Events > dto.Countries[j].Events
		}
		return dto.Countries[i].CountryCode < dto.Countries[j].CountryCode
	})
	return dto
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }

func sortedKeys(m map[string]bool, max int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	return out
}

// addrOf parses a source (an IP, or an IP with a port); invalid for names.
func addrOf(source string) netip.Addr {
	if host, _, err := net.SplitHostPort(source); err == nil {
		source = host
	}
	a, _ := netip.ParseAddr(source)
	return a
}
