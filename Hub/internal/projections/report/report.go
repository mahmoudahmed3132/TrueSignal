// Package report aggregates a date range of decoy activity for the
// evidence report (PCI DSS / CBE reviews, management summaries).
package report

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/truesignal/hub/internal/assets"
	"github.com/truesignal/hub/internal/models"
	"github.com/truesignal/hub/internal/projections/attackmap"
	"github.com/truesignal/hub/internal/projections/insights"
	"github.com/truesignal/hub/internal/store"
)

// MaxRange bounds one report.
const MaxRange = 366 * 24 * time.Hour

type Severity struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

type Day struct {
	Date     string `json:"date"`
	Events   int    `json:"events"`
	Critical int    `json:"critical"`
}

type Source struct {
	Source   string      `json:"source"`
	Events   int         `json:"events"`
	Critical int         `json:"critical"`
	Decoys   int         `json:"decoys"`
	First    string      `json:"firstSeen"`
	Last     string      `json:"lastSeen"`
	Asset    *assets.Ref `json:"asset"`
}

type HoneytokenUse struct {
	Timestamp string `json:"timestamp"`
	Username  string `json:"username"`
	Source    string `json:"source"`
	NodeID    string `json:"nodeId"`
	SensorID  string `json:"sensorId"`
}

// DTO is the read-model behind GET /api/v2/report.
type DTO struct {
	From           string                    `json:"from"`
	To             string                    `json:"to"`
	GeneratedAt    string                    `json:"generatedAt"`
	Summary        *insights.InsightsDTO     `json:"summary"`
	Severity       Severity                  `json:"severity"`
	Daily          []Day                     `json:"daily"`
	TopSources     []Source                  `json:"topSources"`
	SourcesTotal   int                       `json:"sourcesTotal"`
	Techniques     []attackmap.TechniqueStat `json:"techniques"`
	HoneytokenUses []HoneytokenUse           `json:"honeytokenUses"`
	// ArchivedEvents counts in-range archived events (whitelisted, known
	// scanners, or archived by an analyst); they are excluded from the
	// figures above.
	ArchivedEvents int `json:"archivedEvents"`
}

// Build covers events with from <= timestamp < to. Active events are the
// figures; archived ones (whitelisted, known scanners, or archived by an
// analyst) are only counted, since archiving is a triage decision.
func Build(active, archived []models.Event, decoys []store.DeployedSensor, tokens []models.Honeytoken, inventory *assets.Index, from, to, now time.Time) *DTO {
	in := func(e models.Event) bool {
		t, err := time.Parse(time.RFC3339, e.Timestamp)
		return err == nil && !t.Before(from) && t.Before(to)
	}
	var events []models.Event
	for _, e := range active {
		if in(e) && insights.IsAttackerEvent(e) {
			events = append(events, e)
		}
	}
	d := &DTO{
		From: from.UTC().Format(time.RFC3339), To: to.UTC().Format(time.RFC3339), GeneratedAt: now.UTC().Format(time.RFC3339),
		Daily: []Day{}, TopSources: []Source{}, Techniques: []attackmap.TechniqueStat{}, HoneytokenUses: []HoneytokenUse{},
	}
	for _, e := range archived {
		if in(e) && insights.IsAttackerEvent(e) {
			d.ArchivedEvents++
		}
	}

	d.Summary = insights.Calculate(events, decoys, tokens, "custom", time.Time{})

	days := map[string]*Day{}
	for day := from.UTC().Truncate(24 * time.Hour); day.Before(to); day = day.Add(24 * time.Hour) {
		key := day.Format("2006-01-02")
		days[key] = &Day{Date: key}
	}
	srcs := map[string]*Source{}
	srcDecoys := map[string]map[string]bool{}
	for _, e := range events {
		switch e.Severity {
		case "critical":
			d.Severity.Critical++
		case "high":
			d.Severity.High++
		case "medium":
			d.Severity.Medium++
		case "low":
			d.Severity.Low++
		default:
			d.Severity.Info++
		}
		if day := days[dateOf(e.Timestamp)]; day != nil {
			day.Events++
			if e.Severity == "critical" {
				day.Critical++
			}
		}
		s := srcs[e.Source]
		if s == nil {
			s = &Source{Source: e.Source, First: e.Timestamp, Asset: inventory.Lookup(e.Source)}
			srcs[e.Source] = s
			srcDecoys[e.Source] = map[string]bool{}
		}
		s.Events++
		if e.Severity == "critical" {
			s.Critical++
		}
		if e.Timestamp < s.First {
			s.First = e.Timestamp
		}
		if e.Timestamp > s.Last {
			s.Last = e.Timestamp
		}
		srcDecoys[e.Source][e.NodeID+"/"+e.SensorID] = true

		if e.EventTrigger == "honeytoken_used" {
			var det struct {
				Username string `json:"honeytoken_username"`
			}
			_ = json.Unmarshal(e.Details, &det)
			d.HoneytokenUses = append(d.HoneytokenUses, HoneytokenUse{Timestamp: e.Timestamp, Username: det.Username, Source: e.Source, NodeID: e.NodeID, SensorID: e.SensorID})
		}
	}
	for _, day := range days {
		d.Daily = append(d.Daily, *day)
	}
	sort.Slice(d.Daily, func(i, j int) bool { return d.Daily[i].Date < d.Daily[j].Date })

	for k, s := range srcs {
		s.Decoys = len(srcDecoys[k])
		d.TopSources = append(d.TopSources, *s)
	}
	d.SourcesTotal = len(d.TopSources)
	sort.Slice(d.TopSources, func(i, j int) bool {
		a, b := d.TopSources[i], d.TopSources[j]
		if (a.Asset != nil) != (b.Asset != nil) {
			return a.Asset != nil
		}
		if a.Critical != b.Critical {
			return a.Critical > b.Critical
		}
		if a.Events != b.Events {
			return a.Events > b.Events
		}
		return a.Source < b.Source
	})
	if len(d.TopSources) > 25 {
		d.TopSources = d.TopSources[:25]
	}
	sort.Slice(d.HoneytokenUses, func(i, j int) bool { return d.HoneytokenUses[i].Timestamp < d.HoneytokenUses[j].Timestamp })

	for _, t := range attackmap.Calculate(events, "custom", time.Time{}).Techniques {
		if t.PrimaryEvents+t.SecondaryEvents > 0 {
			d.Techniques = append(d.Techniques, t)
		}
	}
	sort.Slice(d.Techniques, func(i, j int) bool {
		if d.Techniques[i].PrimaryEvents != d.Techniques[j].PrimaryEvents {
			return d.Techniques[i].PrimaryEvents > d.Techniques[j].PrimaryEvents
		}
		return d.Techniques[i].ID < d.Techniques[j].ID
	})
	return d
}

func dateOf(ts string) string {
	if len(ts) < 10 {
		return ""
	}
	return ts[:10]
}
