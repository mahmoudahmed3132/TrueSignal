// Package path reconstructs one source's route through the decoys: which
// decoys it reached, in what order, with which ATT&CK techniques, and how
// its tactics progressed.
package path

import (
	"sort"

	"github.com/truesignal/hub/internal/assets"
	"github.com/truesignal/hub/internal/attack"
	"github.com/truesignal/hub/internal/models"
	"github.com/truesignal/hub/internal/projections/insights"
)

// MaxEvents bounds one source's timeline.
const MaxEvents = 2000

// Step is one decoy on the path, in order of first contact.
type Step struct {
	NodeID      string   `json:"nodeId"`
	SensorID    string   `json:"sensorId"`
	FirstSeen   string   `json:"firstSeen"`
	LastSeen    string   `json:"lastSeen"`
	Events      int      `json:"events"`
	MaxSeverity string   `json:"maxSeverity"`
	Triggers    []string `json:"triggers"`
	Techniques  []string `json:"techniques"`
}

// ProgressStep is a technique that brought new tactics into the path, in
// order of first appearance. A technique filed under several tactics
// (Valid Accounts) is one step listing them all, not several stages.
type ProgressStep struct {
	FirstSeen string          `json:"firstSeen"`
	Technique string          `json:"technique"`
	Name      string          `json:"name"`
	Tactics   []attack.Tactic `json:"tactics"`
}

// DTO is the read-model behind GET /api/v2/path.
type DTO struct {
	Source      string         `json:"source"`
	Asset       *assets.Ref    `json:"asset"`
	Events      int            `json:"events"`
	Truncated   bool           `json:"truncated"`
	FirstSeen   string         `json:"firstSeen"`
	LastSeen    string         `json:"lastSeen"`
	Steps       []Step         `json:"steps"`
	Progression []ProgressStep `json:"progression"`
	Timeline    []models.Event `json:"timeline"`
}

var sevRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// Build expects the source's events oldest first (Hub liveness is skipped).
func Build(source string, events []models.Event, truncated bool) *DTO {
	d := &DTO{Source: source, Truncated: truncated, Steps: []Step{}, Progression: []ProgressStep{}, Timeline: []models.Event{}}
	type key struct{ node, sensor string }
	index := map[key]int{}
	triggers := []map[string]bool{}
	techniques := []map[string]bool{}
	seenTactic := map[string]bool{}

	for _, e := range events {
		if !insights.IsAttackerEvent(e) {
			continue
		}
		if m, ok := attack.For(e.EventTrigger); ok {
			mm := m
			e.Attack = &mm
		}
		d.Timeline = append(d.Timeline, e)
		d.Events++
		if d.FirstSeen == "" || e.Timestamp < d.FirstSeen {
			d.FirstSeen = e.Timestamp
		}
		if e.Timestamp > d.LastSeen {
			d.LastSeen = e.Timestamp
		}

		k := key{e.NodeID, e.SensorID}
		i, ok := index[k]
		if !ok {
			i = len(d.Steps)
			index[k] = i
			d.Steps = append(d.Steps, Step{NodeID: e.NodeID, SensorID: e.SensorID, FirstSeen: e.Timestamp, MaxSeverity: e.Severity})
			triggers = append(triggers, map[string]bool{})
			techniques = append(techniques, map[string]bool{})
		}
		s := &d.Steps[i]
		s.Events++
		s.LastSeen = e.Timestamp
		if sevRank[e.Severity] > sevRank[s.MaxSeverity] {
			s.MaxSeverity = e.Severity
		}
		triggers[i][e.EventTrigger] = true
		if e.Attack != nil {
			techniques[i][e.Attack.Primary.ID] = true
			var fresh []attack.Tactic
			for _, tc := range e.Attack.Primary.Tactics {
				if !seenTactic[tc.ID] {
					seenTactic[tc.ID] = true
					fresh = append(fresh, tc)
				}
			}
			if len(fresh) > 0 {
				d.Progression = append(d.Progression, ProgressStep{
					FirstSeen: e.Timestamp, Technique: e.Attack.Primary.ID, Name: e.Attack.Primary.Name, Tactics: fresh,
				})
			}
		}
	}
	for i := range d.Steps {
		d.Steps[i].Triggers = sortedKeys(triggers[i])
		d.Steps[i].Techniques = sortedKeys(techniques[i])
	}
	return d
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
