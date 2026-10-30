package insights

import (
	"sort"
	"time"

	"github.com/truesignal/hub/internal/attack"
	"github.com/truesignal/hub/internal/models"
	"github.com/truesignal/hub/internal/store"
)

// livenessTriggers are raised by the Hub about its own sensors, not by an
// attacker touching a decoy.
var livenessTriggers = map[string]bool{
	"sensor_stopped":        true,
	"sensor_heartbeat_lost": true,
	"sensor_recovered":      true,
}

// LivenessTriggers lists the Hub's own liveness triggers.
func LivenessTriggers() []string {
	out := make([]string, 0, len(livenessTriggers))
	for t := range livenessTriggers {
		out = append(out, t)
	}
	return out
}

// FiredrillSource is the source of firedrill and TS_TEST_MODE events
// (truesignal firedrill, SIGUSR1): a test, not an attacker.
const FiredrillSource = "Wizard Firedrill"

// NonAttackerSources lists sources that never count as attacker activity.
func NonAttackerSources() []string { return []string{FiredrillSource} }

// IsAttackerEvent reports whether an event counts as decoy interaction:
// not Hub liveness and not a firedrill, which would otherwise inflate the
// attacker and coverage figures in the dashboard and the evidence report.
func IsAttackerEvent(e models.Event) bool {
	return !livenessTriggers[e.EventTrigger] && e.Source != FiredrillSource
}

// Calculate aggregates events since `since` (zero = all time) against the
// deployed decoys and honeytokens. Honeytoken use is all-time: the token
// table keeps a counter, not per-use rows.
func Calculate(events []models.Event, decoys []store.DeployedSensor, tokens []models.Honeytoken, timeframe string, since time.Time) *InsightsDTO {
	dto := &InsightsDTO{Timeframe: timeframe, ByType: []TypeStat{}}

	types := map[string]*TypeStat{}
	typeOf := func(sensorID string) *TypeStat {
		t, ok := types[sensorID]
		if !ok {
			t = &TypeStat{SensorID: sensorID}
			types[sensorID] = t
		}
		return t
	}

	deployed := map[store.DeployedSensor]bool{}
	for _, d := range decoys {
		if deployed[d] {
			continue
		}
		deployed[d] = true
		typeOf(d.SensorID).Deployed++
	}
	dto.DecoysDeployed = len(deployed)

	sources := map[string]bool{}
	techniques := map[string]bool{}
	typeSources := map[string]map[string]bool{}
	touched := map[store.DeployedSensor]bool{}

	for _, e := range events {
		if !IsAttackerEvent(e) {
			continue
		}
		if !since.IsZero() {
			t, err := time.Parse(time.RFC3339, e.Timestamp)
			if err == nil && t.Before(since) {
				continue
			}
		}
		dto.Events++
		if e.Severity == "critical" {
			dto.CriticalEvents++
		}
		sources[e.Source] = true
		if m, ok := attack.For(e.EventTrigger); ok {
			techniques[m.Primary.ID] = true
		}

		t := typeOf(e.SensorID)
		t.Events++
		if typeSources[e.SensorID] == nil {
			typeSources[e.SensorID] = map[string]bool{}
		}
		typeSources[e.SensorID][e.Source] = true

		d := store.DeployedSensor{NodeID: e.NodeID, SensorID: e.SensorID}
		if deployed[d] && !touched[d] {
			touched[d] = true
			t.Touched++
		}
	}
	dto.UniqueSources = len(sources)
	dto.TechniquesObserved = len(techniques)
	dto.DecoysTouched = len(touched)

	for id, t := range types {
		t.UniqueSources = len(typeSources[id])
		if t.Deployed > 0 {
			dto.DecoyTypesDeployed++
		}
		dto.ByType = append(dto.ByType, *t)
	}
	sort.Slice(dto.ByType, func(i, j int) bool {
		a, b := dto.ByType[i], dto.ByType[j]
		if a.Events != b.Events {
			return a.Events > b.Events
		}
		return a.SensorID < b.SensorID
	})

	dto.HoneytokensTotal = len(tokens)
	for _, h := range tokens {
		if h.UseCount > 0 {
			dto.HoneytokensUsed++
		}
	}
	return dto
}
