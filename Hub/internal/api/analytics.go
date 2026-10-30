package api

import (
	"net/http"
	"time"

	"github.com/truesignal/hub/internal/assets"
	"github.com/truesignal/hub/internal/geo"
	"github.com/truesignal/hub/internal/projections/attackmap"
	"github.com/truesignal/hub/internal/projections/geomap"
	"github.com/truesignal/hub/internal/projections/insights"
	"github.com/truesignal/hub/internal/projections/path"
	"github.com/truesignal/hub/internal/projections/report"
	"github.com/truesignal/hub/internal/projections/severity"
	"github.com/truesignal/hub/internal/projections/sources"
	"github.com/truesignal/hub/internal/projections/summary"
	"github.com/truesignal/hub/internal/projections/uptime"
	"github.com/truesignal/hub/internal/projections/velocity"
	"github.com/truesignal/hub/internal/services/sourcelist"
	"github.com/truesignal/hub/internal/store"
)

type AnalyticsHandler struct {
	Store *store.SQLiteStore
	// Geo places sources on the map (GET /api/v2/geo); nil disables it.
	Geo *geo.Service
}

func NewAnalyticsHandler(store *store.SQLiteStore) *AnalyticsHandler {
	return &AnalyticsHandler{Store: store}
}

func (h *AnalyticsHandler) GetVelocityAnalytics(w http.ResponseWriter, r *http.Request) {
	timeframe := r.URL.Query().Get("timeframe")
	if timeframe == "" {
		timeframe = "24H"
	}

	nodeID := r.URL.Query().Get("nodeId")
	sensorID := r.URL.Query().Get("sensorId")
	viewingArchiveStr := r.URL.Query().Get("archived")
	viewingArchive := 0
	if viewingArchiveStr == "true" || viewingArchiveStr == "1" {
		viewingArchive = 1
	}

	projector := velocity.NewProjector(h.Store)
	projection, err := projector.BuildThreatVelocityProjection(r.Context(), timeframe, nodeID, sensorID, viewingArchive)
	if err != nil {
		RespondError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	SendJSON(w, http.StatusOK, projection)
}

func (h *AnalyticsHandler) GetSummaryAnalytics(w http.ResponseWriter, r *http.Request) {
	timeframe := r.URL.Query().Get("timeframe")
	if timeframe == "" {
		timeframe = "24H"
	}
	nodeID := r.URL.Query().Get("nodeId")
	sensorID := r.URL.Query().Get("sensorId")

	viewingArchiveStr := r.URL.Query().Get("archived")
	viewingArchive := 0
	if viewingArchiveStr == "true" || viewingArchiveStr == "1" {
		viewingArchive = 1
	}

	projector := summary.NewProjector(h.Store)
	projection, err := projector.BuildSummaryProjection(r.Context(), timeframe, nodeID, sensorID, viewingArchive)
	if err != nil {
		if err.Error() == "not_found" {
			RespondError(w, "Node not found", http.StatusNotFound)
			return
		}
		RespondError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	SendJSON(w, http.StatusOK, projection)
}

// GetInsights handles GET /api/v2/insights: decoy coverage, attacker
// sources and per-decoy-type activity for the dashboard.
func (h *AnalyticsHandler) GetInsights(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	viewingArchive := 0
	if a := q.Get("archived"); a == "true" || a == "1" {
		viewingArchive = 1
	}

	projector := insights.NewProjector(h.Store)
	projection, err := projector.BuildInsightsProjection(r.Context(), q.Get("timeframe"), q.Get("nodeId"), q.Get("sensorId"), viewingArchive)
	if err != nil {
		RespondError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	SendJSON(w, http.StatusOK, projection)
}

// GetAttack handles GET /api/v2/attack: activity per MITRE ATT&CK technique
// over every technique TrueSignal can evidence.
func (h *AnalyticsHandler) GetAttack(w http.ResponseWriter, r *http.Request) {
	d, err := h.buildAttack(r)
	if err != nil {
		RespondError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	SendJSON(w, http.StatusOK, d)
}

// GetAttackLayer handles GET /api/v2/attack/layer: the same data as an
// ATT&CK Navigator layer file.
func (h *AnalyticsHandler) GetAttackLayer(w http.ResponseWriter, r *http.Request) {
	d, err := h.buildAttack(r)
	if err != nil {
		RespondError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename=truesignal-attack-layer.json")
	SendJSON(w, http.StatusOK, attackmap.Layer(d, time.Now()))
}

func (h *AnalyticsHandler) buildAttack(r *http.Request) (*attackmap.DTO, error) {
	q := r.URL.Query()
	viewingArchive := 0
	if a := q.Get("archived"); a == "true" || a == "1" {
		viewingArchive = 1
	}
	return attackmap.NewProjector(h.Store).Build(r.Context(), q.Get("timeframe"), q.Get("nodeId"), q.Get("sensorId"), viewingArchive)
}

// GetGeo handles GET /api/v2/geo: located decoy activity per place and per
// country, and the GeoIP database status (with the DB-IP attribution the
// licence requires wherever the data is shown).
func (h *AnalyticsHandler) GetGeo(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	viewingArchive := 0
	if a := q.Get("archived"); a == "true" || a == "1" {
		viewingArchive = 1
	}
	d, err := geomap.Build(r.Context(), h.Store, h.Geo, q.Get("timeframe"), q.Get("nodeId"), q.Get("sensorId"), viewingArchive)
	if err != nil {
		RespondError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	SendJSON(w, http.StatusOK, d)
}

// GetPath handles GET /api/v2/path?source=: one source's route through the
// decoys (steps in first-contact order, tactic progression, timeline).
func (h *AnalyticsHandler) GetPath(w http.ResponseWriter, r *http.Request) {
	source := r.URL.Query().Get("source")
	if source == "" || len(source) > 256 {
		RespondError(w, "source is required (at most 256 characters)", http.StatusBadRequest)
		return
	}
	events, err := h.Store.GetEventsBySource(source, path.MaxEvents+1)
	if err != nil {
		RespondError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	truncated := len(events) > path.MaxEvents
	if truncated {
		events = events[1:] // the oldest; the query returns the newest MaxEvents+1, oldest first
	}
	d := path.Build(source, events, truncated)
	inv, _ := h.Store.GetConfigValue(assets.ConfigKey)
	list, _ := assets.Decode(inv)
	d.Asset = assets.NewIndex(list).Lookup(source)
	SendJSON(w, http.StatusOK, d)
}

// GetReport handles GET /api/v2/report?from=&to=: decoy activity in a
// date range for the evidence report. from/to are RFC 3339 times or
// YYYY-MM-DD dates (to exclusive); the default is the last 30 days.
func (h *AnalyticsHandler) GetReport(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	parse := func(v string) (time.Time, error) {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t.UTC(), nil
		}
		return time.Parse("2006-01-02", v)
	}
	to, from := now, now.Add(-30*24*time.Hour)
	var err error
	if v := r.URL.Query().Get("to"); v != "" {
		if to, err = parse(v); err != nil {
			RespondError(w, "to must be an RFC 3339 time or a YYYY-MM-DD date", http.StatusBadRequest)
			return
		}
	}
	if v := r.URL.Query().Get("from"); v != "" {
		if from, err = parse(v); err != nil {
			RespondError(w, "from must be an RFC 3339 time or a YYYY-MM-DD date", http.StatusBadRequest)
			return
		}
	}
	if !from.Before(to) || to.Sub(from) > report.MaxRange {
		RespondError(w, "from must be before to, and the range at most 366 days", http.StatusBadRequest)
		return
	}

	fail := func(err error) { RespondError(w, err.Error(), http.StatusInternalServerError) }
	active, err := h.Store.GetEvents(0, "", "")
	if err != nil {
		fail(err)
		return
	}
	archived, err := h.Store.GetEvents(1, "", "")
	if err != nil {
		fail(err)
		return
	}
	decoys, err := h.Store.ListDeployedSensors("", "")
	if err != nil {
		fail(err)
		return
	}
	tokens, err := h.Store.ListHoneytokens()
	if err != nil {
		fail(err)
		return
	}
	inv, _ := h.Store.GetConfigValue(assets.ConfigKey)
	list, _ := assets.Decode(inv)
	SendJSON(w, http.StatusOK, report.Build(active, archived, decoys, tokens, assets.NewIndex(list), from, to, now))
}

// GetSources handles GET /api/v2/sources: one activity profile per event
// source (all events, Hub liveness excluded) with its current list
// membership. The dashboard derives its triage labels from it.
func (h *AnalyticsHandler) GetSources(w http.ResponseWriter, r *http.Request) {
	rows, err := h.Store.GetSourceActivity(insights.LivenessTriggers())
	if err != nil {
		RespondError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	wl, _ := h.Store.GetConfigValue("whitelisted_sources")
	sc, _ := h.Store.GetConfigValue("known_scanners")
	inv, _ := h.Store.GetConfigValue(assets.ConfigKey)
	list, _ := assets.Decode(inv)
	SendJSON(w, http.StatusOK, map[string]any{
		"sources": sources.Build(rows, sourcelist.ParseStored(wl), sourcelist.ParseStored(sc), assets.NewIndex(list)),
	})
}

func (h *AnalyticsHandler) GetSeverityAnalytics(w http.ResponseWriter, r *http.Request) {
	timeframe := r.URL.Query().Get("timeframe")
	if timeframe == "" {
		timeframe = "alltime"
	}

	nodeID := r.URL.Query().Get("node")
	sensorID := r.URL.Query().Get("sensor")
	viewingArchiveStr := r.URL.Query().Get("viewingArchive")
	viewingArchive := 0
	if viewingArchiveStr == "true" || viewingArchiveStr == "1" {
		viewingArchive = 1
	}

	projector := severity.NewProjector(h.Store)
	projection, err := projector.BuildSeverityProjection(r.Context(), timeframe, nodeID, sensorID, viewingArchive)
	if err != nil {
		RespondError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	SendJSON(w, http.StatusOK, projection)
}

// GetUptime handles GET /api/v2/uptime and returns the fleet uptime projection
func (h *AnalyticsHandler) GetUptime(w http.ResponseWriter, r *http.Request) {
	// Parse timeframe from query string (default to 24H)
	timeframe := r.URL.Query().Get("timeframe")
	if timeframe == "" {
		timeframe = "24H"
	}

	// Validate timeframe
	validTimeframes := map[string]bool{
		"1H":  true,
		"24H": true,
		"7D":  true,
		"30D": true,
	}
	if !validTimeframes[timeframe] {
		RespondError(w, "Invalid timeframe. Valid values: 1H, 24H, 7D, 30D", http.StatusBadRequest)
		return
	}

	// Create projector
	projector := uptime.NewProjector(h.Store)

	// Build projection
	criteria := uptime.FilterCriteria{
		Timeframe: timeframe,
		Now:       time.Now().UTC(),
	}

	projection, err := projector.BuildUptimeProjection(criteria)
	if err != nil {
		RespondError(w, "Failed to build uptime projection", http.StatusInternalServerError)
		return
	}

	// Return the projection as JSON
	SendJSON(w, http.StatusOK, projection)
}
