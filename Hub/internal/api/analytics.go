package api

import (
	"net/http"
	"time"

	"github.com/truesignal/hub/internal/projections/insights"
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
	SendJSON(w, http.StatusOK, map[string]any{
		"sources": sources.Build(rows, sourcelist.ParseStored(wl), sourcelist.ParseStored(sc)),
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
