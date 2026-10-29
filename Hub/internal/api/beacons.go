package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/truesignal/hub/internal/models"
	"github.com/truesignal/hub/internal/services/beacon"
)

// BeaconService manages callback beacons.
type BeaconService interface {
	Create(req beacon.CreateRequest) (models.Beacon, error)
	List() ([]models.Beacon, error)
	Get(id string) (*models.Beacon, error)
	Delete(id string) (bool, error)
	Domains() ([]string, error)
}

type BeaconHandler struct {
	service BeaconService
}

func NewBeaconHandler(svc BeaconService) *BeaconHandler {
	return &BeaconHandler{service: svc}
}

// beaconView is a beacon with its rendered artifact.
type beaconView struct {
	models.Beacon
	Artifact beacon.Artifact `json:"artifact"`
}

func view(b models.Beacon) beaconView { return beaconView{Beacon: b, Artifact: beacon.Render(b)} }

// ListBeacons returns every beacon with its artifact, and the zones served by
// deployed Token Receivers.
func (h *BeaconHandler) ListBeacons(w http.ResponseWriter, r *http.Request) {
	list, err := h.service.List()
	if err != nil {
		RespondError(w, "Database error", http.StatusInternalServerError)
		return
	}
	domains, err := h.service.Domains()
	if err != nil {
		RespondError(w, "Database error", http.StatusInternalServerError)
		return
	}
	out := make([]beaconView, 0, len(list))
	for _, b := range list {
		out = append(out, view(b))
	}
	SendJSON(w, http.StatusOK, map[string]any{"beacons": out, "domains": domains})
}

func (h *BeaconHandler) CreateBeacon(w http.ResponseWriter, r *http.Request) {
	var req beacon.CreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	b, err := h.service.Create(req)
	if errors.Is(err, beacon.ErrInvalid) {
		RespondError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err != nil {
		RespondError(w, "Failed to create beacon", http.StatusInternalServerError)
		return
	}
	SendJSON(w, http.StatusCreated, view(b))
}

// DownloadBeacon returns the artifact as a file.
func (h *BeaconHandler) DownloadBeacon(w http.ResponseWriter, r *http.Request) {
	b, err := h.service.Get(chi.URLParam(r, "beaconId"))
	if err != nil {
		RespondError(w, "Database error", http.StatusInternalServerError)
		return
	}
	if b == nil {
		RespondError(w, "Beacon not found", http.StatusNotFound)
		return
	}
	a := beacon.Render(*b)
	w.Header().Set("Content-Type", a.ContentType+"; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+a.Filename+`"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write([]byte(a.Content))
}

func (h *BeaconHandler) DeleteBeacon(w http.ResponseWriter, r *http.Request) {
	ok, err := h.service.Delete(chi.URLParam(r, "beaconId"))
	if err != nil {
		RespondError(w, "Database error", http.StatusInternalServerError)
		return
	}
	if !ok {
		RespondError(w, "Beacon not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
